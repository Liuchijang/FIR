package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	browsercollector "github.com/Liuchijang/Tyto/internal/collectors/browser"
	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterAnalyzer(&browserProfileParser{}) }

type browserProfileParser struct{ offlineCapable }

func (c *browserProfileParser) Name() string     { return "browser_profile_parser" }
func (c *browserProfileParser) Category() string { return "browser" }
func (c *browserProfileParser) Description() string {
	return "Parse bookmarks, extensions and profile configuration"
}

// chromiumMediaHistoryTable records what was played and for how long — the
// closest thing a browser keeps to "this video was watched".
var chromiumMediaHistoryTable = browserTable{
	name:    "playback",
	orderBy: "last_updated_time_s",
	columns: []browserColumn{
		rawColumn("id"),
		rawColumn("url"),
		rawColumn("watch_time_s"),
		rawColumn("has_video"),
		rawColumn("has_audio"),
		unixSecondsColumn("last_updated_time_s", "LastUpdatedUTC"),
	},
}

// chromiumShortcutsTable is the omnibox shortcut store: what the user actually
// typed, and what Chrome offered in response. Text the user typed is a stronger
// statement of intent than a visit, which can be a redirect.
var chromiumShortcutsTable = browserTable{
	name:    "omni_box_shortcuts",
	orderBy: "last_access_time",
	columns: []browserColumn{
		rawColumn("id"),
		rawColumn("text"),
		rawColumn("fill_into_edit"),
		rawColumn("url"),
		rawColumn("contents"),
		rawColumn("description"),
		rawColumn("transition"),
		rawColumn("type"),
		rawColumn("keyword"),
		chromiumTimeColumn("last_access_time", "LastAccessTimeUTC"),
		rawColumn("number_of_hits"),
	},
}

// chromiumDIPSTable is the bounce-tracking store added in Chrome 114. It records
// sites that redirected through others and when each last stored data.
var chromiumDIPSTable = browserTable{
	name:    "bounces",
	orderBy: "site",
	columns: []browserColumn{
		rawColumn("site"),
		chromiumTimeColumn("first_bounce_time", "FirstBounceUTC"),
		chromiumTimeColumn("last_bounce_time", "LastBounceUTC"),
		chromiumTimeColumn("first_site_storage_time", "FirstSiteStorageUTC"),
		chromiumTimeColumn("last_site_storage_time", "LastSiteStorageUTC"),
		chromiumTimeColumn("first_stateful_bounce_time", "FirstStatefulBounceUTC"),
		chromiumTimeColumn("last_stateful_bounce_time", "LastStatefulBounceUTC"),
		chromiumTimeColumn("first_user_interaction_time", "FirstUserInteractionUTC"),
		chromiumTimeColumn("last_user_interaction_time", "LastUserInteractionUTC"),
		chromiumTimeColumn("first_user_activation_time", "FirstUserActivationUTC"),
		chromiumTimeColumn("last_user_activation_time", "LastUserActivationUTC"),
		chromiumTimeColumn("first_web_authn_assertion_time", "FirstWebAuthnAssertionUTC"),
		chromiumTimeColumn("last_web_authn_assertion_time", "LastWebAuthnAssertionUTC"),
	},
}

func (c *browserProfileParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create browser profile parser output dir: %w", err))
	}

	sources, err := resolveBrowserProfileSources(req)
	if err != nil {
		if errors.Is(err, errNoCollectedSource) {
			return skippedNoSource(outDir, "collected browser profiles")
		}
		return analyzerError(outDir, err)
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no browser profiles available for analysis"}
	}

	var files []module.FileInfo
	var warnings []string
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}
		profile := source.Profile
		label := browserProfileLabel(profile)

		// Bookmarks live in a JSON file on Chromium and in places.sqlite on
		// Firefox, so the two families need different readers for the same artifact.
		exports := []struct {
			name string
			run  func(context.Context, string, browsercollector.BrowserProfile) (module.FileInfo, error)
		}{
			{"bookmarks", exportChromiumBookmarks},
			{"extensions", exportChromiumExtensions},
			{"preferences", exportChromiumPreferences},
		}
		if profile.Family == "firefox" {
			exports = []struct {
				name string
				run  func(context.Context, string, browsercollector.BrowserProfile) (module.FileInfo, error)
			}{
				{"bookmarks", exportFirefoxProfileBookmarks},
			}
		}

		for _, export := range exports {
			fi, err := export.run(ctx, outDir, profile)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %s %v", label, export.name, err))
				continue
			}
			if fi.Path != "" {
				files = append(files, fi)
			}
		}
	}

	// The small SQLite stores go through the shared exporter.
	sqlResult := browserAnalyzeSQLite(ctx, req, outDir, []browserExport{
		{database: "Media History", tables: []browserExportTable{
			{suffix: "media_history.csv", table: chromiumMediaHistoryTable},
		}},
		{database: "Shortcuts", tables: []browserExportTable{
			{suffix: "omnibox_shortcuts.csv", table: chromiumShortcutsTable},
		}},
		{database: "DIPS", tables: []browserExportTable{
			{suffix: "dips_bounces.csv", table: chromiumDIPSTable},
		}},
	})
	files = append(files, sqlResult.Files...)

	if len(files) == 0 {
		if len(warnings) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: strings.Join(warnings, "; ")}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: "no browser profile artifacts found"}
	}
	result := module.AnalyzeResult{Files: files, OutputPath: outDir}
	if len(warnings) > 0 {
		result.Error = fmt.Sprintf("parsed %d file(s) with %d warning(s): %s", len(files), len(warnings), strings.Join(warnings, "; "))
	}
	return result
}

// bookmarkNode mirrors the shape of Chrome's Bookmarks file. Only the fields the
// CSV needs are declared; the file also carries sync metadata and per-node GUIDs
// that add nothing to a bookmark timeline.
type bookmarkNode struct {
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	URL          string         `json:"url"`
	DateAdded    string         `json:"date_added"`
	DateModified string         `json:"date_modified"`
	Children     []bookmarkNode `json:"children"`
}

type bookmarkFile struct {
	Roots map[string]bookmarkNode `json:"roots"`
}

// exportChromiumBookmarks flattens the bookmark tree, carrying each entry's
// folder path with it.
//
// The path is what makes a bookmark interpretable: "Bookmarks bar > Work > ..."
// tells an analyst where the user filed something, and a bookmark's position in
// the tree is often the only context distinguishing a deliberate save from an
// imported bulk list.
func exportChromiumBookmarks(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	path := filepath.Join(profile.Path, "Bookmarks")
	raw, err := os.ReadFile(path)
	if err != nil {
		return module.FileInfo{}, nil
	}

	var parsed bookmarkFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return module.FileInfo{}, fmt.Errorf("parse Bookmarks: %w", err)
	}

	stream, err := newCSVStream(filepath.Join(outDir, browserCSVName(profile, "bookmarks.csv")), []string{
		"Type", "Name", "URL", "FolderPath", "DateAddedUTC", "DateModifiedUTC",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	rows := 0
	var walk func(parent string, nodes []bookmarkNode) error
	walk = func(parent string, nodes []bookmarkNode) error {
		for _, node := range nodes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if writeErr := stream.Write([]string{
				node.Type,
				node.Name,
				node.URL,
				parent,
				chromiumTimeString(parseBookmarkTime(node.DateAdded)),
				chromiumTimeString(parseBookmarkTime(node.DateModified)),
			}); writeErr != nil {
				return writeErr
			}
			rows++
			if node.Type == "folder" && len(node.Children) > 0 {
				child := node.Name
				if parent != "" {
					child = parent + " > " + node.Name
				}
				if err := walk(child, node.Children); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Roots is a map, so it is walked in a fixed order to keep the CSV stable
	// between runs on the same profile.
	rootNames := make([]string, 0, len(parsed.Roots))
	for name := range parsed.Roots {
		rootNames = append(rootNames, name)
	}
	sort.Strings(rootNames)
	for _, name := range rootNames {
		root := parsed.Roots[name]
		rootLabel := root.Name
		if rootLabel == "" {
			rootLabel = name
		}
		if err := walk(rootLabel, root.Children); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
	}

	if rows == 0 {
		stream.Abort()
		return module.FileInfo{}, nil
	}
	return stream.Close()
}

// parseBookmarkTime reads a Chromium timestamp stored as a decimal string, which
// is how the Bookmarks JSON holds it.
func parseBookmarkTime(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

// extensionManifest is the part of an extension's manifest that identifies it and
// says what it may do.
type extensionManifest struct {
	Name            string   `json:"name"`
	ShortName       string   `json:"short_name"`
	Description     string   `json:"description"`
	Version         string   `json:"version"`
	ManifestVersion int      `json:"manifest_version"`
	DefaultLocale   string   `json:"default_locale"`
	UpdateURL       string   `json:"update_url"`
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	// Content scripts are what an extension injects into pages, which is the
	// field that matters when an extension is the intrusion vector.
	ContentScripts []struct {
		Matches []string `json:"matches"`
		JS      []string `json:"js"`
	} `json:"content_scripts"`
	Background struct {
		ServiceWorker string   `json:"service_worker"`
		Scripts       []string `json:"scripts"`
	} `json:"background"`
}

// localeMessages is the message catalogue an extension uses when its manifest
// names itself indirectly.
type localeMessages map[string]struct {
	Message string `json:"message"`
}

// exportChromiumExtensions walks Extensions/<id>/<version>/manifest.json.
func exportChromiumExtensions(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	root := filepath.Join(profile.Path, "Extensions")
	if _, err := os.Stat(root); err != nil {
		return module.FileInfo{}, nil
	}

	stream, err := newCSVStream(filepath.Join(outDir, browserCSVName(profile, "extensions.csv")), []string{
		"ExtensionId", "Version", "Name", "ShortName", "Description", "ManifestVersion",
		"UpdateURL", "Permissions", "HostPermissions", "ContentScriptMatches",
		"ContentScriptFiles", "BackgroundServiceWorker", "BackgroundScripts", "ManifestPath",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	ids, err := os.ReadDir(root)
	if err != nil {
		stream.Abort()
		return module.FileInfo{}, nil
	}

	rows := 0
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		if !id.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(root, id.Name()))
		if err != nil {
			continue
		}
		for _, version := range versions {
			if !version.IsDir() {
				continue
			}
			versionDir := filepath.Join(root, id.Name(), version.Name())
			manifestPath := filepath.Join(versionDir, "manifest.json")
			raw, err := os.ReadFile(manifestPath)
			if err != nil {
				continue
			}
			var manifest extensionManifest
			if err := json.Unmarshal(raw, &manifest); err != nil {
				continue
			}

			messages := loadExtensionMessages(versionDir, manifest.DefaultLocale)
			var matches, scripts []string
			for _, cs := range manifest.ContentScripts {
				matches = append(matches, cs.Matches...)
				scripts = append(scripts, cs.JS...)
			}

			if writeErr := stream.Write([]string{
				id.Name(),
				manifest.Version,
				resolveExtensionMessage(manifest.Name, messages),
				resolveExtensionMessage(manifest.ShortName, messages),
				resolveExtensionMessage(manifest.Description, messages),
				strconv.Itoa(manifest.ManifestVersion),
				manifest.UpdateURL,
				strings.Join(manifest.Permissions, "; "),
				strings.Join(manifest.HostPermissions, "; "),
				strings.Join(matches, "; "),
				strings.Join(scripts, "; "),
				manifest.Background.ServiceWorker,
				strings.Join(manifest.Background.Scripts, "; "),
				filepath.Join("Extensions", id.Name(), version.Name(), "manifest.json"),
			}); writeErr != nil {
				stream.Abort()
				return module.FileInfo{}, writeErr
			}
			rows++
		}
	}

	if rows == 0 {
		stream.Abort()
		return module.FileInfo{}, nil
	}
	return stream.Close()
}

func loadExtensionMessages(versionDir, locale string) localeMessages {
	if locale == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(versionDir, "_locales", locale, "messages.json"))
	if err != nil {
		return nil
	}
	var messages localeMessages
	if err := json.Unmarshal(raw, &messages); err != nil {
		return nil
	}
	return messages
}

// resolveExtensionMessage substitutes a "__MSG_key__" placeholder from the
// extension's own message catalogue. Without it the name column reads
// "__MSG_appName__" instead of naming the extension.
func resolveExtensionMessage(value string, messages localeMessages) string {
	if !strings.HasPrefix(value, "__MSG_") || !strings.HasSuffix(value, "__") {
		return value
	}
	key := strings.TrimSuffix(strings.TrimPrefix(value, "__MSG_"), "__")
	if entry, ok := messages[key]; ok && entry.Message != "" {
		return entry.Message
	}
	// Case-insensitive: manifests reference keys with inconsistent casing.
	for name, entry := range messages {
		if strings.EqualFold(name, key) && entry.Message != "" {
			return entry.Message
		}
	}
	return value
}

// preferenceKeys are the Preferences entries worth a row of their own.
//
// The file is tens of thousands of keys of UI state. Flattening all of it would
// bury the handful that answer investigative questions — which account is signed
// in, what the startup pages are, whether an enterprise policy is in force, which
// extensions are installed and when.
var preferenceKeys = []string{
	"account_info",
	"browser.last_redirect_origin",
	"countryid_at_install",
	"default_search_provider_data.template_url_data.keyword",
	"default_search_provider_data.template_url_data.short_name",
	"default_search_provider_data.template_url_data.url",
	"download.default_directory",
	"download.extensions_to_open",
	"extensions.install_signature.ids",
	"extensions.theme.id",
	"homepage",
	"homepage_is_newtabpage",
	"http_receiver.last_used",
	"intl.accept_languages",
	"intl.app_locale",
	"profile.avatar_index",
	"profile.created_by_version",
	"profile.creation_time",
	"profile.exit_type",
	"profile.last_engagement_time",
	"profile.managed_user_id",
	"profile.name",
	"safebrowsing.enabled",
	"session.restore_on_startup",
	"session.startup_urls",
	"signin.allowed",
	"sync.last_synced_time",
	"webrtc.multiple_routes_enabled",
}

// preferenceTimeKeys hold a Chromium timestamp. The JSON stores them as decimal
// strings, so nothing about the value itself says it is a time — left alone they
// reach the CSV as a 17-digit number that no one reads as a date.
var preferenceTimeKeys = map[string]bool{
	"http_receiver.last_used":      true,
	"profile.creation_time":        true,
	"profile.last_engagement_time": true,
	"sync.last_synced_time":        true,
}

// exportChromiumPreferences pulls the selected keys out of Preferences and
// Secure Preferences.
//
// Secure Preferences is the MAC-protected half of the same settings tree — it is
// where Chrome keeps the installed-extension list precisely so an extension
// cannot rewrite it unnoticed — so both files are read and the source is recorded
// per row.
func exportChromiumPreferences(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	stream, err := newCSVStream(filepath.Join(outDir, browserCSVName(profile, "preferences.csv")), []string{
		"SourceFile", "Key", "Value",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	rows := 0
	for _, name := range []string{"Preferences", "Secure Preferences"} {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		raw, err := os.ReadFile(filepath.Join(profile.Path, name))
		if err != nil {
			continue
		}
		var tree map[string]any
		if err := json.Unmarshal(raw, &tree); err != nil {
			continue
		}
		for _, key := range preferenceKeys {
			value, ok := lookupPreference(tree, key)
			if !ok {
				continue
			}
			rendered := renderPreferenceValue(value)
			if preferenceTimeKeys[key] {
				if ticks := parseBookmarkTime(rendered); ticks > 0 {
					rendered = chromiumTimeString(ticks)
				}
			}
			if writeErr := stream.Write([]string{name, key, rendered}); writeErr != nil {
				stream.Abort()
				return module.FileInfo{}, writeErr
			}
			rows++
		}
		// The installed-extension list is a map keyed by extension ID, so it gets
		// one row per extension rather than one row of JSON.
		rows += writeInstalledExtensions(stream, name, tree)
	}

	if rows == 0 {
		stream.Abort()
		return module.FileInfo{}, nil
	}
	return stream.Close()
}

// lookupPreference walks a dotted path through the decoded JSON tree.
func lookupPreference(tree map[string]any, key string) (any, bool) {
	var current any = tree
	for _, part := range strings.Split(key, ".") {
		branch, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = branch[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func writeInstalledExtensions(stream *csvStream, sourceFile string, tree map[string]any) int {
	settings, ok := lookupPreference(tree, "extensions.settings")
	if !ok {
		return 0
	}
	installed, ok := settings.(map[string]any)
	if !ok {
		return 0
	}

	ids := make([]string, 0, len(installed))
	for id := range installed {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rows := 0
	for _, id := range ids {
		entry, ok := installed[id].(map[string]any)
		if !ok {
			continue
		}
		details := []string{}
		for _, field := range []string{"install_time", "first_install_time", "last_update_time", "state", "location", "from_webstore", "path"} {
			if value, ok := entry[field]; ok {
				rendered := renderPreferenceValue(value)
				// install_time and friends are Chromium timestamps held as decimal
				// strings; rendering them raw would leave a 17-digit number.
				if strings.HasSuffix(field, "_time") {
					if ticks := parseBookmarkTime(rendered); ticks > 0 {
						rendered = chromiumTimeString(ticks)
					}
				}
				details = append(details, field+"="+rendered)
			}
		}
		if err := stream.Write([]string{sourceFile, "extensions.settings." + id, strings.Join(details, "; ")}); err != nil {
			return rows
		}
		rows++
	}
	return rows
}

// renderPreferenceValue keeps a scalar readable and falls back to compact JSON
// for anything structured, so a nested object still reaches the CSV intact.
func renderPreferenceValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		// JSON numbers are float64; Chromium timestamps and counts are integers.
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		return string(encoded)
	}
}
