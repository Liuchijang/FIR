// Package browser implements browser-forensics collectors.
package browser

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
)

const BrowserCollectorName = "browser"

const (
	browserFamilyChromium = "chromium"
	browserFamilyFirefox  = "firefox"
)

var chromiumEvidenceFiles = []string{
	"Affiliation Database",
	"Bookmarks",
	"Cookies",
	// Bounce-tracking mitigation state: which sites redirected through others
	// and when they last stored data. Chrome 114+.
	"DIPS",
	"Extension Cookies",
	"Favicons",
	"History",
	"Last Session",
	"Last Tabs",
	"Login Data",
	"Login Data For Account",
	// What was played, for how long, and when it was last touched.
	"Media History",
	"Network Action Predictor",
	"Preferences",
	// Preferences Chrome signs with a MAC so extensions cannot tamper with them
	// silently; it holds the installed-extension list among other things.
	"Secure Preferences",
	"Shortcuts",
	"Top Sites",
	"TransportSecurity",
	"Visited Links",
	"Web Data",
	filepath.Join("Network", "Cookies"),
}

// chromiumEvidenceDirs are copied file-by-file, non-recursively.
//
// Every entry here is a flat LevelDB store — CURRENT/MANIFEST/LOG/*.ldb/*.log
// side by side — which is why the shallow copy is enough and why they cannot be
// copied as single files (that fails with ERROR_INVALID_FUNCTION). Measured on a
// real profile the whole set is under 300 KB.
//
// Deliberately absent: IndexedDB, Extension Settings and Cache/Code Cache.
// The first two nest one directory deeper than this copy reaches, and all three
// routinely run to hundreds of megabytes per profile — enough to change what a
// browser collection costs, for artifacts nothing in Tyto can parse yet.
var chromiumEvidenceDirs = []string{
	"Sessions",
	"Extension Rules",
	"Extension Scripts",
	"Extension State",
	filepath.Join("Local Storage", "leveldb"),
	"Session Storage",
	"Platform Notifications",
	filepath.Join("Service Worker", "Database"),
	filepath.Join("Sync Data", "LevelDB"),
	"shared_proto_db",
}

var firefoxEvidenceFiles = []string{
	"addons.json",
	"cert9.db",
	"compatibility.ini",
	"containers.json",
	"content-prefs.sqlite",
	"content-prefs.sqlite-shm",
	"content-prefs.sqlite-wal",
	"cookies.sqlite",
	"cookies.sqlite-shm",
	"cookies.sqlite-wal",
	"extensions.json",
	"favicons.sqlite",
	"favicons.sqlite-shm",
	"favicons.sqlite-wal",
	"formhistory.sqlite",
	"formhistory.sqlite-shm",
	"formhistory.sqlite-wal",
	"handlers.json",
	"key4.db",
	"logins.json",
	"permissions.sqlite",
	"permissions.sqlite-shm",
	"permissions.sqlite-wal",
	"persdict.dat",
	"places.sqlite",
	"places.sqlite-shm",
	"places.sqlite-wal",
	"prefs.js",
	"search.json.mozlz4",
	"sessionCheckpoints.json",
	"sessionstore.jsonlz4",
	"SiteSecurityServiceState.txt",
	"storage.sqlite",
	"storage.sqlite-shm",
	"storage.sqlite-wal",
}

var firefoxEvidenceDirs = []string{
	"bookmarkbackups",
	"sessionstore-backups",
}

type browserDiscovery struct {
	Browser string
	Family  string
	RelPath string
	Layout  string
}

var browserRoots = []browserDiscovery{
	{
		Browser: "Chrome",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Google", "Chrome", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Edge",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Microsoft", "Edge", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Brave",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Vivaldi",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Local", "Vivaldi", "User Data"),
		Layout:  "chromium_user_data",
	},
	{
		Browser: "Opera",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Roaming", "Opera Software", "Opera Stable"),
		Layout:  "direct_profile",
	},
	{
		Browser: "Opera GX",
		Family:  browserFamilyChromium,
		RelPath: filepath.Join("AppData", "Roaming", "Opera Software", "Opera GX Stable"),
		Layout:  "direct_profile",
	},
	{
		Browser: "Firefox",
		Family:  browserFamilyFirefox,
		RelPath: filepath.Join("AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		Layout:  "firefox_profiles",
	},
}

var browserSelection = struct {
	mu    sync.RWMutex
	paths []string
}{}

func init() { module.RegisterArtifact("browser", &browserCollector{}) }

type browserCollector struct{}

type BrowserProfile struct {
	Browser string
	Family  string
	User    string
	Name    string
	Path    string
}

type ChromiumProfile = BrowserProfile

func (c *browserCollector) Name() string { return BrowserCollectorName }
func (c *browserCollector) Description() string {
	return "Collect browser artifacts from Chrome, Edge, Brave, Vivaldi, Firefox, Opera, and Opera GX"
}

func ConfigureProfiles(paths []string) {
	browserSelection.mu.Lock()
	defer browserSelection.mu.Unlock()

	browserSelection.paths = append([]string(nil), paths...)
}

func ResolveProfiles() ([]BrowserProfile, error) {
	return resolveSelectedProfiles()
}

func DiscoverProfiles() ([]BrowserProfile, error) {
	users, err := platform.UserProfiles()
	if err != nil {
		return nil, fmt.Errorf("read profiles directory: %w", err)
	}

	var profiles []BrowserProfile
	for _, user := range users {
		for _, root := range browserRoots {
			browserRoot := filepath.Join(user.Path, root.RelPath)
			profiles = append(profiles, discoverProfilesForRoot(user.Name, root, browserRoot)...)
		}
	}

	return profiles, nil
}

func (c *browserCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	profiles, err := resolveSelectedProfiles()
	if err != nil {
		return module.CollectResult{Error: err.Error()}
	}

	outDir, err := req.EnsureOutputDir("browser")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create browser output dir: %w", err).Error()}
	}

	// rawCtx is a last-resort read path when a browser file can't be copied
	// through the normal Win32 file APIs (e.g. the browser holds it under a
	// share-mode lock that backup semantics/SeBackupPrivilege cannot bypass —
	// that privilege only bypasses ACL checks, not another process's exclusive
	// lock). Reading the file straight off the volume's $MFT never opens a
	// Win32 handle, so it is immune to any live share-mode lock.
	rawCtx := &acquisition.RawVolumePool{}
	defer rawCtx.Close()

	var allFiles []module.FileInfo
	var errors []string
	for _, profile := range profiles {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		log.Info(fmt.Sprintf("Browser profile selected: %s", profile.Path))
		files, warnings, collectErr := collectProfile(ctx, outDir, profile, rawCtx)
		allFiles = append(allFiles, files...)
		if collectErr != nil {
			errors = append(errors, collectErr.Error())
			log.Warn(collectErr.Error())
			continue
		}
		for _, w := range warnings {
			msg := fmt.Sprintf("%s: %s", profile.Path, w)
			errors = append(errors, msg)
			log.Warn(msg)
		}
	}

	if len(allFiles) == 0 {
		if len(errors) == 0 {
			return module.CollectResult{OutputPath: outDir, Error: "no browser artifacts collected"}
		}
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no browser artifacts collected: %s", strings.Join(errors, "; "))}
	}

	if len(errors) > 0 {
		return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: fmt.Sprintf("collected browser artifacts with %d partial failure(s): %s", len(errors), strings.Join(errors, "; "))}
	}

	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}

func resolveSelectedProfiles() ([]BrowserProfile, error) {
	browserSelection.mu.RLock()
	selected := append([]string(nil), browserSelection.paths...)
	browserSelection.mu.RUnlock()

	if len(selected) == 0 {
		return DiscoverProfiles()
	}

	seen := make(map[string]bool)
	var profiles []BrowserProfile
	for _, path := range selected {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true

		profile, ok := buildProfileFromPath(path)
		if !ok {
			profile = BrowserProfile{
				Browser: "Browser",
				Family:  browserFamilyChromium,
				User:    "unknown",
				Name:    filepath.Base(path),
				Path:    path,
			}
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

func discoverProfilesForRoot(username string, root browserDiscovery, browserRoot string) []BrowserProfile {
	switch root.Layout {
	case "chromium_user_data":
		return discoverChromiumProfilesInUserData(username, root.Browser, browserRoot)
	case "direct_profile":
		return discoverDirectProfile(username, root.Browser, root.Family, browserRoot)
	case "firefox_profiles":
		return discoverFirefoxProfiles(username, root.Browser, browserRoot)
	default:
		return nil
	}
}

func discoverChromiumProfilesInUserData(username, browserName, userDataDir string) []BrowserProfile {
	info, err := os.Stat(userDataDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return nil
	}

	var profiles []BrowserProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		profileDir := filepath.Join(userDataDir, name)
		if !looksLikeChromiumProfile(profileDir, name) {
			continue
		}

		profiles = append(profiles, BrowserProfile{
			Browser: browserName,
			Family:  browserFamilyChromium,
			User:    username,
			Name:    name,
			Path:    profileDir,
		})
	}

	return profiles
}

func discoverDirectProfile(username, browserName, family, profileDir string) []BrowserProfile {
	info, err := os.Stat(profileDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	return []BrowserProfile{{
		Browser: browserName,
		Family:  family,
		User:    username,
		Name:    filepath.Base(profileDir),
		Path:    profileDir,
	}}
}

func discoverFirefoxProfiles(username, browserName, profilesDir string) []BrowserProfile {
	info, err := os.Stat(profilesDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil
	}

	var profiles []BrowserProfile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profileDir := filepath.Join(profilesDir, entry.Name())
		profiles = append(profiles, BrowserProfile{
			Browser: browserName,
			Family:  browserFamilyFirefox,
			User:    username,
			Name:    entry.Name(),
			Path:    profileDir,
		})
	}

	return profiles
}

func buildProfileFromPath(path string) (BrowserProfile, bool) {
	clean := filepath.Clean(path)
	if len(strings.Split(clean, string(os.PathSeparator))) < 4 {
		return BrowserProfile{}, false
	}

	user, ok := userFromProfilePath(clean, platform.ProfilesDirectory())
	if !ok {
		return BrowserProfile{}, false
	}

	browser, family := inferBrowserMetadata(clean)
	return BrowserProfile{
		Browser: browser,
		Family:  family,
		User:    user,
		Name:    filepath.Base(clean),
		Path:    clean,
	}, true
}

// userFromProfilePath names the account a selected browser profile belongs to.
//
// The profile root is asked for rather than assumed. A selected path is
// <ProfilesDirectory>\<user>\..., and DiscoverProfiles already enumerates from
// the real root — but this half still scanned for a segment literally named
// "Users", so on a host keeping profiles somewhere else it matched nothing and
// resolveSelectedProfiles filed every selected profile under "unknown". The
// artifacts were still collected, which is what makes it worth pinning: nothing
// in the output says the attribution is wrong.
//
// The "Users" scan stays as the fallback. ProfilesDirectory answers for the
// machine this is running on, and a path that came from anywhere else still
// resolves the way it always did.
//
// profilesRoot is passed in rather than read here so the relocated case is
// testable: on a host whose root is the default, no end-to-end test can tell the
// two code paths apart.
func userFromProfilePath(clean, profilesRoot string) (string, bool) {
	if user, ok := segmentUnderRoot(clean, profilesRoot); ok {
		return user, true
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	for i, part := range parts {
		if strings.EqualFold(part, "Users") && i+1 < len(parts) {
			return parts[i+1], true
		}
	}
	return "", false
}

// segmentUnderRoot returns the first path segment of clean below root.
func segmentUnderRoot(clean, root string) (string, bool) {
	root = strings.TrimRight(filepath.Clean(root), string(os.PathSeparator))
	if root == "" || len(clean) <= len(root)+1 {
		return "", false
	}
	if !strings.EqualFold(clean[:len(root)], root) || clean[len(root)] != os.PathSeparator {
		return "", false
	}

	rest := clean[len(root)+1:]
	if i := strings.IndexByte(rest, os.PathSeparator); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

func inferBrowserMetadata(path string) (browserName, family string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, `\google\chrome\user data\`):
		return "Chrome", browserFamilyChromium
	case strings.Contains(lower, `\microsoft\edge\user data\`):
		return "Edge", browserFamilyChromium
	case strings.Contains(lower, `\bravesoftware\brave-browser\user data\`):
		return "Brave", browserFamilyChromium
	case strings.Contains(lower, `\vivaldi\user data\`):
		return "Vivaldi", browserFamilyChromium
	case strings.Contains(lower, `\opera software\opera gx stable`):
		return "Opera GX", browserFamilyChromium
	case strings.Contains(lower, `\opera software\opera stable`):
		return "Opera", browserFamilyChromium
	case strings.Contains(lower, `\mozilla\firefox\profiles\`):
		return "Firefox", browserFamilyFirefox
	default:
		return "Browser", browserFamilyChromium
	}
}

func isChromiumProfileDir(name string) bool {
	if strings.EqualFold(name, "Default") {
		return true
	}
	if strings.EqualFold(name, "Guest Profile") {
		return true
	}
	if strings.EqualFold(name, "System Profile") {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "profile ")
}

func looksLikeChromiumProfile(profileDir, name string) bool {
	if isChromiumProfileDir(name) {
		return true
	}

	markers := []string{
		"Bookmarks",
		"Cookies",
		"History",
		"Preferences",
		"Web Data",
	}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(profileDir, marker)); err == nil {
			return true
		}
	}
	return false
}

// collectProfile copies one profile's artifacts. The two families differ only in
// which names they look for and in Chromium's "Local State", which sits one
// level above the profile: everything else — the output layout, the
// missing-file-is-not-an-error rule, the raw-volume fallback — is the same, and
// keeping two copies of it meant a fix to one family's copy loop silently
// skipping the other.
func collectProfile(ctx context.Context, outDir string, profile BrowserProfile, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, []string, error) {
	evidenceFiles, evidenceDirs := chromiumEvidenceFiles, chromiumEvidenceDirs
	if profile.Family == browserFamilyFirefox {
		evidenceFiles, evidenceDirs = firefoxEvidenceFiles, firefoxEvidenceDirs
	}

	// profileRel is the path every FileInfo is reported under, so a manifest entry
	// identifies which profile a file came from.
	//
	// Without it the manifest lists 682 entries whose "path" is a bare name like
	// "Favicons" or "Local Storage/leveldb/000004.log", repeated once per profile
	// with a different hash each time and nothing to say which is which. That is
	// the chain-of-custody record for a browser collection, so it has to resolve to
	// one file. The registry collector already qualifies its user hives the same
	// way ("users/<name>/NTUSER.DAT").
	profileRel := filepath.Join(
		outputDirName(profile.User),
		outputDirName(profile.Browser),
		outputDirName(profile.Name),
	)
	profileRoot := filepath.Join(outDir, profileRel)
	if err := os.MkdirAll(profileRoot, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create browser profile output dir for %s: %w", profile.Path, err)
	}

	var files []module.FileInfo
	var warnings []string

	if profile.Family != browserFamilyFirefox {
		// Local State holds the profile-to-account mapping and the DPAPI-wrapped
		// key the cookie/login databases are encrypted with, and it lives in the
		// User Data root rather than in the profile.
		localState := filepath.Join(filepath.Dir(profile.Path), "Local State")
		if fi, err := copyBrowserFile(localState, filepath.Join(profileRoot, "Local State"), filepath.Join(profileRel, "Local State"), rawCtx); err == nil {
			files = append(files, fi)
		}
	}

	for _, relPath := range evidenceFiles {
		select {
		case <-ctx.Done():
			return files, warnings, ctx.Err()
		default:
		}

		fi, err := copyBrowserFile(filepath.Join(profile.Path, relPath), filepath.Join(profileRoot, relPath), filepath.Join(profileRel, relPath), rawCtx)
		if err != nil {
			// An absent artifact is the normal case — no profile has every name
			// in the list — so only a real copy failure is worth reporting.
			if !os.IsNotExist(err) {
				warnings = append(warnings, fmt.Sprintf("%s: %v", relPath, err))
			}
			continue
		}
		files = append(files, fi)
	}

	for _, relDir := range evidenceDirs {
		select {
		case <-ctx.Done():
			return files, warnings, ctx.Err()
		default:
		}

		dirFiles, err := copyBrowserDir(filepath.Join(profile.Path, relDir), filepath.Join(profileRoot, relDir), filepath.Join(profileRel, relDir), rawCtx)
		if err != nil {
			if !os.IsNotExist(err) {
				warnings = append(warnings, fmt.Sprintf("%s: %v", relDir, err))
			}
			continue
		}
		files = append(files, dirFiles...)
	}

	if profile.Family != browserFamilyFirefox {
		manifests, err := copyExtensionManifests(ctx, profile.Path, profileRoot, profileRel, rawCtx)
		if err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("Extensions: %v", err))
		}
		files = append(files, manifests...)
	}

	if len(files) == 0 {
		if len(warnings) == 0 {
			return nil, nil, fmt.Errorf("no browser artifacts copied from %s", profile.Path)
		}
		return nil, warnings, fmt.Errorf("no browser artifacts copied from %s: %s", profile.Path, strings.Join(warnings, "; "))
	}

	return files, warnings, nil
}

// copyExtensionManifests collects the metadata of every installed extension
// without collecting the extensions themselves.
//
// Extensions/<id>/<version>/manifest.json is what says who an extension claims
// to be and what it is permitted to do — the part an investigation needs when a
// browser extension is the intrusion vector. The rest of the directory is the
// extension's own code and assets, routinely tens to hundreds of megabytes per
// profile, so it is passed over: a shallow copy would miss the manifests
// entirely and a full one would dominate the run.
//
// _locales/<locale>/messages.json comes along because a manifest may name itself
// "__MSG_appName__" and the real name only exists in the message catalogue.
func copyExtensionManifests(ctx context.Context, profilePath, profileRoot, profileRel string, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, error) {
	extensionsRoot := filepath.Join(profilePath, "Extensions")
	if _, err := os.Stat(extensionsRoot); err != nil {
		return nil, err
	}

	var files []module.FileInfo
	// Depth 3 covers <id>/<version>/manifest.json and
	// <id>/<version>/_locales/<locale>/messages.json.
	err := filepath.WalkDir(extensionsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if name != "manifest.json" && name != "messages.json" {
			return nil
		}

		rel, err := filepath.Rel(profilePath, path)
		if err != nil {
			return nil
		}
		fi, err := copyBrowserFile(path, filepath.Join(profileRoot, rel), filepath.Join(profileRel, rel), rawCtx)
		if err != nil {
			return nil
		}
		files = append(files, fi)
		return nil
	})
	return files, err
}

func copyBrowserFile(src, dst, relPath string, rawCtx *acquisition.RawVolumePool) (module.FileInfo, error) {
	if _, err := os.Stat(src); err != nil {
		return module.FileInfo{}, err
	}

	fi, err := utils.SafeCopyFile(src, dst)
	if err == nil {
		fi.Path = relPath
		return fi, nil
	}

	fi, err = utils.SafeCopyFileBackup(src, dst)
	if err == nil {
		fi.Path = relPath
		return fi, nil
	}

	// Both Win32 copy paths failed (likely a share-mode lock — see rawCtx above).
	if rawCtx != nil {
		if _, rawErr := rawCtx.CopyFile(src, dst); rawErr == nil {
			if rawFi, fiErr := utils.FileInfoFromPath(dst); fiErr == nil {
				rawFi.Path = relPath
				return rawFi, nil
			}
		}
	}
	return module.FileInfo{}, err
}

func copyBrowserDir(srcDir, dstDir, relDir string, rawCtx *acquisition.RawVolumePool) ([]module.FileInfo, error) {
	info, err := os.Stat(srcDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", srcDir)
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, err
	}

	var files []module.FileInfo
	var copied bool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		src := filepath.Join(srcDir, entry.Name())
		relPath := filepath.Join(relDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		fi, copyErr := copyBrowserFile(src, dst, relPath, rawCtx)
		if copyErr != nil {
			continue
		}
		files = append(files, fi)
		copied = true
	}

	if !copied {
		return nil, fmt.Errorf("no files copied from %s", srcDir)
	}

	return files, nil
}

func outputDirName(name string) string {
	return strings.ReplaceAll(output.SanitizeDirNameForExport(name), " ", "_")
}

// EstimatedBytes sums the artifacts actually present in the selected profiles, so
// picking one profile does not estimate a flat whole-machine figure.
func (c *browserCollector) EstimatedBytes() int64 {
	profiles, err := resolveSelectedProfiles()
	if err != nil || len(profiles) == 0 {
		return 0
	}

	// Both families' names are measured for every profile: PathsSize skips what
	// is not there, so a Chromium profile simply contributes nothing for the
	// Firefox names and the estimate needs no per-family branch.
	names := make([]string, 0, len(chromiumEvidenceFiles)+len(chromiumEvidenceDirs)+len(firefoxEvidenceFiles)+len(firefoxEvidenceDirs))
	names = append(names, chromiumEvidenceFiles...)
	names = append(names, chromiumEvidenceDirs...)
	names = append(names, firefoxEvidenceFiles...)
	names = append(names, firefoxEvidenceDirs...)

	var total int64
	for _, profile := range profiles {
		paths := make([]string, 0, len(names))
		for _, name := range names {
			paths = append(paths, filepath.Join(profile.Path, name))
		}
		total += utils.PathsSize(paths...)
	}
	return total
}
