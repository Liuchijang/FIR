package analyzers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	browsercollector "github.com/Liuchijang/Tyto/internal/collectors/browser"
	"github.com/Liuchijang/Tyto/internal/module"
)

// Firefox keeps bookmarks in places.sqlite rather than in a JSON file, split
// across two tables: moz_bookmarks holds the tree, moz_places holds the URLs. A
// bookmark's folder path is only recoverable by walking parent ids, so neither
// browserTable nor a single SELECT covers it.

// firefoxBookmarkTypes is nsINavBookmarksService's item types.
var firefoxBookmarkTypes = map[int64]string{
	1: "bookmark",
	2: "folder",
	3: "separator",
}

type firefoxBookmark struct {
	id           int64
	itemType     int64
	parent       int64
	position     int64
	title        string
	url          string
	dateAdded    int64
	lastModified int64
	guid         string
}

// exportFirefoxBookmarks writes one profile's bookmark tree with folder paths.
func exportFirefoxBookmarks(ctx context.Context, db *sql.DB, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	rows, err := db.QueryContext(ctx, `
SELECT b.id, b.type, b.parent, b.position, COALESCE(b.title, ''),
       COALESCE(p.url, ''), COALESCE(b.dateAdded, 0), COALESCE(b.lastModified, 0),
       COALESCE(b.guid, '')
FROM moz_bookmarks b
LEFT JOIN moz_places p ON p.id = b.fk
ORDER BY b.id`)
	if err != nil {
		// A places schema without moz_bookmarks is not a failure.
		return module.FileInfo{}, nil
	}
	defer rows.Close()

	// The whole tree is held to resolve parents, which is bounded by how many
	// bookmarks a person has — thousands at most, not a volume-sized artifact.
	var all []firefoxBookmark
	byID := make(map[int64]firefoxBookmark)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return module.FileInfo{}, err
		}
		var b firefoxBookmark
		if err := rows.Scan(&b.id, &b.itemType, &b.parent, &b.position, &b.title,
			&b.url, &b.dateAdded, &b.lastModified, &b.guid); err != nil {
			continue
		}
		all = append(all, b)
		byID[b.id] = b
	}
	if err := rows.Err(); err != nil || len(all) == 0 {
		return module.FileInfo{}, nil
	}

	stream, err := newCSVStream(filepath.Join(outDir, browserCSVName(profile, "bookmarks.csv")), []string{
		"Type", "TypeResolved", "Title", "URL", "FolderPath", "Position",
		"DateAddedUTC", "LastModifiedUTC", "Guid",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	for _, b := range all {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		if writeErr := stream.Write([]string{
			strconv.FormatInt(b.itemType, 10),
			firefoxBookmarkTypes[b.itemType],
			b.title,
			b.url,
			firefoxBookmarkPath(byID, b),
			strconv.FormatInt(b.position, 10),
			firefoxTimeString(b.dateAdded),
			firefoxTimeString(b.lastModified),
			b.guid,
		}); writeErr != nil {
			stream.Abort()
			return module.FileInfo{}, writeErr
		}
	}
	return stream.Close()
}

// firefoxBookmarkPath walks parent ids up to the root.
//
// The depth guard is not decoration: parent is a plain integer with no foreign
// key, so a damaged places.sqlite can contain a cycle, and without a bound the
// walk would not terminate.
func firefoxBookmarkPath(byID map[int64]firefoxBookmark, item firefoxBookmark) string {
	const maxDepth = 64

	var parts []string
	current := item.parent
	for depth := 0; depth < maxDepth && current != 0; depth++ {
		parent, ok := byID[current]
		if !ok {
			break
		}
		if parent.title != "" {
			parts = append(parts, parent.title)
		}
		if parent.parent == parent.id {
			break
		}
		current = parent.parent
	}

	// Collected bottom-up, so reverse into root-first order.
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, " > ")
}

// exportFirefoxProfileBookmarks opens places.sqlite and exports its bookmark
// tree, matching the signature the profile analyzer dispatches on.
func exportFirefoxProfileBookmarks(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	db, cleanup, ok, err := openBrowserSQLite(outDir, profile, "places.sqlite")
	if err != nil || !ok {
		return module.FileInfo{}, err
	}
	defer cleanup()
	return exportFirefoxBookmarks(ctx, db, outDir, profile)
}

// firefoxLoginsFile mirrors logins.json.
//
// Field names changed across versions: hostname/formSubmitURL became
// origin/formActionOrigin. Both are declared so one parser covers either, the
// same reason the SQLite tables select on what the schema actually has.
type firefoxLoginsFile struct {
	NextID  int64 `json:"nextId"`
	Version int   `json:"version"`
	Logins  []struct {
		ID                  int64  `json:"id"`
		Hostname            string `json:"hostname"`
		Origin              string `json:"origin"`
		HTTPRealm           string `json:"httpRealm"`
		FormSubmitURL       string `json:"formSubmitURL"`
		FormActionOrigin    string `json:"formActionOrigin"`
		UsernameField       string `json:"usernameField"`
		PasswordField       string `json:"passwordField"`
		EncryptedUsername   string `json:"encryptedUsername"`
		EncryptedPassword   string `json:"encryptedPassword"`
		GUID                string `json:"guid"`
		EncType             int    `json:"encType"`
		TimeCreated         int64  `json:"timeCreated"`
		TimeLastUsed        int64  `json:"timeLastUsed"`
		TimePasswordChanged int64  `json:"timePasswordChanged"`
		TimesUsed           int64  `json:"timesUsed"`
	} `json:"logins"`
	// Firefox records which saved passwords it believes were exposed in a breach.
	// That is a statement about the account, not about the browser, and it is
	// worth carrying across.
	PotentiallyVulnerable []struct {
		GUID string `json:"guid"`
	} `json:"potentiallyVulnerablePasswords"`
	DismissedBreachAlerts map[string]any `json:"dismissedBreachAlertsByLoginGUID"`
}

// exportFirefoxLogins writes the saved-login metadata from logins.json.
//
// The credentials themselves are encrypted with NSS against key4.db and are not
// recovered here — Tyto does not decrypt browser secrets. What the file
// establishes without decryption is which sites an account was saved for, when,
// how often it was used, and whether Firefox flagged the password as breached.
func exportFirefoxLogins(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	raw, err := os.ReadFile(filepath.Join(profile.Path, "logins.json"))
	if err != nil {
		return module.FileInfo{}, nil
	}

	var parsed firefoxLoginsFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return module.FileInfo{}, fmt.Errorf("parse logins.json: %w", err)
	}
	if len(parsed.Logins) == 0 {
		return module.FileInfo{}, nil
	}

	vulnerable := make(map[string]bool, len(parsed.PotentiallyVulnerable))
	for _, entry := range parsed.PotentiallyVulnerable {
		vulnerable[entry.GUID] = true
	}

	stream, err := newCSVStream(filepath.Join(outDir, browserCSVName(profile, "logins.csv")), []string{
		"Origin", "HttpRealm", "FormActionOrigin", "UsernameField", "PasswordField",
		"EncryptedUsername", "EncryptedPassword", "EncryptionType",
		"TimeCreatedUTC", "TimeLastUsedUTC", "TimePasswordChangedUTC", "TimesUsed",
		"PotentiallyVulnerable", "BreachAlertDismissed", "Guid",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	for _, login := range parsed.Logins {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		_, dismissed := parsed.DismissedBreachAlerts[login.GUID]
		if writeErr := stream.Write([]string{
			firstNonEmptyString(login.Origin, login.Hostname),
			login.HTTPRealm,
			firstNonEmptyString(login.FormActionOrigin, login.FormSubmitURL),
			login.UsernameField,
			login.PasswordField,
			login.EncryptedUsername,
			login.EncryptedPassword,
			firefoxEncryptionType(login.EncType),
			firefoxMillisString(login.TimeCreated),
			firefoxMillisString(login.TimeLastUsed),
			firefoxMillisString(login.TimePasswordChanged),
			strconv.FormatInt(login.TimesUsed, 10),
			strconv.FormatBool(vulnerable[login.GUID]),
			strconv.FormatBool(dismissed),
			login.GUID,
		}); writeErr != nil {
			stream.Abort()
			return module.FileInfo{}, writeErr
		}
	}
	return stream.Close()
}

// firefoxEncryptionType names nsILoginManagerCrypto's encoding. Only type 1 has
// ever shipped, so anything else is worth showing as the number it is.
func firefoxEncryptionType(encType int) string {
	if encType == 1 {
		return "NSS 3DES/AES via key4.db"
	}
	return "unknown(" + strconv.Itoa(encType) + ")"
}

// firefoxMillisString renders logins.json timestamps, which are Unix
// milliseconds — unlike places.sqlite, which uses microseconds.
func firefoxMillisString(millis int64) string {
	if millis <= 0 {
		return ""
	}
	return formatUnixMicro(millis*1000, "")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
