package analyzers

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	browsercollector "github.com/Liuchijang/Tyto/internal/collectors/browser"
	"github.com/Liuchijang/Tyto/internal/module"
)

// Downloads live in the same History database as visits, which is why they are
// exported by browser_history_parser instead of a module of their own: a separate
// module would take a second working copy of a file that routinely runs to tens
// or hundreds of megabytes, and both copies would be made concurrently from the
// same locked profile.

// downloadStates is Chromium's DownloadItem::DownloadState. 3 was the
// interrupted code until a fix in Chrome 22; 4 has been ever since, so both map
// to the same meaning.
var downloadStates = map[int64]string{
	0: "In Progress",
	1: "Complete",
	2: "Canceled",
	3: "Interrupted",
	4: "Interrupted",
}

// downloadDangerTypes is Chromium's DownloadDangerType. Anything above 9 is a
// Safe Browsing or enterprise deep-scanning verdict, and those are the values
// worth reading in an intrusion: they say the browser itself flagged the file.
var downloadDangerTypes = map[int64]string{
	0:  "Not Dangerous",
	1:  "Dangerous",
	2:  "Dangerous URL",
	3:  "Dangerous Content",
	4:  "Content May Be Malicious",
	5:  "Uncommon Content",
	6:  "Dangerous But User Validated",
	7:  "Dangerous Host",
	8:  "Potentially Unwanted",
	9:  "Allowlisted by Policy",
	10: "Pending Scan",
	11: "Blocked - Password Protected",
	12: "Blocked - Too Large",
	13: "Warning - Sensitive Content",
	14: "Blocked - Sensitive Content",
	15: "Safe - Deep Scanned",
	16: "Dangerous, but user opened",
	17: "Prompt for Scanning",
	18: "Blocked - Unsupported Type",
	19: "Dangerous - Account Compromise",
	20: "Deep Scan Failed",
	21: "Encrypted - Prompt User for Password for Local Scanning",
	22: "Encrypted - Pending Detailed Verdict after Local Scanning",
	23: "Blocked - Scan Failed",
}

// downloadInterruptReasons is Chromium's DownloadInterruptReason. The numbering
// is sparse by design — file errors below 20, network 20s, server 30s, user and
// browser 40s and 50 — so a gap is not a missing entry.
var downloadInterruptReasons = map[int64]string{
	0:  "No Interrupt",
	1:  "File Error",
	2:  "Access Denied",
	3:  "Disk Full",
	5:  "Path Too Long",
	6:  "File Too Large",
	7:  "Virus",
	10: "Temporary Problem",
	11: "Blocked",
	12: "Security Check Failed",
	13: "Resume Error",
	14: "File Hash Mismatch",
	15: "File Same as Source",
	20: "Network Error",
	21: "Operation Timed Out",
	22: "Connection Lost",
	23: "Server Down",
	24: "Invalid Request",
	30: "Server Error",
	31: "Range Request Error",
	32: "Server Precondition Error",
	33: "Unable to get file",
	34: "Server Unauthorized",
	35: "Server Certificate Problem",
	36: "Server Access Forbidden",
	37: "Server Unreachable",
	38: "Content Length Mismatch",
	39: "Cross Origin Redirect",
	40: "Canceled",
	41: "Browser Shutdown",
	50: "Browser Crashed",
}

// chromiumDownloadsTable is the superset of every downloads schema Chrome has
// shipped. browserTable selects only the columns the database on hand has, so
// one definition covers all of them.
var chromiumDownloadsTable = browserTable{
	name:    "downloads",
	orderBy: "start_time",
	columns: []browserColumn{
		rawColumn("id"),
		rawColumn("guid"),
		rawColumn("target_path"),
		rawColumn("current_path"),
		chromiumTimeColumn("start_time", "StartTimeUTC"),
		chromiumTimeColumn("end_time", "EndTimeUTC"),
		chromiumTimeColumn("last_access_time", "LastAccessTimeUTC"),
		rawColumn("received_bytes"),
		rawColumn("total_bytes"),
		rawColumn("state"),
		enumColumn("state", "StateResolved", downloadStates),
		rawColumn("danger_type"),
		enumColumn("danger_type", "DangerTypeResolved", downloadDangerTypes),
		rawColumn("interrupt_reason"),
		enumColumn("interrupt_reason", "InterruptReasonResolved", downloadInterruptReasons),
		boolColumn("opened", "Opened"),
		rawColumn("referrer"),
		rawColumn("tab_url"),
		rawColumn("tab_referrer_url"),
		rawColumn("site_url"),
		rawColumn("mime_type"),
		rawColumn("original_mime_type"),
		rawColumn("http_method"),
		rawColumn("etag"),
		// Chrome stores the server's Last-Modified header verbatim, so this is a
		// header string rather than a timestamp Tyto can normalise.
		rawColumn("last_modified"),
		rawColumn("by_ext_id"),
		rawColumn("by_ext_name"),
		// The column exists but Chrome has never populated it; kept so a build
		// that starts doing so is not silently dropped.
		rawColumn("hash"),
	},
}

// downloadsCSVHeader is the downloads table's own columns plus the redirect
// chain, which comes from a second table.
func downloadsCSVHeader() []string {
	return append(chromiumDownloadsTable.headers(), "UrlChain")
}

// exportProfileDownloads writes a profile's downloads, whichever browser family
// it belongs to. A profile with no download record at all returns a zero
// FileInfo rather than an empty CSV.
func exportProfileDownloads(ctx context.Context, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	if profile.Family == "firefox" {
		db, cleanup, ok, err := openBrowserSQLite(outDir, profile, "places.sqlite")
		if err != nil || !ok {
			return module.FileInfo{}, err
		}
		defer cleanup()
		return exportFirefoxDownloads(ctx, db, outDir, profile)
	}

	db, cleanup, ok, err := openBrowserSQLite(outDir, profile, "History")
	if err != nil || !ok {
		return module.FileInfo{}, err
	}
	defer cleanup()
	return exportChromiumDownloads(ctx, db, outDir, profile)
}

// exportChromiumDownloads writes one profile's download history.
//
// The redirect chain lives in downloads_url_chains, one row per hop. Joining it
// in SQL would multiply every download by its hop count, so the chain is loaded
// into a map first and folded in per download. That map is bounded by the size of
// a browser's download history — thousands of rows, not a volume-sized artifact —
// which is why holding it is acceptable here and would not be for $MFT.
func exportChromiumDownloads(ctx context.Context, db *sql.DB, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	present, err := browserTableColumns(ctx, db, chromiumDownloadsTable.name)
	if err != nil || len(present) == 0 {
		return module.FileInfo{}, err
	}

	chains, err := loadDownloadURLChains(ctx, db)
	if err != nil {
		// Losing the chain costs one column, not the export.
		chains = nil
	}

	idIndex := -1
	for i, column := range chromiumDownloadsTable.columns {
		if column.header == "id" {
			idIndex = i
			break
		}
	}

	path := filepath.Join(outDir, browserCSVName(profile, "downloads.csv"))
	stream, err := newCSVStream(path, downloadsCSVHeader())
	if err != nil {
		return module.FileInfo{}, err
	}

	rows := 0
	found, err := chromiumDownloadsTable.stream(ctx, db, func(record []string) error {
		chain := ""
		if idIndex >= 0 {
			chain = strings.Join(chains[record[idIndex]], " -> ")
		}
		if writeErr := stream.Write(append(record, chain)); writeErr != nil {
			return writeErr
		}
		rows++
		return nil
	})
	if err != nil || !found || rows == 0 {
		stream.Abort()
		return module.FileInfo{}, err
	}
	return stream.Close()
}

func loadDownloadURLChains(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index`)
	if err != nil {
		return nil, fmt.Errorf("read downloads_url_chains: %w", err)
	}
	defer rows.Close()

	chains := make(map[string][]string)
	for rows.Next() {
		var id, url any
		if err := rows.Scan(&id, &url); err != nil {
			continue
		}
		key := renderBrowserValue(id)
		chains[key] = append(chains[key], renderBrowserValue(url))
	}
	return chains, rows.Err()
}

// firefoxDownloadsTable reads Firefox's downloads, which are annotations on
// places entries rather than a table of their own. moz_annos holds one row per
// annotation name, so the destination and the transfer state arrive as separate
// rows that have to be pivoted back together.
const firefoxDownloadsQuery = `
SELECT
    p.url,
    COALESCE(p.title, ''),
    MAX(CASE WHEN a.anno_attribute_id = dest.id THEN a.content END),
    MAX(CASE WHEN a.anno_attribute_id = meta.id THEN a.content END),
    MAX(a.dateAdded),
    MAX(a.lastModified)
FROM moz_annos a
JOIN moz_places p ON p.id = a.place_id
LEFT JOIN moz_anno_attributes dest ON dest.name = 'downloads/destinationFileURI'
LEFT JOIN moz_anno_attributes meta ON meta.name = 'downloads/metaData'
WHERE a.anno_attribute_id IN (dest.id, meta.id)
GROUP BY p.id
ORDER BY MAX(a.dateAdded) DESC
`

func exportFirefoxDownloads(ctx context.Context, db *sql.DB, outDir string, profile browsercollector.BrowserProfile) (module.FileInfo, error) {
	rows, err := db.QueryContext(ctx, firefoxDownloadsQuery)
	if err != nil {
		// An older places schema without these annotation tables is not a failure.
		return module.FileInfo{}, nil
	}
	defer rows.Close()

	path := filepath.Join(outDir, browserCSVName(profile, "downloads.csv"))
	stream, err := newCSVStream(path, []string{
		"URL", "Title", "DestinationFileURI", "MetaData", "DateAddedUTC", "LastModifiedUTC",
	})
	if err != nil {
		return module.FileInfo{}, err
	}

	count := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		var url, title, destination, metadata, added, modified any
		if err := rows.Scan(&url, &title, &destination, &metadata, &added, &modified); err != nil {
			continue
		}
		if err := stream.Write([]string{
			renderBrowserValue(url),
			renderBrowserValue(title),
			renderBrowserValue(destination),
			renderBrowserValue(metadata),
			firefoxTimeString(browserInt(added)),
			firefoxTimeString(browserInt(modified)),
		}); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
		count++
	}
	if err := rows.Err(); err != nil || count == 0 {
		stream.Abort()
		return module.FileInfo{}, nil
	}
	return stream.Close()
}
