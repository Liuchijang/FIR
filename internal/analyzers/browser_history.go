package analyzers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	browsercollector "github.com/Liuchijang/FIR/internal/collectors/browser"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
	_ "modernc.org/sqlite"
)

func init() { module.RegisterAnalyzer(&browserHistoryParser{}) }

type browserHistoryParser struct{}

type browserHistoryRow struct {
	Username     string
	Browser      string
	Profile      string
	Family       string
	SourceDB     string
	VisitTimeUTC string
	URL          string
	Title        string
	VisitCount   string
	TypedCount   string
	Transition   string
	VisitType    string
	LastVisitUTC string
}

func (c *browserHistoryParser) Name() string     { return "browser_history_parser" }
func (c *browserHistoryParser) Category() string { return "browser" }
func (c *browserHistoryParser) Description() string {
	return "Parse browser history from collected or live selected browser profiles"
}

func (c *browserHistoryParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create browser history parser output dir: %w", err))
	}

	sources, err := resolveBrowserProfileSources(req)
	if err != nil {
		return analyzerError(outDir, err)
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no browser profiles available for history analysis"}
	}

	var files []module.FileInfo
	var parseErrors []string
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		rows, err := parseBrowserProfileHistory(outDir, source.Profile)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
			continue
		}
		if len(rows) == 0 {
			parseErrors = append(parseErrors, fmt.Sprintf("%s/%s/%s: no browser history entries parsed", source.Profile.User, source.Profile.Browser, source.Profile.Name))
			continue
		}

		sort.Slice(rows, func(i, j int) bool {
			if rows[i].VisitTimeUTC == rows[j].VisitTimeUTC {
				return rows[i].URL < rows[j].URL
			}
			return rows[i].VisitTimeUTC > rows[j].VisitTimeUTC
		})

		outCSV := filepath.Join(outDir, browserCSVName(source.Profile, "history.csv"))
		csvRows := make([][]string, 0, len(rows))
		for _, row := range rows {
			csvRows = append(csvRows, []string{
				row.Username,
				row.Browser,
				row.Profile,
				row.Family,
				row.SourceDB,
				row.VisitTimeUTC,
				row.URL,
				row.Title,
				row.VisitCount,
				row.TypedCount,
				row.Transition,
				row.VisitType,
				row.LastVisitUTC,
			})
		}
		fi, err := writeCSV(outCSV, []string{
			"Username",
			"Browser",
			"Profile",
			"Family",
			"SourceDB",
			"VisitTimeUTC",
			"URL",
			"Title",
			"VisitCount",
			"TypedCount",
			"Transition",
			"VisitType",
			"LastVisitUTC",
		}, csvRows)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s/%s/%s: write csv %v", source.Profile.User, source.Profile.Browser, source.Profile.Name, err))
			continue
		}
		files = append(files, fi)

		// Downloads come out of the same database, so they are exported here
		// rather than by a module that would copy it a second time.
		downloads, err := exportProfileDownloads(ctx, outDir, source.Profile)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s: downloads %v", browserProfileLabel(source.Profile), err))
		} else if downloads.Path != "" {
			files = append(files, downloads)
		}
	}

	if len(files) == 0 {
		if len(parseErrors) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no browser history entries parsed: %s", strings.Join(parseErrors, "; "))}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: "no browser history entries parsed"}
	}

	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}

func resolveBrowserProfileSources(req module.AnalyzeRequest) ([]browserProfileSource, error) {
	if req.IsSelected(browsercollector.BrowserCollectorName) {
		if sourceDir, ok := existingModuleDir(req.OutputDir, browsercollector.BrowserCollectorName); ok {
			sources, err := collectedBrowserProfileSources(sourceDir)
			if err == nil && len(sources) > 0 {
				return sources, nil
			}
		}
		return nil, fmt.Errorf("browser collector was selected but collected browser history sources were not found")
	}

	profiles, err := browsercollector.ResolveProfiles()
	if err != nil {
		return nil, err
	}

	sources := make([]browserProfileSource, 0, len(profiles))
	for _, profile := range profiles {
		sources = append(sources, browserProfileSource{Profile: profile})
	}
	return sources, nil
}

func collectedBrowserProfileSources(sourceDir string) ([]browserProfileSource, error) {
	userEntries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("read browser source dir: %w", err)
	}

	var sources []browserProfileSource
	for _, userEntry := range userEntries {
		if !userEntry.IsDir() {
			continue
		}

		username := userEntry.Name()
		userDir := filepath.Join(sourceDir, username)
		browserEntries, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}

		for _, browserEntry := range browserEntries {
			if !browserEntry.IsDir() {
				continue
			}

			browserName := browserEntry.Name()
			browserDir := filepath.Join(userDir, browserName)
			profileEntries, err := os.ReadDir(browserDir)
			if err != nil {
				continue
			}

			for _, profileEntry := range profileEntries {
				if !profileEntry.IsDir() {
					continue
				}

				profileDir := filepath.Join(browserDir, profileEntry.Name())
				sources = append(sources, browserProfileSource{
					Profile: browsercollector.BrowserProfile{
						User:    username,
						Browser: browserName,
						Name:    profileEntry.Name(),
						Path:    profileDir,
						Family:  inferBrowserFamily(browserName, profileDir),
					},
				})
			}
		}
	}

	return sources, nil
}

func inferBrowserFamily(browserName, profileDir string) string {
	if _, err := os.Stat(filepath.Join(profileDir, "places.sqlite")); err == nil {
		return "firefox"
	}
	if strings.EqualFold(browserName, "Firefox") {
		return "firefox"
	}
	return "chromium"
}

func parseBrowserProfileHistory(outDir string, profile browsercollector.BrowserProfile) ([]browserHistoryRow, error) {
	if rows, err := parseChromiumHistory(outDir, profile); err == nil && len(rows) > 0 {
		return rows, nil
	}
	if rows, err := parseFirefoxHistory(outDir, profile); err == nil && len(rows) > 0 {
		return rows, nil
	}
	return nil, fmt.Errorf("%s/%s/%s: no supported browser history database found", profile.User, profile.Browser, profile.Name)
}

func parseChromiumHistory(outDir string, profile browsercollector.BrowserProfile) ([]browserHistoryRow, error) {
	sourceDB := filepath.Join(profile.Path, "History")
	if _, err := os.Stat(sourceDB); err != nil {
		return nil, err
	}

	workingDB, cleanup, err := prepareSQLiteWorkingCopy(outDir, sourceDB)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", workingDB)
	if err != nil {
		return nil, fmt.Errorf("open chromium history db: %w", err)
	}
	defer db.Close()

	query := `
SELECT
    urls.url,
    COALESCE(urls.title, ''),
    COALESCE(urls.visit_count, 0),
    COALESCE(urls.typed_count, 0),
    COALESCE(visits.visit_time, 0),
    COALESCE(urls.last_visit_time, 0),
    COALESCE(visits.transition, 0)
FROM urls
JOIN visits ON visits.url = urls.id
ORDER BY visits.visit_time DESC
`

	rs, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query chromium history: %w", err)
	}
	defer rs.Close()

	rows := make([]browserHistoryRow, 0, 256)
	for rs.Next() {
		var urlValue, title string
		var visitCount, typedCount, visitTime, lastVisitTime, transition int64
		if err := rs.Scan(&urlValue, &title, &visitCount, &typedCount, &visitTime, &lastVisitTime, &transition); err != nil {
			continue
		}
		rows = append(rows, browserHistoryRow{
			Username:     profile.User,
			Browser:      profile.Browser,
			Profile:      profile.Name,
			Family:       "chromium",
			SourceDB:     "History",
			VisitTimeUTC: chromiumTimeString(visitTime),
			URL:          urlValue,
			Title:        title,
			VisitCount:   strconv.FormatInt(visitCount, 10),
			TypedCount:   strconv.FormatInt(typedCount, 10),
			Transition:   strconv.FormatInt(transition, 10),
			VisitType:    "",
			LastVisitUTC: chromiumTimeString(lastVisitTime),
		})
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("read chromium history rows: %w", err)
	}

	return rows, nil
}

func parseFirefoxHistory(outDir string, profile browsercollector.BrowserProfile) ([]browserHistoryRow, error) {
	sourceDB := filepath.Join(profile.Path, "places.sqlite")
	if _, err := os.Stat(sourceDB); err != nil {
		return nil, err
	}

	workingDB, cleanup, err := prepareSQLiteWorkingCopy(outDir, sourceDB)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", workingDB)
	if err != nil {
		return nil, fmt.Errorf("open firefox history db: %w", err)
	}
	defer db.Close()

	query := `
SELECT
    moz_places.url,
    COALESCE(moz_places.title, ''),
    COALESCE(moz_places.visit_count, 0),
    COALESCE(moz_places.last_visit_date, 0),
    COALESCE(moz_historyvisits.visit_date, 0),
    COALESCE(moz_historyvisits.visit_type, 0)
FROM moz_places
JOIN moz_historyvisits ON moz_historyvisits.place_id = moz_places.id
ORDER BY moz_historyvisits.visit_date DESC
`

	rs, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query firefox history: %w", err)
	}
	defer rs.Close()

	rows := make([]browserHistoryRow, 0, 256)
	for rs.Next() {
		var urlValue, title string
		var visitCount, lastVisitDate, visitDate, visitType int64
		if err := rs.Scan(&urlValue, &title, &visitCount, &lastVisitDate, &visitDate, &visitType); err != nil {
			continue
		}
		rows = append(rows, browserHistoryRow{
			Username:     profile.User,
			Browser:      profile.Browser,
			Profile:      profile.Name,
			Family:       "firefox",
			SourceDB:     "places.sqlite",
			VisitTimeUTC: firefoxTimeString(visitDate),
			URL:          urlValue,
			Title:        title,
			VisitCount:   strconv.FormatInt(visitCount, 10),
			TypedCount:   "",
			Transition:   "",
			VisitType:    strconv.FormatInt(visitType, 10),
			LastVisitUTC: firefoxTimeString(lastVisitDate),
		})
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("read firefox history rows: %w", err)
	}

	return rows, nil
}

// prepareSQLiteWorkingCopy copies a history database somewhere it can be opened
// read-write, because SQLite has to be able to replay the -wal file and the
// original is on a live, locked profile.
//
// The copy lands under the run's own output directory, not the machine's %TEMP%.
// The subject of a triage run is evidence: dropping a full copy of every
// browser profile's history into its temp directory writes to the volume under
// investigation, and anything left behind by a killed run stays there. Under
// outDir it is on the evidence drive and goes away with the run directory.
func prepareSQLiteWorkingCopy(outDir string, sourceDB string) (string, func(), error) {
	tempDir, err := os.MkdirTemp(outDir, "sqlite-work-*")
	if err != nil {
		return "", nil, fmt.Errorf("create sqlite work dir: %w", err)
	}

	cleanup := func() { _ = os.RemoveAll(tempDir) }
	targetDB := filepath.Join(tempDir, filepath.Base(sourceDB))
	if _, err := utils.SafeCopyFile(sourceDB, targetDB); err != nil {
		if _, err := utils.SafeCopyFileBackup(sourceDB, targetDB); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("copy sqlite db %s: %w", sourceDB, err)
		}
	}

	for _, sidecar := range sqliteSidecarPaths(sourceDB) {
		if _, err := os.Stat(sidecar); err != nil {
			continue
		}
		targetSidecar := filepath.Join(tempDir, filepath.Base(sidecar))
		if _, err := utils.SafeCopyFile(sidecar, targetSidecar); err != nil {
			_, _ = utils.SafeCopyFileBackup(sidecar, targetSidecar)
		}
	}

	return targetDB, cleanup, nil
}

func sqliteSidecarPaths(sourceDB string) []string {
	return []string{sourceDB + "-wal", sourceDB + "-shm"}
}

func chromiumTimeString(value int64) string {
	// Chromium counts microseconds from 1601-01-01, Firefox from the Unix epoch.
	const chromiumEpochDelta = 11644473600000000
	if value < chromiumEpochDelta {
		return ""
	}
	return formatUnixMicro(value-chromiumEpochDelta, "")
}

func firefoxTimeString(value int64) string {
	return formatUnixMicro(value, "")
}
