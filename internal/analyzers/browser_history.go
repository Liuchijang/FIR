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
	"time"

	browsercollector "github.com/Liuchijang/FIR/internal/collectors/browser"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/utils"
	_ "modernc.org/sqlite"
)

func init() { module.RegisterAnalyzer(&browserHistoryParser{}) }

type browserHistoryParser struct{}

type browserHistorySource struct {
	Profile browsercollector.BrowserProfile
}

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

	sources, err := resolveBrowserHistorySources(req)
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

		outCSV := filepath.Join(outDir, browserHistoryCSVName(source.Profile))
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
		if err := writeCSVFile(outCSV, []string{
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
		}, csvRows); err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s/%s/%s: write csv %v", source.Profile.User, source.Profile.Browser, source.Profile.Name, err))
			continue
		}

		fi, err := utils.FileInfoFromPath(outCSV)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("%s/%s/%s: file info %v", source.Profile.User, source.Profile.Browser, source.Profile.Name, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		if len(parseErrors) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no browser history entries parsed: %s", strings.Join(parseErrors, "; "))}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: "no browser history entries parsed"}
	}

	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}

func resolveBrowserHistorySources(req module.AnalyzeRequest) ([]browserHistorySource, error) {
	if req.IsSelected(browsercollector.BrowserCollectorName) {
		if sourceDir, ok := existingModuleDir(req.OutputDir, browsercollector.BrowserCollectorName); ok {
			sources, err := collectedBrowserHistorySources(sourceDir)
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

	sources := make([]browserHistorySource, 0, len(profiles))
	for _, profile := range profiles {
		sources = append(sources, browserHistorySource{Profile: profile})
	}
	return sources, nil
}

func collectedBrowserHistorySources(sourceDir string) ([]browserHistorySource, error) {
	userEntries, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("read browser source dir: %w", err)
	}

	var sources []browserHistorySource
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
				sources = append(sources, browserHistorySource{
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

func prepareSQLiteWorkingCopy(_ string, sourceDB string) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", "fir-sqlite-work-*")
	if err != nil {
		return "", nil, fmt.Errorf("create sqlite temp dir: %w", err)
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
	if value <= 0 {
		return ""
	}
	const chromiumEpochDelta = 11644473600000000
	if value < chromiumEpochDelta {
		return ""
	}
	unixMicros := value - chromiumEpochDelta
	return time.UnixMicro(unixMicros).UTC().Format("2006-01-02 15:04:05")
}

func firefoxTimeString(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.UnixMicro(value).UTC().Format("2006-01-02 15:04:05")
}

func browserHistoryCSVName(profile browsercollector.BrowserProfile) string {
	parts := []string{
		output.SanitizeDirNameForExport(profile.User),
		output.SanitizeDirNameForExport(profile.Browser),
		output.SanitizeDirNameForExport(profile.Name),
		"history.csv",
	}
	return strings.Join(parts, "_")
}
