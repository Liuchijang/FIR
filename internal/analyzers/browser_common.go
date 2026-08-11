package analyzers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	browsercollector "github.com/Liuchijang/FIR/internal/collectors/browser"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
)

// browserProfileSource is one profile an analyzer will read, whether it came
// from this run's collected output or from the live machine.
type browserProfileSource struct {
	Profile browsercollector.BrowserProfile
}

// browserCSVName names a per-profile CSV. Every browser analyzer writes one file
// per profile rather than one merged file, so a profile that fails to parse
// cannot take the others' output with it.
func browserCSVName(profile browsercollector.BrowserProfile, suffix string) string {
	parts := []string{
		output.SanitizeDirNameForExport(profile.User),
		output.SanitizeDirNameForExport(profile.Browser),
		output.SanitizeDirNameForExport(profile.Name),
		suffix,
	}
	return strings.Join(parts, "_")
}

func browserProfileLabel(profile browsercollector.BrowserProfile) string {
	return profile.User + "/" + profile.Browser + "/" + profile.Name
}

// openBrowserSQLite opens a browser database through a working copy.
//
// The original cannot be opened directly: SQLite has to be able to replay the
// -wal file to see the most recent writes, and the live profile holds the file
// locked. Returns ok=false when the profile simply does not have this database,
// which is not an error — no profile carries every one.
func openBrowserSQLite(outDir string, profile browsercollector.BrowserProfile, dbName string) (db *sql.DB, cleanup func(), ok bool, err error) {
	sourceDB := filepath.Join(profile.Path, dbName)
	if _, statErr := os.Stat(sourceDB); statErr != nil {
		return nil, nil, false, nil
	}

	workingDB, removeWorkingCopy, err := prepareSQLiteWorkingCopy(outDir, sourceDB)
	if err != nil {
		return nil, nil, false, err
	}

	handle, err := sql.Open("sqlite", workingDB)
	if err != nil {
		removeWorkingCopy()
		return nil, nil, false, fmt.Errorf("open %s: %w", dbName, err)
	}
	return handle, func() {
		handle.Close()
		removeWorkingCopy()
	}, true, nil
}

// browserTableToCSV streams one table of one database into its own CSV.
//
// It returns a zero FileInfo when the table is absent or empty: an empty CSV in
// an evidence directory is noise, and csvStream.Abort exists so a file that has
// nothing to say never reaches disk.
func browserTableToCSV(ctx context.Context, db *sql.DB, table browserTable, path string) (module.FileInfo, int, error) {
	stream, err := newCSVStream(path, table.headers())
	if err != nil {
		return module.FileInfo{}, 0, err
	}

	rows := 0
	found, err := table.stream(ctx, db, func(record []string) error {
		if writeErr := stream.Write(record); writeErr != nil {
			return writeErr
		}
		rows++
		return nil
	})
	if err != nil || !found || rows == 0 {
		stream.Abort()
		return module.FileInfo{}, 0, err
	}

	fi, err := stream.Close()
	if err != nil {
		return module.FileInfo{}, 0, err
	}
	return fi, rows, nil
}

// browserAnalyzeSQLite is the shape every SQLite-backed browser analyzer takes:
// resolve the profiles, and for each one export a set of tables out of a set of
// databases.
//
// A profile or a database that fails contributes a warning rather than failing
// the module, matching the partial-failure contract in internal/collection — one
// corrupt profile among six must not cost the other five.
type browserExport struct {
	// database is the file inside the profile, e.g. "History".
	database string
	// tables maps a CSV filename suffix to the table exported into it.
	tables []browserExportTable
}

type browserExportTable struct {
	suffix string
	table  browserTable
}

func browserAnalyzeSQLite(ctx context.Context, req module.AnalyzeRequest, outDir string, exports []browserExport) module.AnalyzeResult {
	sources, err := resolveBrowserProfileSources(req)
	if err != nil {
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
		profileFiles, profileWarnings := exportBrowserProfile(ctx, outDir, source.Profile, exports)
		files = append(files, profileFiles...)
		warnings = append(warnings, profileWarnings...)
	}

	if len(files) == 0 {
		if len(warnings) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: strings.Join(warnings, "; ")}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: "no matching browser artifacts found in any profile"}
	}
	result := module.AnalyzeResult{Files: files, OutputPath: outDir}
	if len(warnings) > 0 {
		result.Error = fmt.Sprintf("parsed %d file(s) with %d warning(s): %s", len(files), len(warnings), strings.Join(warnings, "; "))
	}
	return result
}

func exportBrowserProfile(ctx context.Context, outDir string, profile browsercollector.BrowserProfile, exports []browserExport) ([]module.FileInfo, []string) {
	var files []module.FileInfo
	var warnings []string

	for _, export := range exports {
		db, cleanup, ok, err := openBrowserSQLite(outDir, profile, export.database)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s/%s: %v", browserProfileLabel(profile), export.database, err))
			continue
		}
		if !ok {
			continue
		}

		for _, exported := range export.tables {
			path := filepath.Join(outDir, browserCSVName(profile, exported.suffix))
			fi, _, err := browserTableToCSV(ctx, db, exported.table, path)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s/%s: %v", browserProfileLabel(profile), exported.suffix, err))
				continue
			}
			if fi.Path != "" {
				files = append(files, fi)
			}
		}
		cleanup()
	}

	return files, warnings
}
