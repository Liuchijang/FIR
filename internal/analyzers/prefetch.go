package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/prefetch"
)

func init() { module.RegisterAnalyzer(&prefetchParser{}) }

type prefetchParser struct{ offlineCapable }

func (c *prefetchParser) Name() string     { return "prefetch_parser" }
func (c *prefetchParser) Category() string { return "execution" }
func (c *prefetchParser) Description() string {
	return "Parse Prefetch: execution times, run counts, volumes and the files each run loaded"
}

// maxPreviousRuns is how many older executions prefetch_files.csv carries beside the
// most recent one. Versions 26 and later record eight timestamps in total.
const maxPreviousRuns = 7

// Analyze parses the record's contents rather than its container.
//
// This used to read the first sixteen bytes and the .pf file's own MAC timestamps,
// and both halves were wrong on a modern host. Windows 10 stores Prefetch compressed,
// so those bytes are the container's "MAM" magic — 250 of 256 files in a real run
// reported version 72171853, a blank signature and a header size in the billions. And
// the MAC timestamps belong to whichever copy of the file was opened: for a collected
// artifact they record the moment Tyto copied it, so the same run analyzed twice
// produced 256 rows differing only in AccessedUTC.
//
// internal/prefetch decompresses the container and reads what is inside: up to eight
// execution timestamps, the run count, the volumes touched, and the files and
// directories each traced run loaded. All of that is in the file's bytes, so a
// collected copy carries it intact — which is the only reason offline analysis of a
// Prefetch directory is worth running.
func (c *prefetchParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create prefetch parser output dir: %w", err))
	}

	sourceDir, live, err := resolveArtifactSource(req, "prefetch")
	if err != nil {
		return skippedNoSource(outDir, "collected Prefetch directory")
	}
	if live {
		sourceDir = filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("read prefetch source dir: %w", err))
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	records := make([]parsedPrefetch, 0, len(names))
	var parseErrs []string
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		file, err := prefetch.Parse(filepath.Join(sourceDir, name))
		if err != nil {
			// One unreadable .pf used to cost the whole CSV. A Prefetch folder
			// routinely holds a file the OS is writing to, and a collection can bring
			// home a file an EDR zero-filled on read — six of 256 in a real run. The
			// file still gets a row saying why it could not be read, because a record
			// silently missing from the CSV is indistinguishable from a host that
			// never ran that program.
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", name, err))
			records = append(records, parsedPrefetch{name: name, err: err})
			continue
		}
		file.SetNameHash(name)
		records = append(records, parsedPrefetch{name: name, file: file})
	}

	if len(records) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no prefetch files found in %s", sourceDir)}
	}

	files, err := writePrefetchCSVs(outDir, records)
	if err != nil {
		return analyzerError(outDir, err)
	}

	result := module.AnalyzeResult{Files: files, OutputPath: outDir}
	if len(parseErrs) > 0 {
		result.Error = fmt.Sprintf("parsed %d of %d prefetch file(s); %d could not be read: %s",
			len(records)-len(parseErrs), len(records), len(parseErrs), strings.Join(parseErrs, "; "))
	}
	return result
}

// parsedPrefetch pairs a source file name with its record, or with the reason there
// is no record.
type parsedPrefetch struct {
	name string
	file *prefetch.File
	err  error
}

func writePrefetchCSVs(outDir string, records []parsedPrefetch) ([]module.FileInfo, error) {
	var files []module.FileInfo

	fi, err := writePrefetchFiles(outDir, records)
	if err != nil {
		return files, err
	}
	files = append(files, fi)

	fi, err = writePrefetchRunTimes(outDir, records)
	if err != nil {
		return files, err
	}
	files = append(files, fi)

	fi, err = writePrefetchVolumes(outDir, records)
	if err != nil {
		return files, err
	}
	files = append(files, fi)

	fi, err = writePrefetchReferences(outDir, records)
	if err != nil {
		return files, err
	}
	return append(files, fi), nil
}

func writePrefetchFiles(outDir string, records []parsedPrefetch) (module.FileInfo, error) {
	header := []string{
		"SourceFile", "ExecutableName", "PrefetchHash", "HashMatchesFileName",
		"Version", "FieldLayout", "Compressed", "DeclaredRecordSize", "ParsedRecordSize",
		"RunCount", "RunTimeCount", "LastRunUTC",
	}
	for i := 1; i <= maxPreviousRuns; i++ {
		header = append(header, fmt.Sprintf("PreviousRun%dUTC", i))
	}
	header = append(header, "VolumeCount", "DirectoryCount", "LoadedFileCount", "ParseError")

	rows := make([][]string, 0, len(records))
	for _, record := range records {
		// A record that would not parse still gets a row. Its timestamp columns stay
		// empty rather than carrying a placeholder, because a consumer that types the
		// column rejects the whole file over one cell it cannot convert.
		if record.file == nil {
			row := []string{record.name, "", "", "", "", "", "", "", "", "", "", ""}
			row = append(row, make([]string, maxPreviousRuns)...)
			rows = append(rows, append(row, "", "", "", record.err.Error()))
			continue
		}

		file := record.file
		row := []string{
			record.name,
			file.ExecutableName,
			fmt.Sprintf("%08X", file.Hash),
			strconv.FormatBool(file.HashMatchesName),
			strconv.FormatUint(uint64(file.Version), 10),
			file.LayoutName,
			strconv.FormatBool(file.Compressed),
			strconv.FormatUint(uint64(file.DeclaredSize), 10),
			strconv.Itoa(file.ActualSize),
			strconv.FormatUint(uint64(file.RunCount), 10),
			strconv.Itoa(len(file.RunTimes)),
			formatTime(file.LastRun(), ""),
		}
		for i := 1; i <= maxPreviousRuns; i++ {
			if i < len(file.RunTimes) {
				row = append(row, formatTime(file.RunTimes[i], ""))
				continue
			}
			row = append(row, "")
		}
		rows = append(rows,
			append(row,
				strconv.Itoa(len(file.Volumes)),
				strconv.Itoa(file.DirectoryCount()),
				strconv.Itoa(len(file.LoadedFiles)),
				""))
	}
	return writeCSV(filepath.Join(outDir, "prefetch_files.csv"), header, rows)
}

// writePrefetchRunTimes emits one row per execution, which is the shape a timeline
// gets built from. The wide columns in prefetch_files.csv answer "when did this run
// last"; this answers "what ran in this window".
func writePrefetchRunTimes(outDir string, records []parsedPrefetch) (module.FileInfo, error) {
	rows := make([][]string, 0, len(records)*4)
	for _, record := range records {
		if record.file == nil {
			continue
		}
		for i, runTime := range record.file.RunTimes {
			rows = append(rows, []string{
				formatTime(runTime, ""),
				record.file.ExecutableName,
				record.name,
				strconv.Itoa(i),
				strconv.FormatUint(uint64(record.file.RunCount), 10),
			})
		}
	}
	// Newest first, matching the order inside a record.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] > rows[j][0] })
	return writeCSV(filepath.Join(outDir, "prefetch_run_times.csv"),
		[]string{"RunUTC", "ExecutableName", "SourceFile", "RunIndex", "TotalRunCount"}, rows)
}

func writePrefetchVolumes(outDir string, records []parsedPrefetch) (module.FileInfo, error) {
	rows := make([][]string, 0, len(records))
	for _, record := range records {
		if record.file == nil {
			continue
		}
		for i, volume := range record.file.Volumes {
			rows = append(rows, []string{
				record.name,
				record.file.ExecutableName,
				strconv.Itoa(i),
				volume.DevicePath,
				volume.SerialHex,
				formatTime(volume.Created, ""),
				strconv.Itoa(len(volume.Directories)),
				strconv.Itoa(volume.FileRefCount),
			})
		}
	}
	return writeCSV(filepath.Join(outDir, "prefetch_volumes.csv"), []string{
		"SourceFile", "ExecutableName", "VolumeIndex", "DevicePath",
		"SerialNumber", "VolumeCreatedUTC", "DirectoryCount", "FileReferenceCount",
	}, rows)
}

// writePrefetchReferences streams the paths every traced run touched.
//
// Streamed rather than materialized: one host's 250 records held 36,697 loaded files
// and 8,987 directories, and that scales with how much software a machine runs rather
// than with anything bounded.
func writePrefetchReferences(outDir string, records []parsedPrefetch) (module.FileInfo, error) {
	stream, err := newCSVStream(filepath.Join(outDir, "prefetch_references.csv"),
		[]string{"SourceFile", "ExecutableName", "ReferenceType", "Path"})
	if err != nil {
		return module.FileInfo{}, err
	}

	for _, record := range records {
		if record.file == nil {
			continue
		}
		write := func(kind, path string) error {
			return stream.Write([]string{record.name, record.file.ExecutableName, kind, path})
		}
		for _, path := range record.file.LoadedFiles {
			if err := write("File", path); err != nil {
				stream.Abort()
				return module.FileInfo{}, err
			}
		}
		for _, volume := range record.file.Volumes {
			for _, path := range volume.Directories {
				if err := write("Directory", path); err != nil {
					stream.Abort()
					return module.FileInfo{}, err
				}
			}
		}
	}
	return stream.Close()
}
