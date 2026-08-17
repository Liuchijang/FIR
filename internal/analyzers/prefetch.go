package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterAnalyzer(&prefetchParser{}) }

type prefetchParser struct{ offlineCapable }

func (c *prefetchParser) Name() string     { return "prefetch_parser" }
func (c *prefetchParser) Category() string { return "execution" }
func (c *prefetchParser) Description() string {
	return "Parse Prefetch"
}

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

	rows := make([][]string, 0, len(entries))
	var parseErrs []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}

		row, err := parsePrefetchMetadata(filepath.Join(sourceDir, entry.Name()))
		if err != nil {
			// One unreadable .pf used to cost the whole CSV. A Prefetch folder
			// routinely holds a file the OS is writing to; losing every other
			// execution record over it is the wrong trade, and the runner
			// already reports files-plus-error as a warning.
			parseErrs = append(parseErrs, err.Error())
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })

	if len(rows) == 0 {
		if len(parseErrs) > 0 {
			return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no prefetch files parsed in %s: %s", sourceDir, strings.Join(parseErrs, "; "))}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no prefetch files found in %s", sourceDir)}
	}

	result := csvResult(outDir, "prefetch_files.csv", []string{
		"SourceFile",
		"ExecutableName",
		"PrefetchHash",
		"Version",
		"Signature",
		"HeaderFileSize",
		"ObservedFileSize",
		"CreatedUTC",
		"ModifiedUTC",
		"AccessedUTC",
	}, rows)
	if result.Error == "" && len(parseErrs) > 0 {
		result.Error = fmt.Sprintf("parsed %d prefetch file(s) with %d failure(s): %s", len(rows), len(parseErrs), strings.Join(parseErrs, "; "))
	}
	return result
}

func parsePrefetchMetadata(path string) ([]string, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat prefetch file %s: %w", path, err)
	}

	header := make([]byte, 16)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open prefetch file %s: %w", path, err)
	}
	defer f.Close()

	// ReadFull, not Read: a short read leaves the tail of the buffer zeroed, and
	// those zeros parse as a version 0 file with a zero header size rather than
	// as the truncated file it is.
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("read prefetch header %s: %w", path, err)
	}

	version := binary.LittleEndian.Uint32(header[0:4])
	signature := strings.TrimRight(string(header[4:8]), "\x00")
	headerSize := binary.LittleEndian.Uint32(header[12:16])

	fileName := filepath.Base(path)
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	exeName := baseName
	hash := ""
	if idx := strings.LastIndex(baseName, "-"); idx > 0 {
		exeName = baseName[:idx]
		hash = baseName[idx+1:]
	}

	created, accessed, modified := fileTimesUTC(stat)
	return []string{
		fileName,
		exeName,
		hash,
		fmt.Sprintf("%d", version),
		signature,
		fmt.Sprintf("%d", headerSize),
		fmt.Sprintf("%d", stat.Size()),
		created,
		modified,
		accessed,
	}, nil
}

func fileTimesUTC(stat os.FileInfo) (string, string, string) {
	modified := formatTime(stat.ModTime(), "")
	created := ""
	accessed := ""

	data, ok := stat.Sys().(*syscall.Win32FileAttributeData)
	if ok {
		created = win32FiletimeString(data.CreationTime)
		accessed = win32FiletimeString(data.LastAccessTime)
		if value := win32FiletimeString(data.LastWriteTime); value != "" {
			modified = value
		}
	}

	return created, accessed, modified
}

func win32FiletimeString(ft syscall.Filetime) string {
	return formatFiletimeParts(ft.LowDateTime, ft.HighDateTime, "")
}
