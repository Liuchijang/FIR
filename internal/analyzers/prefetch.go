package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.RegisterAnalyzer(&prefetchParser{}) }

type prefetchParser struct{}

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

	sourceDir := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	if dir, ok := existingModuleDir(req.OutputDir, "prefetch"); ok {
		sourceDir = dir
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("read prefetch source dir: %w", err))
	}

	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}

		row, err := parsePrefetchMetadata(filepath.Join(sourceDir, entry.Name()))
		if err != nil {
			return analyzerError(outDir, err)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })

	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no prefetch files found in %s", sourceDir)}
	}

	return csvResult(outDir, "prefetch_files.csv", []string{
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

	if _, err := f.Read(header); err != nil {
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
	modified := stat.ModTime().UTC().Format(time.RFC3339)
	created := ""
	accessed := ""

	data, ok := stat.Sys().(*syscall.Win32FileAttributeData)
	if ok {
		created = filetimeToRFC3339(data.CreationTime)
		accessed = filetimeToRFC3339(data.LastAccessTime)
		if value := filetimeToRFC3339(data.LastWriteTime); value != "" {
			modified = value
		}
	}

	return created, accessed, modified
}

func filetimeToRFC3339(ft syscall.Filetime) string {
	if ft == (syscall.Filetime{}) {
		return ""
	}
	return time.Unix(0, ft.Nanoseconds()).UTC().Format(time.RFC3339)
}
