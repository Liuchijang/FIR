package module

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AnalyzeRequest struct {
	OutputDir string
	// SourceDir is the run to read collected artifacts from when it is not the
	// run being written. Empty means "read from OutputDir", which is every live
	// run; offline analysis sets it. Read it through SourceRoot().
	SourceDir       string
	AnalyzerDir     string
	Hostname        string
	StartedAt       time.Time
	SourcePolicy    SourcePolicy
	SelectedModules map[string]bool
	// CollectedFiles is what this run's collectors recorded, keyed by module name.
	//
	// It exists for the facts about an artifact that do not survive being copied.
	// A collected file's own timestamps are the moment Tyto copied it, so an
	// analyzer that wants the subject's has to be told; the collector knew, and
	// this is how the answer reaches the other side of the barrier. Offline it is
	// filled from the analyzed run's manifest, which is the same record.
	CollectedFiles map[string][]FileInfo
	Options        map[string]string
}

// SourceFile returns what the run recorded about one collected artifact.
//
// It is addressed the way the collector filed it: the module that collected it,
// and the path relative to that module's directory — which is what FileInfo.Path
// holds and what an offline run rejoins against.
func (req AnalyzeRequest) SourceFile(moduleName, relPath string) (FileInfo, bool) {
	want := normalizeRelPath(relPath)
	for _, file := range req.CollectedFiles[moduleName] {
		if normalizeRelPath(file.Path) == want {
			return file, true
		}
	}
	return FileInfo{}, false
}

// normalizeRelPath makes the two spellings of the same relative path compare
// equal: the separator differs between where a path is built and where it is read
// back out of JSON, and Windows paths do not differ by case.
func normalizeRelPath(path string) string {
	return strings.ToLower(strings.ReplaceAll(filepath.Clean(path), "/", `\`))
}

// EnsureOutputDir resolves this request's analyzer directory — defaulting to
// filepath.Join(OutputDir, "Analyzer", name) when the caller didn't set one —
// and creates it. Every analyzer's Analyze method needs this, so it's
// centralized here instead of being copy-pasted per module.
func (req AnalyzeRequest) EnsureOutputDir(name string) (string, error) {
	outDir := req.AnalyzerDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "Analyzer", name)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return outDir, err
	}
	return outDir, nil
}

type AnalyzeResult struct {
	Files      []FileInfo
	OutputPath string
	Skipped    bool
	Error      string
}

type Analyzer interface {
	Name() string
	Category() string
	Description() string
	Analyze(ctx context.Context, req AnalyzeRequest) AnalyzeResult
}
