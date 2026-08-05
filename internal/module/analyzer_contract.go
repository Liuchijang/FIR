package module

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

type AnalyzeRequest struct {
	OutputDir       string
	AnalyzerDir     string
	Hostname        string
	StartedAt       time.Time
	SourcePolicy    SourcePolicy
	SelectedModules map[string]bool
	Options         map[string]string
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
