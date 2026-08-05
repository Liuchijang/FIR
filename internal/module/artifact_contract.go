package module

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

type CollectRequest struct {
	OutputDir       string
	ArtifactDir     string
	Hostname        string
	StartedAt       time.Time
	SourcePolicy    SourcePolicy
	SelectedModules map[string]bool
	Options         map[string]string
}

// EnsureOutputDir resolves this request's artifact directory — defaulting to
// filepath.Join(OutputDir, defaultSubdir) when the caller didn't set one — and
// creates it. Every collector's Collect method needs this, so it's centralized
// here instead of being copy-pasted per module.
func (req CollectRequest) EnsureOutputDir(defaultSubdir string) (string, error) {
	outDir := req.ArtifactDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, defaultSubdir)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return outDir, err
	}
	return outDir, nil
}

type CollectResult struct {
	Files      []FileInfo
	OutputPath string
	Skipped    bool
	Error      string
}

type ArtifactCollector interface {
	Name() string
	Description() string
	Collect(ctx context.Context, req CollectRequest) CollectResult
}
