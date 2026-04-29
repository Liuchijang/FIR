package module

import (
	"context"
	"time"
)

// AnalyzeRequest is the normalized request shape for analyzer modules.
type AnalyzeRequest struct {
	OutputDir       string
	AnalyzerDir     string
	Hostname        string
	StartedAt       time.Time
	SourcePolicy    SourcePolicy
	SelectedModules map[string]bool
	Options         map[string]string
}

// AnalyzeResult is the normalized result shape for analyzer modules.
type AnalyzeResult struct {
	Files      []FileInfo
	OutputPath string
	Skipped    bool
	Error      string
}

// Analyzer is the preferred contract for post-collection analysis modules.
type Analyzer interface {
	Name() string
	Category() string
	Description() string
	Analyze(ctx context.Context, req AnalyzeRequest) AnalyzeResult
}
