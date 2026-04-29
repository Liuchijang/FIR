package module

import (
	"context"
	"time"
)

// CollectRequest is the normalized request shape for artifact collectors.
type CollectRequest struct {
	OutputDir       string
	ArtifactDir     string
	Hostname        string
	StartedAt       time.Time
	SourcePolicy    SourcePolicy
	SelectedModules map[string]bool
	Options         map[string]string
}

// CollectResult is the normalized result shape for artifact collectors.
type CollectResult struct {
	Files      []FileInfo
	OutputPath string
	Skipped    bool
	Error      string
}

// ArtifactCollector is the preferred contract for new collection modules.
type ArtifactCollector interface {
	Name() string
	Description() string
	Collect(ctx context.Context, req CollectRequest) CollectResult
}
