package module

import (
	"context"
	"fmt"
	"time"
)

type RequestCollector interface {
	Module
	CollectWithRequest(ctx context.Context, req CollectRequest) CollectResult
}

type artifactAdapter struct {
	category  string
	collector ArtifactCollector
}

func RegisterArtifact(category string, collector ArtifactCollector) {
	Register(&artifactAdapter{
		category:  category,
		collector: collector,
	})
}

func (a *artifactAdapter) Name() string {
	return a.collector.Name()
}

func (a *artifactAdapter) Category() string {
	return a.category
}

func (a *artifactAdapter) Description() string {
	return a.collector.Description()
}

func (a *artifactAdapter) Collect(ctx context.Context, outputDir string) ([]FileInfo, error) {
	result := a.CollectWithRequest(ctx, CollectRequest{
		OutputDir:    outputDir,
		ArtifactDir:  ModuleDir(outputDir, a),
		StartedAt:    time.Now(),
		SourcePolicy: SourcePolicyCollectedThenLive,
	})
	if result.Error != "" {
		return result.Files, fmt.Errorf("%s", result.Error)
	}
	return result.Files, nil
}

func (a *artifactAdapter) CollectWithRequest(ctx context.Context, req CollectRequest) CollectResult {
	return a.collector.Collect(ctx, req)
}

// EstimatedBytes forwards to the wrapped collector so the estimate is not hidden by
// the adapter; 0 means the collector has no better answer than the flat estimate.
func (a *artifactAdapter) EstimatedBytes() int64 {
	if est, ok := a.collector.(SizeEstimator); ok {
		return est.EstimatedBytes()
	}
	return 0
}
