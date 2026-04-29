package module

import (
	"context"
	"fmt"
	"time"
)

// RequestAnalyzer is the runtime bridge for analyzers using AnalyzeRequest.
type RequestAnalyzer interface {
	Module
	AnalyzeWithRequest(ctx context.Context, req AnalyzeRequest) AnalyzeResult
}

type analyzerAdapter struct {
	analyzer Analyzer
}

// RegisterAnalyzer registers a post-collection analyzer using the request/result contract.
func RegisterAnalyzer(analyzer Analyzer) {
	Register(&analyzerAdapter{analyzer: analyzer})
}

func (a *analyzerAdapter) Name() string {
	return a.analyzer.Name()
}

func (a *analyzerAdapter) Category() string {
	return a.analyzer.Category()
}

func (a *analyzerAdapter) Mode() string {
	return ModeAnalyzer
}

func (a *analyzerAdapter) Description() string {
	return a.analyzer.Description()
}

func (a *analyzerAdapter) Collect(ctx context.Context, outputDir string) ([]FileInfo, error) {
	result := a.AnalyzeWithRequest(ctx, AnalyzeRequest{
		OutputDir:    outputDir,
		AnalyzerDir:  ModuleDir(outputDir, a),
		StartedAt:    time.Now(),
		SourcePolicy: SourcePolicyCollectedThenLive,
	})
	if result.Error != "" {
		return result.Files, fmt.Errorf("%s", result.Error)
	}
	return result.Files, nil
}

func (a *analyzerAdapter) AnalyzeWithRequest(ctx context.Context, req AnalyzeRequest) AnalyzeResult {
	return a.analyzer.Analyze(ctx, req)
}
