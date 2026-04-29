package module

import (
	"context"
	"path/filepath"
	"testing"
)

type fakeAnalyzer struct {
	req AnalyzeRequest
}

func (f *fakeAnalyzer) Name() string        { return "fake_analyzer" }
func (f *fakeAnalyzer) Category() string    { return "testing" }
func (f *fakeAnalyzer) Description() string { return "fake analyzer" }
func (f *fakeAnalyzer) Analyze(ctx context.Context, req AnalyzeRequest) AnalyzeResult {
	f.req = req
	return AnalyzeResult{
		Files: []FileInfo{{Path: "analysis.csv", SHA256: "abc", Size: 3}},
	}
}

func TestAnalyzerAdapterLegacyCollect(t *testing.T) {
	analyzer := &fakeAnalyzer{}
	adapter := &analyzerAdapter{analyzer: analyzer}

	outputDir := t.TempDir()
	files, err := adapter.Collect(context.Background(), outputDir)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Collect() files = %d, want 1", len(files))
	}
	if ModeOf(adapter) != ModeAnalyzer {
		t.Fatalf("ModeOf() = %q, want %q", ModeOf(adapter), ModeAnalyzer)
	}

	wantAnalyzerDir := filepath.Join(outputDir, "Analyzer", "fake_analyzer")
	if analyzer.req.AnalyzerDir != wantAnalyzerDir {
		t.Fatalf("AnalyzerDir = %q, want %q", analyzer.req.AnalyzerDir, wantAnalyzerDir)
	}
}
