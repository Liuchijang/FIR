package module

import (
	"context"
	"path/filepath"
	"testing"
)

type fakeArtifactCollector struct {
	req CollectRequest
}

func (f *fakeArtifactCollector) Name() string        { return "fake_artifact" }
func (f *fakeArtifactCollector) Description() string { return "fake artifact" }
func (f *fakeArtifactCollector) Collect(ctx context.Context, req CollectRequest) CollectResult {
	f.req = req
	return CollectResult{
		Files: []FileInfo{{Path: "artifact.txt", SHA256: "abc", Size: 3}},
	}
}

func TestArtifactAdapterLegacyCollect(t *testing.T) {
	collector := &fakeArtifactCollector{}
	adapter := &artifactAdapter{
		category:  "testing",
		collector: collector,
	}

	outputDir := t.TempDir()
	files, err := adapter.Collect(context.Background(), outputDir)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("Collect() files = %d, want 1", len(files))
	}
	if adapter.Category() != "testing" {
		t.Fatalf("Category() = %q, want testing", adapter.Category())
	}

	wantArtifactDir := filepath.Join(outputDir, "testing")
	if collector.req.ArtifactDir != wantArtifactDir {
		t.Fatalf("ArtifactDir = %q, want %q", collector.req.ArtifactDir, wantArtifactDir)
	}
}
