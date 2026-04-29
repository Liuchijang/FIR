package collection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/resource"
)

type fakeModule struct {
	name string
	err  error
}

func (f fakeModule) Name() string        { return f.name }
func (f fakeModule) Category() string    { return "test" }
func (f fakeModule) Description() string { return "fake module" }
func (f fakeModule) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []module.FileInfo{{Path: f.name + ".txt", SHA256: "abc", Size: 3}}, nil
}

func TestRunWritesManifestAndKeepsModuleFailuresIsolated(t *testing.T) {
	baseDir := t.TempDir()
	report, err := Run(context.Background(), []module.Module{
		fakeModule{name: "ok"},
		fakeModule{name: "fail", err: errors.New("expected failure")},
	}, Options{
		OutputBaseDir: baseDir,
		SilentConsole: true,
		Concurrency:   2,
		Resources: resource.Config{
			CPULimitPercent: 60,
			RAMCapBytes:     512 * 1024 * 1024,
			Workers:         2,
			DiskIOLimitBps:  80 * 1024 * 1024,
			Compress:        false,
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.SuccessCount != 1 || report.FailureCount != 1 {
		t.Fatalf("counts = success:%d failure:%d, want success:1 failure:1", report.SuccessCount, report.FailureCount)
	}
	if report.OutputDir == "" {
		t.Fatalf("OutputDir is empty")
	}
	if _, err := os.Stat(filepath.Join(report.OutputDir, "manifest.json")); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(report.OutputDir, "metadata.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metadata.json should not be written, stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(report.OutputDir, "summary.txt")); err != nil {
		t.Fatalf("summary not written: %v", err)
	}
}

func TestRunCompressionRemovesRawOutput(t *testing.T) {
	baseDir := t.TempDir()
	report, err := Run(context.Background(), []module.Module{
		fakeModule{name: "ok"},
	}, Options{
		OutputBaseDir: baseDir,
		SilentConsole: true,
		Concurrency:   1,
		Resources: resource.Config{
			CPULimitPercent: 60,
			RAMCapBytes:     512 * 1024 * 1024,
			Workers:         1,
			DiskIOLimitBps:  80 * 1024 * 1024,
			Compress:        true,
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if _, err := os.Stat(report.OutputDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw output should be removed, stat error = %v", err)
	}
	if _, err := os.Stat(report.OutputDir + ".zip"); err != nil {
		t.Fatalf("archive not written: %v", err)
	}
	if _, err := os.Stat(report.OutputDir + ".zip.sha256"); err != nil {
		t.Fatalf("archive hash sidecar not written: %v", err)
	}
}

type requestCollectorModule struct {
	name  string
	mu    *sync.Mutex
	order *[]string
}

func (m requestCollectorModule) Name() string        { return m.name }
func (m requestCollectorModule) Category() string    { return "test" }
func (m requestCollectorModule) Description() string { return "request collector" }
func (m requestCollectorModule) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	return nil, errors.New("legacy collect should not run")
}
func (m requestCollectorModule) CollectWithRequest(ctx context.Context, req module.CollectRequest) module.CollectResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.order = append(*m.order, m.name)
	return module.CollectResult{Files: []module.FileInfo{{Path: "collector.txt", Size: 1}}}
}

type requestAnalyzerModule struct {
	name           string
	mu             *sync.Mutex
	order          *[]string
	selectedSource bool
	sourcePolicy   module.SourcePolicy
}

func (m *requestAnalyzerModule) Name() string        { return m.name }
func (m *requestAnalyzerModule) Category() string    { return "test" }
func (m *requestAnalyzerModule) Description() string { return "request analyzer" }
func (m *requestAnalyzerModule) Mode() string        { return module.ModeAnalyzer }
func (m *requestAnalyzerModule) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	return nil, errors.New("legacy collect should not run")
}
func (m *requestAnalyzerModule) AnalyzeWithRequest(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.order = append(*m.order, m.name)
	m.selectedSource = req.IsSelected("source")
	m.sourcePolicy = req.SourcePolicy
	return module.AnalyzeResult{Files: []module.FileInfo{{Path: "analyzer.txt", Size: 1}}}
}

func TestRunExecutesCollectorsBeforeAnalyzersAndPassesRequestContext(t *testing.T) {
	var mu sync.Mutex
	var order []string
	analyzer := &requestAnalyzerModule{name: "parser", mu: &mu, order: &order}

	report, err := Run(context.Background(), []module.Module{
		requestCollectorModule{name: "source", mu: &mu, order: &order},
		analyzer,
	}, Options{
		OutputBaseDir: t.TempDir(),
		SilentConsole: true,
		Concurrency:   2,
		Timeout:       time.Second,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.SuccessCount != 2 || report.FailureCount != 0 {
		t.Fatalf("counts = success:%d failure:%d", report.SuccessCount, report.FailureCount)
	}
	if got := order; len(got) != 2 || got[0] != "source" || got[1] != "parser" {
		t.Fatalf("run order = %v, want [source parser]", got)
	}
	if !analyzer.selectedSource {
		t.Fatalf("analyzer did not receive selected source module")
	}
	if analyzer.sourcePolicy != module.SourcePolicyCollectedThenLive {
		t.Fatalf("source policy = %q, want %q", analyzer.sourcePolicy, module.SourcePolicyCollectedThenLive)
	}
}

type timeoutModule struct{}

func (timeoutModule) Name() string        { return "timeout" }
func (timeoutModule) Category() string    { return "test" }
func (timeoutModule) Description() string { return "times out" }
func (timeoutModule) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRunMarksModuleTimeouts(t *testing.T) {
	report, err := Run(context.Background(), []module.Module{timeoutModule{}}, Options{
		OutputBaseDir: t.TempDir(),
		SilentConsole: true,
		Concurrency:   1,
		Timeout:       10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.FailureCount != 1 {
		t.Fatalf("FailureCount = %d, want 1", report.FailureCount)
	}
	got := report.Results[0]
	if got.Status != module.StatusTimeout {
		t.Fatalf("Status = %q, want %q", got.Status, module.StatusTimeout)
	}
	if got.ErrorKind != module.ErrorKindTimeout {
		t.Fatalf("ErrorKind = %q, want %q", got.ErrorKind, module.ErrorKindTimeout)
	}
}
