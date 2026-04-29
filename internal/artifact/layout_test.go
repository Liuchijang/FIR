package artifact

import (
	"path/filepath"
	"testing"
)

func TestModuleDirLegacyLayout(t *testing.T) {
	outputDir := t.TempDir()
	tests := []struct {
		name     string
		mode     string
		module   string
		category string
		want     string
	}{
		{name: "prefetch", mode: ModeCollector, module: "prefetch", category: "execution", want: filepath.Join(outputDir, "execution", "prefetch")},
		{name: "amcache", mode: ModeCollector, module: "amcache", category: "execution", want: filepath.Join(outputDir, "execution")},
		{name: "eventlog", mode: ModeCollector, module: "eventlog", category: "eventlog", want: filepath.Join(outputDir, "eventlog")},
		{name: "analyzer", mode: ModeAnalyzer, module: "prefetch_parser", category: "execution", want: filepath.Join(outputDir, "Analyzer", "prefetch_parser")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ModuleDir(outputDir, tt.mode, tt.module, tt.category)
			if got != tt.want {
				t.Fatalf("ModuleDir() = %q, want %q", got, tt.want)
			}
		})
	}
}
