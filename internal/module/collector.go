// Package module defines the core module contract and associated types used by
// collectors and analyzers in FIR.
package module

import (
	"context"
	"time"

	"github.com/Liuchijang/FIR/internal/artifact"
)

const (
	ModeCollector = "collector"
	ModeAnalyzer  = "analyzer"
)

type modeProvider interface {
	Mode() string
}

// Module is the interface implemented by both collection and analysis modules.
// Each module is responsible for producing forensic output in its category.
type Module interface {
	// Name returns the unique identifier for this module (e.g., "mft", "registry").
	Name() string

	// Category returns the artifact category (e.g., "ntfs", "registry", "eventlog").
	Category() string

	// Description returns a human-readable description of what this module does.
	Description() string

	// Collect executes the module logic.
	// It receives a context for timeout/cancellation and the output directory path.
	// The module must create its own subdirectory within outputDir if needed.
	Collect(ctx context.Context, outputDir string) ([]FileInfo, error)
}

// FileInfo holds metadata about a collected file, including its integrity hash.
type FileInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Result captures the outcome of a single module's execution.
type Result struct {
	CollectorName  string        `json:"collector_name"`
	Category       string        `json:"category"`
	FilesCollected []FileInfo    `json:"files_collected"`
	Duration       time.Duration `json:"-"`
	DurationSec    float64       `json:"duration_seconds"`
	Status         string        `json:"status"`
	ErrorKind      string        `json:"error_kind,omitempty"`
	OutputPath     string        `json:"output_path,omitempty"`
	Skipped        bool          `json:"skipped,omitempty"`
	Error          string        `json:"error,omitempty"`
	Success        bool          `json:"success"`
}

func ModeOf(m Module) string {
	if provider, ok := m.(modeProvider); ok {
		mode := provider.Mode()
		if mode != "" {
			return mode
		}
	}
	return ModeCollector
}

func ModeDirName(mode string) string {
	return artifact.ModeDirName(mode)
}

// ModuleDir returns the default module directory for a collector or analyzer.
// Collector paths stay compatible with the legacy on-disk layout so existing
// collection code and analyzer fallbacks continue to work.
func ModuleDir(outputDir string, m Module) string {
	return artifact.ModuleDir(outputDir, ModeOf(m), m.Name(), m.Category())
}
