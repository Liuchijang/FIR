// Package module defines the core module contract and associated types used by
// collectors and analyzers in Tyto.
package module

import (
	"context"
	"time"

	"github.com/Liuchijang/Tyto/internal/artifact"
)

const (
	ModeCollector = "collector"
	ModeAnalyzer  = "analyzer"
)

type modeProvider interface {
	Mode() string
}

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

type FileInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

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

func TotalSize(files []FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

// SizeEstimator lets a module report how many bytes it will actually write, so the
// storage estimate follows the user's selection instead of a flat per-module guess.
// Returning 0 means "no opinion" and falls back to that guess.
type SizeEstimator interface {
	EstimatedBytes() int64
}
