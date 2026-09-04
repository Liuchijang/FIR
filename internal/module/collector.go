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
	// ZeroFilled marks an artifact that copied with the right size and no content.
	//
	// It is a real outcome, not a theoretical one: six of 256 .pf files in a measured
	// run came home at their correct sizes with every byte zero — five binaries an EDR
	// protects and one svchost — and the manifest recorded a valid SHA-256 for each
	// with error_message (none). The copy reported success because the reads returned
	// success; the bytes were simply zeros. Nothing downstream could tell that from a
	// program that had never run.
	//
	// Recorded per file rather than raised as a copy error because the file existing
	// at that size is itself a finding, so the artifact is kept and the manifest says
	// what it is worth.
	ZeroFilled bool `json:"zero_filled,omitempty"`

	// SourceCreated and SourceModified are the artifact's own timestamps on the
	// subject machine, RFC3339Nano in UTC.
	//
	// Nothing else can carry them. No copier in the tree preserves file times, so
	// a collected copy's own timestamps record when Tyto copied it: prefetch_parser
	// had to drop four columns over exactly that, and the same run analyzed twice
	// produced 256 rows differing only in AccessedUTC. For some artifacts it is the
	// finding rather than a detail — a Recent folder's .lnk is created the first
	// time a document is opened and written the last time.
	//
	// Preserving the times on the copy would have been simpler and is deliberately
	// not done: collected files carrying collection times is what made it possible
	// to prove the event log parser was rewriting artifacts after the collector had
	// hashed them, by showing the two mtime windows did not overlap.
	//
	// The access time is not recorded. Windows updates it inconsistently and
	// disables it outright for many operations, so the column would look like a
	// measurement without being one.
	SourceCreated  string `json:"source_created,omitempty"`
	SourceModified string `json:"source_modified,omitempty"`
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
