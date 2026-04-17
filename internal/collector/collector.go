// Package collector defines the core Collector interface and associated types
// used by all artifact collectors in FIR.
package collector

import (
	"context"
	"time"
)

// Collector is the interface that all artifact collectors must implement.
// Each collector is responsible for acquiring a specific category of forensic
// artifacts and saving them to the designated output directory.
type Collector interface {
	// Name returns the unique identifier for this collector (e.g., "mft", "registry").
	Name() string

	// Category returns the artifact category (e.g., "ntfs", "registry", "eventlog").
	Category() string

	// Description returns a human-readable description of what this collector acquires.
	Description() string

	// Collect performs the actual artifact acquisition.
	// It receives a context for timeout/cancellation and the output directory path.
	// The collector must create its own subdirectory within outputDir if needed.
	Collect(ctx context.Context, outputDir string) ([]FileInfo, error)
}

// FileInfo holds metadata about a collected file, including its integrity hash.
type FileInfo struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Result captures the outcome of a single collector's execution.
type Result struct {
	CollectorName  string        `json:"collector_name"`
	Category       string        `json:"category"`
	FilesCollected []FileInfo    `json:"files_collected"`
	Duration       time.Duration `json:"-"`
	DurationSec    float64       `json:"duration_seconds"`
	Error          string        `json:"error,omitempty"`
	Success        bool          `json:"success"`
}
