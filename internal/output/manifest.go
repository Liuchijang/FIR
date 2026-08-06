package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/platform"
	"github.com/Liuchijang/FIR/internal/resource"
)

type Manifest struct {
	Hostname          string                   `json:"hostname"`
	StartTime         time.Time                `json:"start_time"`
	EndTime           time.Time                `json:"end_time"`
	OS                string                   `json:"os"`
	Architecture      string                   `json:"architecture"`
	CollectorVersion  string                   `json:"collector_version"`
	OutputDir         string                   `json:"output_dir"`
	SelectedArtifacts []string                 `json:"selected_artifacts"`
	SuccessCount      int                      `json:"success_count"`
	FailureCount      int                      `json:"failure_count"`
	SkippedCount      int                      `json:"skipped_count"`
	Resources         resource.Config          `json:"resources"`
	StorageEstimate   resource.StorageEstimate `json:"storage_estimate"`
	CompressEnabled   bool                     `json:"compress_enabled"`
	Archive           ArchiveInfo              `json:"archive,omitempty"`
	// UncompressedFiles are delivered next to the archive rather than inside
	// it. Anyone verifying the evidence needs to know the zip is not the whole
	// run; the per-file hashes are in Artifacts as usual.
	UncompressedFiles []string           `json:"uncompressed_files,omitempty"`
	Artifacts         []ManifestArtifact `json:"artifacts"`
}

type ManifestArtifact struct {
	Name       string            `json:"name"`
	Category   string            `json:"category"`
	Success    bool              `json:"success"`
	Skipped    bool              `json:"skipped,omitempty"`
	Error      string            `json:"error_message,omitempty"`
	ErrorKind  string            `json:"error_kind,omitempty"`
	OutputPath string            `json:"output_path,omitempty"`
	Duration   float64           `json:"duration_seconds"`
	Files      []module.FileInfo `json:"files"`
}

func NewManifest(outputDir string, startedAt time.Time, finishedAt time.Time, results []module.Result) Manifest {
	host := platform.DetectHost()

	manifest := Manifest{
		Hostname:         host.Hostname,
		StartTime:        startedAt,
		EndTime:          finishedAt,
		OS:               host.OS,
		Architecture:     host.Architecture,
		CollectorVersion: Version,
		OutputDir:        outputDir,
		Artifacts:        make([]ManifestArtifact, 0, len(results)),
	}

	for _, result := range results {
		manifest.SelectedArtifacts = append(manifest.SelectedArtifacts, result.CollectorName)
		switch {
		case result.Skipped:
			manifest.SkippedCount++
		case result.Success:
			manifest.SuccessCount++
		default:
			manifest.FailureCount++
		}
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{
			Name:       result.CollectorName,
			Category:   result.Category,
			Success:    result.Success,
			Skipped:    result.Skipped,
			Error:      result.Error,
			ErrorKind:  result.ErrorKind,
			OutputPath: result.OutputPath,
			Duration:   result.DurationSec,
			Files:      result.FilesCollected,
		})
	}

	return manifest
}

func WriteManifest(outputDir string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		return fmt.Errorf("write manifest.json: %w", err)
	}
	return nil
}
