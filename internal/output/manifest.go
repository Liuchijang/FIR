package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/resource"
)

type Manifest struct {
	Hostname  string    `json:"hostname"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	// Timezone is the zone of the machine the artifacts came from, and it is the
	// only record of it: every timestamp in every CSV is UTC, so nothing else in
	// the run says what the subject's own clock read.
	//
	// A pointer because absent and "UTC" must not look alike. An offline analysis
	// of a run collected before this field existed has no way to know the
	// subject's zone, and a zero TimezoneInfo would assert offset 0 — a wrong
	// answer wearing the shape of a right one.
	Timezone          *platform.TimezoneInfo   `json:"timezone,omitempty"`
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
	UncompressedFiles []string `json:"uncompressed_files,omitempty"`
	// SourceRun is set only by an offline analysis run and describes the
	// collection it parsed. Without it the hostname above would be the only
	// clue about which machine the CSVs describe, and on an analyst workstation
	// that clue points at the wrong machine.
	SourceRun *SourceRunInfo     `json:"source_run,omitempty"`
	Artifacts []ManifestArtifact `json:"artifacts"`
}

// SourceRunInfo records the collection an analysis run read, and what verifying
// it against its own manifest found.
type SourceRunInfo struct {
	Path             string    `json:"path"`
	Archive          string    `json:"archive,omitempty"`
	Hostname         string    `json:"hostname,omitempty"`
	CollectedAt      time.Time `json:"collected_at,omitempty"`
	CollectorVersion string    `json:"collector_version,omitempty"`
	ManifestFound    bool      `json:"manifest_found"`
	// AnalyzedOn names the machine that ran the analysis. The fields above
	// describe the subject machine, so without this there is nothing in the
	// output saying where the parsing happened.
	AnalyzedOn string           `json:"analyzed_on,omitempty"`
	Integrity  *IntegrityReport `json:"integrity,omitempty"`
}

// IntegrityReport is the result of re-hashing collected artifacts against the
// SHA-256 the collecting run recorded for them.
//
// Mismatches and missing files are listed rather than counted alone: evidence
// that changed in transit is a finding in its own right, and an analyst needs to
// know which files it applies to before trusting the CSVs derived from them.
type IntegrityReport struct {
	FilesChecked int      `json:"files_checked"`
	Verified     int      `json:"verified"`
	Mismatched   []string `json:"mismatched,omitempty"`
	Missing      []string `json:"missing,omitempty"`
	Unreadable   []string `json:"unreadable,omitempty"`
}

// OK reports whether every checked file matched.
func (r *IntegrityReport) OK() bool {
	if r == nil {
		return true
	}
	return len(r.Mismatched) == 0 && len(r.Missing) == 0 && len(r.Unreadable) == 0
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
	timezone := platform.DetectTimezone()

	manifest := Manifest{
		Hostname:         host.Hostname,
		StartTime:        startedAt,
		EndTime:          finishedAt,
		Timezone:         &timezone,
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

// ReadManifest loads the manifest a previous run wrote.
//
// It is how an offline analysis learns which machine the artifacts came from,
// which collectors actually ran, and what each collected file hashed to.
func ReadManifest(runDir string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(runDir, "manifest.json"))
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest.json in %s: %w", runDir, err)
	}
	return manifest, nil
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
