package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/fir/fir/internal/collector"
)

var Version = "1.0.0"

type Metadata struct {
	Hostname           string             `json:"hostname"`
	Timestamp          string             `json:"timestamp"`
	TimestampUTC       string             `json:"timestamp_utc"`
	OS                 string             `json:"os"`
	Architecture       string             `json:"architecture"`
	ArtifactsCollected []string           `json:"artifacts_collected"`
	CollectorVersion   string             `json:"collector_version"`
	TotalDuration      string             `json:"total_duration"`
	Results            []collector.Result `json:"results"`
	Errors             []string           `json:"errors,omitempty"`
}

func WriteMetadata(outputDir string, results []collector.Result, totalDuration time.Duration) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UNKNOWN"
	}

	now := time.Now()
	var collected []string
	var errors []string

	for _, r := range results {
		if r.Success {
			collected = append(collected, r.CollectorName)
		}
		if r.Error != "" {
			errors = append(errors, fmt.Sprintf("%s: %s", r.CollectorName, r.Error))
		}
	}

	meta := Metadata{Hostname: hostname, Timestamp: now.Format(time.RFC3339), TimestampUTC: now.UTC().Format(time.RFC3339), OS: runtime.GOOS, Architecture: runtime.GOARCH, ArtifactsCollected: collected, CollectorVersion: Version, TotalDuration: fmt.Sprintf("%.3fs", totalDuration.Seconds()), Results: results, Errors: errors}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	metaPath := filepath.Join(outputDir, "metadata.json")
	if err := os.WriteFile(metaPath, data, 0o644); err != nil {
		return fmt.Errorf("write metadata.json: %w", err)
	}
	return nil
}
