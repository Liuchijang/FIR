package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() {
	collector.Register(&amcacheCollector{})
}

type amcacheCollector struct{}

func (c *amcacheCollector) Name() string        { return "amcache" }
func (c *amcacheCollector) Category() string     { return "execution" }
func (c *amcacheCollector) Description() string {
	return "Collects Amcache.hve from C:\\Windows\\AppCompat\\Programs"
}

func (c *amcacheCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "execution")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create execution output dir: %w", err)
	}

	amcachePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	dst := filepath.Join(outDir, "Amcache.hve")

	// Try direct copy first.
	fi, err := utils.SafeCopyFile(amcachePath, dst)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of Amcache.hve failed: %v, will try alternative methods", err))

		// Try with reg save (Amcache is a registry hive mounted under HKLM).
		os.Remove(dst) // Clean up any partial file.
		fi, err = saveAmcacheViaReg(ctx, dst)
		if err != nil {
			return fmt.Errorf("collect Amcache.hve: %w", err)
		}
	}

	_ = fi
	return nil
}

// saveAmcacheViaReg attempts to save Amcache via reg.exe as a fallback.
func saveAmcacheViaReg(ctx context.Context, outputPath string) (collector.FileInfo, error) {
	// Amcache is not always mounted as a standard reg key.
	// Fall back to copying from the filesystem path.
	amcachePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")

	// Try backup-semantics copy.
	fi, err := utils.SafeCopyFileBackup(amcachePath, outputPath)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("backup copy Amcache.hve: %w", err)
	}
	return fi, nil
}
