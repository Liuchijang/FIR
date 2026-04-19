package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
)

func init() { collector.Register(&amcacheCollector{}) }

type amcacheCollector struct{}

func (c *amcacheCollector) Name() string     { return "amcache" }
func (c *amcacheCollector) Category() string { return "execution" }
func (c *amcacheCollector) Description() string {
	return "Collects Amcache.hve from C:\\Windows\\AppCompat\\Programs"
}

func (c *amcacheCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "execution")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create execution output dir: %w", err)
	}

	amcachePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	pairs := map[string]string{
		amcachePath: filepath.Join(outDir, "Amcache.hve"),
	}

	log.Debug("Collecting Amcache.hve via volume snapshot")
	files, err := acquisition.CopyFilesFromVolumeSnapshot(ctx, acquisition.VolumeOfPath(amcachePath), pairs)
	if err != nil {
		return nil, fmt.Errorf("collect Amcache.hve via snapshot: %w", err)
	}

	return files, nil
}
