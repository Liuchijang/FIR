package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/utils"
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
	dst := filepath.Join(outDir, "Amcache.hve")

	fi, err := utils.SafeCopyFile(amcachePath, dst)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of Amcache.hve failed: %v, will try alternative methods", err))
		os.Remove(dst)
		fi, err = saveAmcacheViaReg(ctx, dst)
		if err != nil {
			return nil, fmt.Errorf("collect Amcache.hve: %w", err)
		}
	}

	return []collector.FileInfo{fi}, nil
}

func saveAmcacheViaReg(ctx context.Context, outputPath string) (collector.FileInfo, error) {
	_ = ctx
	amcachePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	fi, err := utils.SafeCopyFileBackup(amcachePath, outputPath)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("backup copy Amcache.hve: %w", err)
	}
	return fi, nil
}
