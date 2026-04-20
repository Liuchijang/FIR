package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
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

	log.Debug("Collecting Amcache.hve via direct Windows file access")
	files, err := acquisition.CopyFilesDirect(ctx, pairs)
	if err != nil {
		log.Debug(fmt.Sprintf("Direct copy of Amcache.hve failed: %v", err))
		fi, fallbackErr := collectAmcacheFallback(filepath.Join(outDir, "Amcache.hve"), amcachePath)
		if fallbackErr != nil {
			return nil, fmt.Errorf("collect Amcache.hve via direct copy: %v; fallback failed: %w", err, fallbackErr)
		}
		return []collector.FileInfo{fi}, nil
	}

	return files, nil
}

func collectAmcacheFallback(dst, src string) (collector.FileInfo, error) {
	fi, err := saveMountedAmcacheHive(dst)
	if err == nil {
		return fi, nil
	}

	vol, openErr := acquisition.OpenRawVolume("C")
	if openErr != nil {
		return collector.FileInfo{}, fmt.Errorf("mounted hive fallback failed: %v; open raw volume fallback failed: %w", err, openErr)
	}
	defer vol.Close()

	volData, volErr := vol.GetNTFSVolumeData()
	if volErr != nil {
		return collector.FileInfo{}, fmt.Errorf("mounted hive fallback failed: %v; get NTFS volume data fallback failed: %w", err, volErr)
	}

	if _, copyErr := acquisition.CopyFileFromRawPath(vol, volData, src, dst); copyErr != nil {
		return collector.FileInfo{}, fmt.Errorf("mounted hive fallback failed: %v; raw path fallback failed: %w", err, copyErr)
	}
	return utils.FileInfoFromPath(dst)
}

func saveMountedAmcacheHive(dst string) (collector.FileInfo, error) {
	if err := utils.SaveRegistryHive(winreg.LOCAL_MACHINE, "AMCACHE", dst); err != nil {
		return collector.FileInfo{}, err
	}
	return utils.FileInfoFromPath(dst)
}
