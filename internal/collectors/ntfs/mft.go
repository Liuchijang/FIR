// Package ntfs implements collectors for NTFS filesystem artifacts.
package ntfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.RegisterArtifact("ntfs", &mftCollector{}) }

type mftCollector struct{}

func (c *mftCollector) Name() string { return "mft" }
func (c *mftCollector) Description() string {
	return "Collect $MFT"
}

func (c *mftCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir := req.ArtifactDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "ntfs")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create NTFS output dir: %w", err).Error()}
	}

	mftPath := filepath.Join(outDir, "$MFT")
	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		log.Debug(fmt.Sprintf("Raw volume access failed: %v", err))
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("open raw volume: %w (ensure running as Administrator)", err).Error()}
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("get NTFS volume data: %w", err).Error()}
	}
	log.Debug(fmt.Sprintf("NTFS Volume: MFT at LCN %d, size %d bytes, %d bytes/cluster", volData.MFTStartLCN, volData.MFTValidDataLength, volData.BytesPerCluster))

	written, err := vol.CopyMFTToFile(volData, mftPath)
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("copy MFT: %w", err).Error()}
	}

	hash, err := utils.HashFile(mftPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash $MFT: %v", err))
	}
	log.Debug(fmt.Sprintf("$MFT collected: %d bytes, SHA256: %s", written, hash))
	return module.CollectResult{Files: []module.FileInfo{{Path: "$MFT", SHA256: hash, Size: written}}, OutputPath: outDir}
}
