// Package ntfs implements collectors for NTFS filesystem artifacts.
package ntfs

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterArtifact("ntfs", &mftCollector{}) }

type mftCollector struct{}

func (c *mftCollector) Name() string { return "mft" }
func (c *mftCollector) Description() string {
	return "Collect $MFT"
}

func (c *mftCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	return collectPerDrive(ctx, req, "$MFT", collectMFTForDrive)
}

func collectMFTForDrive(_ context.Context, log *logging.Logger, outDir, drive string) (module.FileInfo, error) {
	relName := "$MFT_" + drive
	mftPath := filepath.Join(outDir, relName)

	vol, err := acquisition.OpenRawVolume(drive)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("open raw volume: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("get NTFS volume data: %w", err)
	}
	log.Debug(fmt.Sprintf("NTFS Volume %s: MFT at LCN %d, size %d bytes, %d bytes/cluster", drive, volData.MFTStartLCN, volData.MFTValidDataLength, volData.BytesPerCluster))

	written, hash, err := vol.CopyMFTToFile(volData, mftPath)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("copy MFT: %w", err)
	}

	log.Debug(fmt.Sprintf("$MFT collected for drive %s: %d bytes, SHA256: %s", drive, written, hash))
	return module.FileInfo{Path: relName, SHA256: hash, Size: written}, nil
}
