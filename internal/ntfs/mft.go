// Package ntfs implements collectors for NTFS filesystem artifacts.
package ntfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { collector.Register(&mftCollector{}) }

type mftCollector struct{}

func (c *mftCollector) Name() string     { return "mft" }
func (c *mftCollector) Category() string { return "ntfs" }
func (c *mftCollector) Description() string {
	return "Collects the $MFT (Master File Table) via raw disk access"
}

func (c *mftCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "ntfs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create NTFS output dir: %w", err)
	}

	mftPath := filepath.Join(outDir, "$MFT")
	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		log.Debug(fmt.Sprintf("Raw volume access failed: %v", err))
		return nil, fmt.Errorf("open raw volume: %w (ensure running as Administrator)", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return nil, fmt.Errorf("get NTFS volume data: %w", err)
	}
	log.Debug(fmt.Sprintf("NTFS Volume: MFT at LCN %d, size %d bytes, %d bytes/cluster", volData.MFTStartLCN, volData.MFTValidDataLength, volData.BytesPerCluster))

	written, err := vol.CopyMFTToFile(volData, mftPath)
	if err != nil {
		return nil, fmt.Errorf("copy MFT: %w", err)
	}

	hash, err := utils.HashFile(mftPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash $MFT: %v", err))
	}
	log.Debug(fmt.Sprintf("$MFT collected: %d bytes, SHA256: %s", written, hash))
	return []collector.FileInfo{{Path: "$MFT", SHA256: hash, Size: written}}, nil
}
