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

func init() { collector.Register(&secureCollector{}) }

type secureCollector struct{}

func (c *secureCollector) Name() string     { return "secure_sds" }
func (c *secureCollector) Category() string { return "ntfs" }
func (c *secureCollector) Description() string {
	return "Collects the $Secure:$SDS stream via direct NTFS metafile access"
}

func (c *secureCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "ntfs")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create NTFS output dir: %w", err)
	}

	outputPath := filepath.Join(outDir, "$Secure_SDS")
	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		return nil, fmt.Errorf("open raw volume: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return nil, fmt.Errorf("get NTFS volume data: %w", err)
	}

	written, err := acquisition.CopyNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS", outputPath)
	if err != nil {
		log.Debug(fmt.Sprintf("Raw $Secure:$SDS extraction failed: %v", err))
		return nil, fmt.Errorf("$Secure:$SDS raw NTFS extraction failed: %w", err)
	}

	hash, err := utils.HashFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("hash $Secure:$SDS: %w", err)
	}
	log.Debug(fmt.Sprintf("$Secure:$SDS collected via raw NTFS record 9: %d bytes, SHA256: %s", written, hash))
	return []collector.FileInfo{{Path: "$Secure_SDS", SHA256: hash, Size: written}}, nil
}
