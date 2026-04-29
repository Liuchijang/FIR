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

func init() { module.RegisterArtifact("ntfs", &secureCollector{}) }

type secureCollector struct{}

func (c *secureCollector) Name() string { return "secure_sds" }
func (c *secureCollector) Description() string {
	return "Collect $Secure:$SDS"
}

func (c *secureCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir := req.ArtifactDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "ntfs")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create NTFS output dir: %w", err).Error()}
	}

	outputPath := filepath.Join(outDir, "$Secure_SDS")
	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("open raw volume: %w", err).Error()}
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("get NTFS volume data: %w", err).Error()}
	}

	written, err := acquisition.CopyNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS", outputPath)
	if err != nil {
		log.Debug(fmt.Sprintf("Raw $Secure:$SDS extraction failed: %v", err))
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("$Secure:$SDS raw NTFS extraction failed: %w", err).Error()}
	}

	hash, err := utils.HashFile(outputPath)
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("hash $Secure:$SDS: %w", err).Error()}
	}
	log.Debug(fmt.Sprintf("$Secure:$SDS collected via raw NTFS record 9: %d bytes, SHA256: %s", written, hash))
	return module.CollectResult{Files: []module.FileInfo{{Path: "$Secure_SDS", SHA256: hash, Size: written}}, OutputPath: outDir}
}
