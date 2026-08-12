package ntfs

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterArtifact("ntfs", &secureCollector{}) }

type secureCollector struct{}

func (c *secureCollector) Name() string { return "secure_sds" }
func (c *secureCollector) Description() string {
	return "Collect $Secure:$SDS"
}

func (c *secureCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	return collectPerDrive(ctx, req, "$Secure:$SDS", collectSecureSDSForDrive)
}

func collectSecureSDSForDrive(_ context.Context, log *logging.Logger, outDir, drive string) (module.FileInfo, error) {
	relName := "$Secure_SDS_" + drive
	outputPath := filepath.Join(outDir, relName)

	vol, err := acquisition.OpenRawVolume(drive)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("open raw volume: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("get NTFS volume data: %w", err)
	}

	written, hash, err := acquisition.CopyNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS", outputPath)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("$Secure:$SDS raw NTFS extraction failed: %w", err)
	}

	log.Debug(fmt.Sprintf("$Secure:$SDS collected for drive %s via raw NTFS record 9: %d bytes, SHA256: %s", drive, written, hash))
	return module.FileInfo{Path: relName, SHA256: hash, Size: written}, nil
}
