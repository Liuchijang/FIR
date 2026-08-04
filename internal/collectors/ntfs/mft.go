// Package ntfs implements collectors for NTFS filesystem artifacts.
package ntfs

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

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
	outDir, err := req.EnsureOutputDir("ntfs")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create NTFS output dir: %w", err).Error()}
	}

	drives, err := acquisition.ListFixedDrives()
	if err != nil {
		log.Debug(fmt.Sprintf("Drive enumeration failed, falling back to C: %v", err))
		drives = []string{"C"}
	}

	var files []module.FileInfo
	var errs []string
	for _, drive := range drives {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: files, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		fi, err := collectMFTForDrive(log, outDir, drive)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
			log.Debug(fmt.Sprintf("MFT collection skipped for drive %s: %v", drive, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("no $MFT collected from any drive (ensure running as Administrator): %s", strings.Join(errs, "; ")).Error()}
	}
	if len(errs) > 0 {
		return module.CollectResult{Files: files, OutputPath: outDir, Error: fmt.Sprintf("collected $MFT from %d drive(s) with %d failure(s): %s", len(files), len(errs), strings.Join(errs, "; "))}
	}
	return module.CollectResult{Files: files, OutputPath: outDir}
}

func collectMFTForDrive(log *logging.Logger, outDir, drive string) (module.FileInfo, error) {
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

	written, err := vol.CopyMFTToFile(volData, mftPath)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("copy MFT: %w", err)
	}

	hash, err := utils.HashFile(mftPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash $MFT for drive %s: %v", drive, err))
	}
	log.Debug(fmt.Sprintf("$MFT collected for drive %s: %d bytes, SHA256: %s", drive, written, hash))
	return module.FileInfo{Path: relName, SHA256: hash, Size: written}, nil
}
