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

func init() { module.RegisterArtifact("ntfs", &secureCollector{}) }

type secureCollector struct{}

func (c *secureCollector) Name() string { return "secure_sds" }
func (c *secureCollector) Description() string {
	return "Collect $Secure:$SDS"
}

func (c *secureCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
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

		fi, err := collectSecureSDSForDrive(log, outDir, drive)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
			log.Debug(fmt.Sprintf("$Secure:$SDS collection skipped for drive %s: %v", drive, err))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("no $Secure:$SDS collected from any drive (ensure running as Administrator): %s", strings.Join(errs, "; ")).Error()}
	}
	if len(errs) > 0 {
		return module.CollectResult{Files: files, OutputPath: outDir, Error: fmt.Sprintf("collected $Secure:$SDS from %d drive(s) with %d failure(s): %s", len(files), len(errs), strings.Join(errs, "; "))}
	}
	return module.CollectResult{Files: files, OutputPath: outDir}
}

func collectSecureSDSForDrive(log *logging.Logger, outDir, drive string) (module.FileInfo, error) {
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

	written, err := acquisition.CopyNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS", outputPath)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("$Secure:$SDS raw NTFS extraction failed: %w", err)
	}

	hash, err := utils.HashFile(outputPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash $Secure:$SDS for drive %s: %v", drive, err))
	}
	log.Debug(fmt.Sprintf("$Secure:$SDS collected for drive %s via raw NTFS record 9: %d bytes, SHA256: %s", drive, written, hash))
	return module.FileInfo{Path: relName, SHA256: hash, Size: written}, nil
}
