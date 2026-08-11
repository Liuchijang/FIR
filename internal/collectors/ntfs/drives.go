package ntfs

import (
	"context"
	"fmt"
	"strings"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
)

// driveCollector extracts one artifact from one volume.
//
// It may return a FileInfo *and* an error: an artifact that was written but
// could not be read to completion is still evidence, and dropping it would lose
// the part of the journal or stream that was recovered. Returning a zero
// FileInfo alongside the error means nothing usable reached disk.
type driveCollector func(ctx context.Context, log *logging.Logger, outDir, drive string) (module.FileInfo, error)

// collectPerDrive runs collect against every fixed drive and folds the per-drive
// outcomes into one CollectResult.
//
// The $MFT, $UsnJrnl:$J and $Secure:$SDS collectors are the same module three
// times over — enumerate fixed drives, extract one artifact per drive, keep
// going when a volume fails, and fail the module only when every volume did.
// Keeping one copy of that shape is what makes the partial-failure contract in
// internal/collection (files + error == success with a warning) hold the same
// way for all three.
func collectPerDrive(ctx context.Context, req module.CollectRequest, artifact string, collect driveCollector) module.CollectResult {
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

		fi, err := collect(ctx, log, outDir, drive)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
			log.Debug(fmt.Sprintf("%s collection incomplete for drive %s: %v", artifact, drive, err))
			if fi.Path == "" {
				continue
			}
		}
		files = append(files, fi)
	}

	if len(files) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no %s collected from any drive (ensure running as Administrator): %s", artifact, strings.Join(errs, "; "))}
	}
	if len(errs) > 0 {
		return module.CollectResult{Files: files, OutputPath: outDir, Error: fmt.Sprintf("collected %s from %d drive(s) with %d failure(s): %s", artifact, len(files), len(errs), strings.Join(errs, "; "))}
	}
	return module.CollectResult{Files: files, OutputPath: outDir}
}
