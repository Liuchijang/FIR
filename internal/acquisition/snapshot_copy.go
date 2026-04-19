package acquisition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/utils"
)

// CopyFilesFromVolumeSnapshot copies one or more files from a single volume using a VSS snapshot.
func CopyFilesFromVolumeSnapshot(ctx context.Context, volume string, pairs map[string]string) ([]collector.FileInfo, error) {
	sc, cleanup, err := CreateShadowCopy(ctx, volume)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var files []collector.FileInfo
	var errs []string
	srcPaths := make([]string, 0, len(pairs))
	for src := range pairs {
		srcPaths = append(srcPaths, src)
	}
	sort.Strings(srcPaths)

	for _, src := range srcPaths {
		dst := pairs[src]
		snapshotPath := sc.ShadowPath(src)
		fi, copyErr := copySingleSnapshotFile(snapshotPath, dst)
		if copyErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", src, copyErr))
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return files, nil
}

func copySingleSnapshotFile(src, dst string) (collector.FileInfo, error) {
	if _, err := os.Stat(src); err != nil {
		return collector.FileInfo{}, err
	}

	fi, err := utils.SafeCopyFile(src, dst)
	if err == nil {
		return fi, nil
	}
	return utils.SafeCopyFileBackup(src, dst)
}

func VolumeOfPath(path string) string {
	vol := filepath.VolumeName(path)
	if vol == "" {
		return ""
	}
	if !strings.HasSuffix(vol, `\`) {
		vol += `\`
	}
	return vol
}
