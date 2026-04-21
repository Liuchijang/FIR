package acquisition

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

// CopyFilesDirect copies one or more files directly from the live filesystem.
// It first tries a normal copy and then retries with backup semantics.
func CopyFilesDirect(ctx context.Context, pairs map[string]string) ([]module.FileInfo, error) {
	var files []module.FileInfo
	var errs []string
	srcPaths := make([]string, 0, len(pairs))
	for src := range pairs {
		srcPaths = append(srcPaths, src)
	}
	sort.Strings(srcPaths)

	for _, src := range srcPaths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		dst := pairs[src]
		fi, copyErr := copySingleFile(src, dst)
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

func copySingleFile(src, dst string) (module.FileInfo, error) {
	fi, err := utils.SafeCopyFile(src, dst)
	if err == nil {
		return fi, nil
	}
	return utils.SafeCopyFileBackup(src, dst)
}
