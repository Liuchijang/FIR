package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/collector"
)

// FileInfoFromPath computes metadata for a generated artifact already written to disk.
func FileInfoFromPath(path string) (collector.FileInfo, error) {
	hash, err := HashFile(path)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("hash %s: %w", path, err)
	}

	stat, err := os.Stat(path)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat %s: %w", path, err)
	}

	return collector.FileInfo{
		Path:   filepath.Base(path),
		SHA256: hash,
		Size:   stat.Size(),
	}, nil
}
