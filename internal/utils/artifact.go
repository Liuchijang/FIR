package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/module"
)

func FileInfoFromPath(path string) (module.FileInfo, error) {
	hash, err := HashFile(path)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("hash %s: %w", path, err)
	}

	stat, err := os.Stat(path)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("stat %s: %w", path, err)
	}

	return module.FileInfo{
		Path:   filepath.Base(path),
		SHA256: hash,
		Size:   stat.Size(),
	}, nil
}
