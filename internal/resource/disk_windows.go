//go:build windows

package resource

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func FreeSpaceBytes(path string) (int64, error) {
	existing, err := existingPath(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(existing)
	if err != nil {
		return 0, err
	}
	var freeToCaller uint64
	if err := windows.GetDiskFreeSpaceEx(ptr, &freeToCaller, nil, nil); err != nil {
		return 0, err
	}
	return int64(freeToCaller), nil
}

func existingPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", os.ErrNotExist
		}
		abs = parent
	}
}
