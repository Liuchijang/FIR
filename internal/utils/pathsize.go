package utils

import (
	"io/fs"
	"os"
	"path/filepath"
)

// PathsSize sums the bytes at each path, walking directories and skipping anything
// unreadable. Collectors use it to report what they will actually write, so the
// storage estimate tracks the machine instead of a flat per-module guess.
func PathsSize(paths ...string) int64 {
	var total int64
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			total += info.Size()
			continue
		}
		filepath.WalkDir(path, func(_ string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if info, err := entry.Info(); err == nil {
				total += info.Size()
			}
			return nil
		})
	}
	return total
}
