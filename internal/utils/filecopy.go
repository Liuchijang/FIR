package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fir/fir/internal/collector"
	"golang.org/x/sys/windows"
)

const copyBufferSize = 64 * 1024

// SafeCopyFile copies src to dst while simultaneously computing the SHA-256 hash.
func SafeCopyFile(src, dst string) (collector.FileInfo, error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("open source %s: %w", src, err)
	}
	defer srcFile.Close()

	if _, err := srcFile.Stat(); err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat source %s: %w", src, err)
	}

	return copyToDestination(srcFile, dst)
}

// SafeCopyFileBackup copies a file using backup semantics so SeBackupPrivilege can help with locked files.
func SafeCopyFileBackup(src, dst string) (collector.FileInfo, error) {
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("utf16 source %s: %w", src, err)
	}

	handle, err := windows.CreateFile(
		srcPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("open source %s with backup semantics: %w", src, err)
	}
	defer windows.CloseHandle(handle)

	srcFile := os.NewFile(uintptr(handle), src)
	if srcFile == nil {
		return collector.FileInfo{}, fmt.Errorf("create file wrapper for %s", src)
	}
	defer srcFile.Close()

	if _, err := srcFile.Stat(); err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat source %s: %w", src, err)
	}

	return copyToDestination(srcFile, dst)
}

func copyToDestination(srcFile *os.File, dst string) (collector.FileInfo, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return collector.FileInfo{}, fmt.Errorf("create dest dir: %w", err)
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("create destination %s: %w", dst, err)
	}
	defer func() {
		dstFile.Close()
		if err != nil {
			os.Remove(dst)
		}
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(dstFile, hasher)
	buf := make([]byte, copyBufferSize)
	written, err := io.CopyBuffer(writer, srcFile, buf)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("copy to %s: %w", dst, err)
	}

	if err := dstFile.Sync(); err != nil {
		return collector.FileInfo{}, fmt.Errorf("sync %s: %w", dst, err)
	}

	return collector.FileInfo{Path: filepath.Base(dst), SHA256: hex.EncodeToString(hasher.Sum(nil)), Size: written}, nil
}

func CopyDir(srcDir, dstDir string) ([]collector.FileInfo, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", srcDir, err)
	}

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("create dest dir %s: %w", dstDir, err)
	}

	var files []collector.FileInfo
	var lastErr error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())

		fi, err := SafeCopyFile(src, dst)
		if err != nil {
			lastErr = err
			continue
		}
		files = append(files, fi)
	}

	if len(files) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return files, nil
}

func CopyDirRecursive(srcDir, dstDir string) ([]collector.FileInfo, error) {
	var files []collector.FileInfo

	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(srcDir, path)
		dstPath := filepath.Join(dstDir, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}

		fi, copyErr := SafeCopyFile(path, dstPath)
		if copyErr != nil {
			return nil
		}
		fi.Path = relPath
		files = append(files, fi)
		return nil
	})

	return files, err
}
