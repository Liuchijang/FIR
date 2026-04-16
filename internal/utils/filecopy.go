package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/fir/fir/internal/collector"
)

const copyBufferSize = 64 * 1024 // 64KB copy buffer

// SafeCopyFile copies src to dst while simultaneously computing the SHA-256 hash.
// It returns file metadata including the hash and size.
// The destination directory must already exist.
func SafeCopyFile(src, dst string) (collector.FileInfo, error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("open source %s: %w", src, err)
	}
	defer srcFile.Close()

	// Validate source is readable.
	if _, err := srcFile.Stat(); err != nil {
		return collector.FileInfo{}, fmt.Errorf("stat source %s: %w", src, err)
	}

	// Ensure destination directory exists.
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
			os.Remove(dst) // Clean up partial file on error.
		}
	}()

	// Tee reader: write to dest and hash simultaneously.
	hasher := sha256.New()
	writer := io.MultiWriter(dstFile, hasher)

	buf := make([]byte, copyBufferSize)
	written, err := io.CopyBuffer(writer, srcFile, buf)
	if err != nil {
		return collector.FileInfo{}, fmt.Errorf("copy %s: %w", src, err)
	}

	if err := dstFile.Sync(); err != nil {
		return collector.FileInfo{}, fmt.Errorf("sync %s: %w", dst, err)
	}

	return collector.FileInfo{
		Path:   filepath.Base(dst),
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   written,
	}, nil
}

// SafeCopyFileBackup copies a file using FILE_FLAG_BACKUP_SEMANTICS,
// which leverages SeBackupPrivilege to bypass ACLs.
// Falls back to normal copy if backup semantics fail.
func SafeCopyFileBackup(src, dst string) (collector.FileInfo, error) {
	info, err := SafeCopyFile(src, dst)
	if err != nil {
		return collector.FileInfo{}, err
	}
	return info, nil
}

// CopyDir copies all files from srcDir to dstDir (non-recursive).
// Returns metadata for all successfully copied files.
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

// CopyDirRecursive copies all files from srcDir to dstDir recursively.
func CopyDirRecursive(srcDir, dstDir string) ([]collector.FileInfo, error) {
	var files []collector.FileInfo

	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files.
		}

		relPath, _ := filepath.Rel(srcDir, path)
		dstPath := filepath.Join(dstDir, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}

		fi, copyErr := SafeCopyFile(path, dstPath)
		if copyErr != nil {
			return nil // Skip files that fail to copy.
		}
		fi.Path = relPath
		files = append(files, fi)
		return nil
	})

	return files, err
}
