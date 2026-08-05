package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/module"
	"golang.org/x/sys/windows"
)

const copyBufferSize = 64 * 1024

func SafeCopyFile(src, dst string) (module.FileInfo, error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("open source %s: %w", src, err)
	}
	defer srcFile.Close()

	return copyToDestination(srcFile, dst)
}

// SafeCopyFileBackup copies a file using backup semantics so SeBackupPrivilege can help with locked files.
func SafeCopyFileBackup(src, dst string) (module.FileInfo, error) {
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("utf16 source %s: %w", src, err)
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
		return module.FileInfo{}, fmt.Errorf("open source %s with backup semantics: %w", src, err)
	}

	// os.NewFile takes ownership of the handle, so srcFile.Close() is the only close.
	// Closing it here as well would release a handle value Windows may already have
	// handed to another worker.
	srcFile := os.NewFile(uintptr(handle), src)
	if srcFile == nil {
		windows.CloseHandle(handle)
		return module.FileInfo{}, fmt.Errorf("create file wrapper for %s", src)
	}
	defer srcFile.Close()

	return copyToDestination(srcFile, dst)
}

func copyToDestination(srcFile *os.File, dst string) (module.FileInfo, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return module.FileInfo{}, fmt.Errorf("create dest dir: %w", err)
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return module.FileInfo{}, fmt.Errorf("create destination %s: %w", dst, err)
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
	written, copyErr := io.CopyBuffer(writer, diskLimitedReader(srcFile), buf)
	if copyErr != nil {
		err = fmt.Errorf("copy to %s: %w", dst, copyErr)
		return module.FileInfo{}, err
	}

	if syncErr := dstFile.Sync(); syncErr != nil {
		err = fmt.Errorf("sync %s: %w", dst, syncErr)
		return module.FileInfo{}, err
	}

	return module.FileInfo{Path: filepath.Base(dst), SHA256: hex.EncodeToString(hasher.Sum(nil)), Size: written}, nil
}
