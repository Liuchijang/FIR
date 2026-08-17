package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Liuchijang/Tyto/internal/module"
	"golang.org/x/sys/windows"
)

// copyBufferSize is 1 MiB: large enough that per-call overhead disappears
// against the syscall, small enough that N concurrent copies do not commit an
// unreasonable amount of memory to buffers.
const copyBufferSize = 1024 * 1024

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
	// zeroScanner rides along with the hash so a zero-filled artifact is detected on
	// the bytes that reach disk, in the one place every collector's copy passes
	// through. Checking after the fact in each collector is a step a new one can
	// forget, and the whole point is that this cannot be forgotten.
	scanner := &zeroScanner{}
	writer := io.MultiWriter(dstFile, hasher, scanner)
	buf := make([]byte, copyBufferSize)
	written, copyErr := io.CopyBuffer(writer, srcFile, buf)
	if copyErr != nil {
		err = fmt.Errorf("copy to %s: %w", dst, copyErr)
		return module.FileInfo{}, err
	}

	if syncErr := dstFile.Sync(); syncErr != nil {
		err = fmt.Errorf("sync %s: %w", dst, syncErr)
		return module.FileInfo{}, err
	}

	return module.FileInfo{
		Path:       filepath.Base(dst),
		SHA256:     hex.EncodeToString(hasher.Sum(nil)),
		Size:       written,
		ZeroFilled: written > 0 && !scanner.sawData,
	}, nil
}

// zeroScanner reports whether any non-zero byte passed through it.
//
// An io.Writer rather than a second pass over the file: the bytes are already being
// walked for the hash, so this costs one comparison per byte and no extra read. A
// legitimately all-zero forensic artifact does not exist — an empty EVTX still carries
// a header, an unused registry log still carries its signature — so all-zero always
// means the read returned nothing, whatever the reads reported.
type zeroScanner struct{ sawData bool }

func (z *zeroScanner) Write(p []byte) (int, error) {
	if !z.sawData {
		for _, b := range p {
			if b != 0 {
				z.sawData = true
				break
			}
		}
	}
	return len(p), nil
}
