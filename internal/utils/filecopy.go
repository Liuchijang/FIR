package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	srcPtr, err := windows.UTF16PtrFromString(extendedLengthPath(src))
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

	created, modified := sourceTimes(srcFile)

	return module.FileInfo{
		Path:           filepath.Base(dst),
		SHA256:         hex.EncodeToString(hasher.Sum(nil)),
		Size:           written,
		ZeroFilled:     written > 0 && !scanner.sawData,
		SourceCreated:  created,
		SourceModified: modified,
	}, nil
}

// sourceTimes reads the artifact's own timestamps off the handle the bytes were
// just read from.
//
// It rides along with the copy for the same reason the zero-fill scan does: this
// is the one place every collector's copy passes through, and a step each
// collector has to remember is a step a new one can forget. The handle is used
// rather than the path so the answer describes the file that was actually read,
// including the one opened with backup semantics.
//
// A file whose times cannot be read is not an error. The digest and the bytes are
// what the run is for; an empty timestamp says the field was not available, which
// is what the manifest's omitempty then records.
func sourceTimes(srcFile *os.File) (created, modified string) {
	info, err := srcFile.Stat()
	if err != nil {
		return "", ""
	}
	modified = formatSourceTime(info.ModTime())

	// The creation time is not in the portable interface, and on Windows it is the
	// half that matters most here: a Recent folder's link is created the first time
	// a document is opened.
	if data, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		created = formatSourceTime(time.Unix(0, data.CreationTime.Nanoseconds()))
	}
	return created, modified
}

// SourceTimesOf reads an artifact's own timestamps from a path, for the callers
// that never copied it: an analyzer reading the live host holds the real file, so
// its timestamps are the subject's and not a copy's.
func SourceTimesOf(path string) (created, modified string) {
	file, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer file.Close()
	return sourceTimes(file)
}

// formatSourceTime renders an artifact timestamp the way every analyzer CSV
// renders one, so a value can pass from here into a column without being
// reformatted on the way.
func formatSourceTime(at time.Time) string {
	if at.IsZero() || at.Year() < 1601 || at.Year() > 9999 {
		return ""
	}
	return at.UTC().Format(time.RFC3339Nano)
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

// extendedLengthPath does for windows.CreateFile what the standard library
// already does for us everywhere else.
//
// Go runs every absolute path through fixLongPath before it reaches a syscall,
// so SafeCopyFile opens a 300-character source fine — while SafeCopyFileBackup,
// the fallback it escalates *to*, failed in CreateFile with
// ERROR_PATH_NOT_FOUND and reported it as "open source with backup semantics",
// which reads as a privilege problem on a locked file. Firefox bookmark backups
// and per-profile browser paths under a long username reach that length on an
// ordinary host.
//
// The 248 threshold and the refusal to prefix a relative path are both Go's:
// the extended-length form disables all path normalisation, so what is handed
// over has to be fully qualified and already clean.
func extendedLengthPath(path string) string {
	if len(path) < 248 || strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return path
	}
	if strings.HasPrefix(path, `\\`) {
		// The leading pair is dropped before Clean, not after: Clean collapses a
		// leading double separator to one, so slicing its result loses a
		// character of the server name.
		return `\\?\UNC\` + filepath.Clean(path[2:])
	}
	if !filepath.IsAbs(path) {
		return path
	}
	return `\\?\` + filepath.Clean(path)
}

// CopyDirFiles copies the files of one directory into the run.
//
// It is the shape every per-user collector needs: the artifacts of one folder,
// each with a module-relative Path so an offline run can re-hash it, and the
// partial-failure rule that matters more than the copying — a folder that is not
// there is silent, because an account that never opened anything has none, while
// a file that is there and could not be read is a warning. Those two look
// identical in a file count, and only one of them means evidence was lost.
//
// accept selects which names to take; nil takes them all. The plain copy is
// escalated to backup semantics once, which is free when the plain one works.
func CopyDirFiles(srcDir, dstDir, relPrefix string, accept func(name string) bool) ([]module.FileInfo, []string, error) {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return nil, nil, err
	}

	var files []module.FileInfo
	var warnings []string
	for _, entry := range entries {
		if entry.IsDir() || (accept != nil && !accept(entry.Name())) {
			continue
		}

		relPath := filepath.Join(relPrefix, entry.Name())
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, relPath)

		fi, err := SafeCopyFile(src, dst)
		if err != nil {
			fi, err = SafeCopyFileBackup(src, dst)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", relPath, err))
				continue
			}
		}

		// Path is relative to the module directory: an offline run re-hashes an
		// artifact by joining this onto the run's own directory for the module, and
		// an absolute path from the subject's machine would not resolve there.
		fi.Path = relPath
		files = append(files, fi)
	}
	return files, warnings, nil
}
