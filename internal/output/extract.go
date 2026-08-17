package output

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveUncompressedSize sums what a run archive expands to.
//
// The storage gate needs this before extracting: without it a run passes the
// free-space check on the compressed size and then fills the drive while
// unpacking. It reads the central directory only, so the cost does not scale
// with the archive's contents.
func ArchiveUncompressedSize(archivePath string) (int64, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer reader.Close()

	var total int64
	for _, entry := range reader.File {
		total += int64(entry.UncompressedSize64)
	}
	return total, nil
}

// ExtractRunArchive unpacks a run archive into destDir and returns the bytes
// written.
//
// The layout is the one zipDirectory writes: entry names are paths relative to
// the run directory, so extracting into destDir reproduces the run directory
// itself and every analyzer's module-directory lookup works unchanged.
//
// Entry names are treated as untrusted. This archive arrives from another
// machine — that is the entire point of the offline workflow — so an entry
// naming "..\..\Windows\System32\..." has to be refused rather than written. Any
// entry that would land outside destDir fails the whole extraction: a partial
// evidence tree that quietly dropped files is worse than no extraction at all.
func ExtractRunArchive(archivePath, destDir string) (int64, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("open archive %s: %w", archivePath, err)
	}
	defer reader.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, fmt.Errorf("create extraction dir: %w", err)
	}
	root, err := filepath.Abs(destDir)
	if err != nil {
		return 0, fmt.Errorf("resolve extraction dir: %w", err)
	}

	var written int64
	for _, entry := range reader.File {
		target, err := resolveArchiveEntry(root, entry.Name)
		if err != nil {
			return written, err
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return written, fmt.Errorf("create %s: %w", entry.Name, err)
			}
			continue
		}
		size, err := extractArchiveEntry(entry, target)
		written += size
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// resolveArchiveEntry maps an archive entry name to a path under root, refusing
// anything that escapes it.
func resolveArchiveEntry(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("archive holds an entry with no name")
	}
	// A zip stores forward slashes regardless of the writing platform, and an
	// absolute or rooted name is never legitimate in a run archive.
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry %q is an absolute path", name)
	}

	target := filepath.Join(root, clean)
	// Compare against root plus a separator, so a sibling directory whose name
	// merely starts with root's ("...\run" vs "...\run_source") is not accepted.
	if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	return target, nil
}

func extractArchiveEntry(entry *zip.File, target string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, fmt.Errorf("create dir for %s: %w", entry.Name, err)
	}

	source, err := entry.Open()
	if err != nil {
		return 0, fmt.Errorf("open %s in archive: %w", entry.Name, err)
	}
	defer source.Close()

	file, err := os.Create(target)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", target, err)
	}
	written, err := io.Copy(file, source)
	if closeErr := file.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return written, fmt.Errorf("extract %s: %w", entry.Name, err)
	}
	return written, nil
}
