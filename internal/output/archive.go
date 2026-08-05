package output

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/utils"
)

type ArchiveInfo struct {
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

func CompressRunDirectory(outputDir string) (ArchiveInfo, error) {
	archivePath := outputDir + ".zip"
	if err := zipDirectory(outputDir, archivePath); err != nil {
		return ArchiveInfo{}, err
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("stat archive: %w", err)
	}
	hash, err := utils.HashFile(archivePath)
	if err != nil {
		return ArchiveInfo{}, err
	}
	return ArchiveInfo{
		Path:   archivePath,
		SHA256: hash,
		Size:   info.Size(),
	}, nil
}

func WriteArchiveHashFile(archive ArchiveInfo) error {
	if archive.Path == "" || archive.SHA256 == "" {
		return fmt.Errorf("archive path/hash is empty")
	}
	path := archive.Path + ".sha256"
	content := fmt.Sprintf("%s  %s\n", archive.SHA256, filepath.Base(archive.Path))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write archive hash sidecar: %w", err)
	}
	return nil
}

func RemoveRawOutputDir(outputDir string, archivePath string) error {
	outputAbs, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("resolve output dir: %w", err)
	}
	archiveAbs, err := filepath.Abs(archivePath)
	if err != nil {
		return fmt.Errorf("resolve archive path: %w", err)
	}
	// filepath.Dir of a root ("C:\", "\") is itself, which is the only reliable way
	// to catch a volume root here: comparing against filepath.Separator misses "C:\".
	if outputAbs == "" || filepath.Dir(outputAbs) == outputAbs || outputAbs == archiveAbs {
		return fmt.Errorf("refuse to remove unsafe output path %q", outputDir)
	}
	if _, err := os.Stat(archiveAbs); err != nil {
		return fmt.Errorf("archive missing, raw output preserved: %w", err)
	}
	if !strings.HasSuffix(strings.ToLower(archiveAbs), ".zip") {
		return fmt.Errorf("archive path is not a zip: %s", archivePath)
	}
	return os.RemoveAll(outputAbs)
}

// zipDirectory archives sourceDir into archivePath. Every failure is reported: the
// caller deletes the raw output once this returns nil, so a dropped error here would
// silently trade complete evidence for a truncated archive.
func zipDirectory(sourceDir string, archivePath string) (err error) {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}
	out, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}

	zipWriter := zip.NewWriter(out)
	defer func() {
		// The central directory is written by Close, so its error is the one that
		// decides whether the archive is readable at all.
		if closeErr := zipWriter.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("finalize archive: %w", closeErr)
		}
		if syncErr := out.Sync(); syncErr != nil && err == nil {
			err = fmt.Errorf("sync archive: %w", syncErr)
		}
		if closeErr := out.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close archive: %w", closeErr)
		}
	}()

	sourceDir = filepath.Clean(sourceDir)
	archiveClean := filepath.Clean(archivePath)

	var skipped []error
	walkErr := filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			skipped = append(skipped, fmt.Errorf("walk %s: %w", path, walkErr))
			return nil
		}
		if entry.IsDir() || filepath.Clean(path) == archiveClean {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			skipped = append(skipped, fmt.Errorf("stat %s: %w", path, err))
			return nil
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return fmt.Errorf("relativize %s: %w", path, err)
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("header for %s: %w", path, err)
		}
		header.Name = strings.TrimPrefix(filepath.ToSlash(rel), "/")
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("add %s: %w", rel, err)
		}
		in, err := os.Open(path)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("open %s: %w", path, err))
			return nil
		}
		defer in.Close()
		if _, err := io.Copy(writer, in); err != nil {
			return fmt.Errorf("compress %s: %w", rel, err)
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	return errors.Join(skipped...)
}
