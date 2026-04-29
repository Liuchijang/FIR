package output

import (
	"archive/zip"
	"fmt"
	"io"
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
	if outputAbs == "" || outputAbs == string(filepath.Separator) || outputAbs == archiveAbs {
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

func zipDirectory(sourceDir string, archivePath string) error {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil {
		return fmt.Errorf("create archive dir: %w", err)
	}
	out, err := os.Create(archivePath)
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer out.Close()

	zipWriter := zip.NewWriter(out)
	defer zipWriter.Close()

	sourceDir = filepath.Clean(sourceDir)
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Clean(path) == filepath.Clean(archivePath) {
			return nil
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		rel = strings.TrimPrefix(rel, "/")

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer in.Close()
		_, err = io.Copy(writer, in)
		return err
	})
}
