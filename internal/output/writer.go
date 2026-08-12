// Package output manages the output directory structure and file writing for Tyto.
package output

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liuchijang/Tyto/internal/platform"
)

type Manager struct {
	baseDir string // Root output directory (e.g., DESKTOP-ABC123_20260416_143210)
}

func NewManager(baseDir string) (*Manager, error) {
	hostname := platform.DetectHost().Hostname
	hostname = sanitizeDirName(hostname)

	ts := time.Now().Format("20060102_150405")
	dirName := fmt.Sprintf("%s_%s", hostname, ts)

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output base directory: %w", err)
	}
	fullPath, err := createRunDir(baseDir, dirName)
	if err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	return &Manager{baseDir: fullPath}, nil
}

// maxRunDirAttempts bounds the disambiguation below. Reaching it means something
// other than a name collision is wrong.
const maxRunDirAttempts = 64

// createRunDir creates a run directory that did not exist a moment ago.
//
// os.Mkdir rather than os.MkdirAll for the final component, because MkdirAll
// succeeds on a directory that is already there. Adopting an existing directory
// is not harmless here: the run ends by zipping this path and handing it to
// RemoveRawOutputDir, so anything that was in it beforehand — an earlier run's
// evidence, or a second Tyto started in the same second — gets archived under
// this run's name and then recursively deleted. Two runs cannot collide by
// accident at second granularity, but "cannot" is not a guard.
func createRunDir(baseDir, dirName string) (string, error) {
	for attempt := 1; attempt <= maxRunDirAttempts; attempt++ {
		candidate := filepath.Join(baseDir, dirName)
		if attempt > 1 {
			candidate = filepath.Join(baseDir, fmt.Sprintf("%s_%d", dirName, attempt))
		}
		err := os.Mkdir(candidate, 0o755)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("%s already exists in %s after %d attempts", dirName, baseDir, maxRunDirAttempts)
}

func (m *Manager) BaseDir() string {
	return m.baseDir
}

// sanitizeDirName removes characters that are invalid in Windows directory names.
func sanitizeDirName(name string) string {
	invalid := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
	result := name
	for _, ch := range invalid {
		result = strings.ReplaceAll(result, ch, "_")
	}
	return result
}

func SanitizeDirNameForExport(name string) string {
	return sanitizeDirName(name)
}
