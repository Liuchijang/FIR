// Package output manages the output directory structure and file writing for FIR.
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Liuchijang/FIR/internal/platform"
)

type Manager struct {
	mu      sync.Mutex
	baseDir string // Root output directory (e.g., DESKTOP-ABC123_20260416_143210)
	created map[string]bool
}

func NewManager(baseDir string) (*Manager, error) {
	hostname := platform.DetectHost().Hostname
	hostname = sanitizeDirName(hostname)

	ts := time.Now().Format("20060102_150405")
	dirName := fmt.Sprintf("%s_%s", hostname, ts)
	fullPath := filepath.Join(baseDir, dirName)

	if err := os.MkdirAll(fullPath, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	return &Manager{
		baseDir: fullPath,
		created: make(map[string]bool),
	}, nil
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
