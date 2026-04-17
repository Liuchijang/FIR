// Package output manages the output directory structure and file writing for FIR.
package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manager handles output directory creation and path resolution.
type Manager struct {
	mu      sync.Mutex
	baseDir string // Root output directory (e.g., DESKTOP-ABC123_20260416_143210)
	created map[string]bool
}

// NewManager creates a new output manager.
// baseDir is the parent directory where the timestamped collection folder will be created.
func NewManager(baseDir string) (*Manager, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "UNKNOWN"
	}
	// Sanitize hostname: remove characters invalid for directory names.
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

// BaseDir returns the full path to the collection output directory.
func (m *Manager) BaseDir() string {
	return m.baseDir
}

// CategoryDir returns the path for a specific artifact category subdirectory,
// creating it if it doesn't exist yet.
func (m *Manager) CategoryDir(category string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	dir := filepath.Join(m.baseDir, category)
	if !m.created[category] {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create category dir %s: %w", category, err)
		}
		m.created[category] = true
	}
	return dir, nil
}

// LogsDir returns the path for the logs subdirectory.
func (m *Manager) LogsDir() (string, error) {
	return m.CategoryDir("logs")
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
