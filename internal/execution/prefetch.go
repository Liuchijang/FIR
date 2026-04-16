// Package execution implements collectors for Windows execution artifacts.
package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() {
	collector.Register(&prefetchCollector{})
}

type prefetchCollector struct{}

func (c *prefetchCollector) Name() string        { return "prefetch" }
func (c *prefetchCollector) Category() string     { return "execution" }
func (c *prefetchCollector) Description() string {
	return "Collects Windows Prefetch files (.pf) from C:\\Windows\\Prefetch"
}

func (c *prefetchCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "execution", "prefetch")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create prefetch output dir: %w", err)
	}

	prefetchDir := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return fmt.Errorf("read Prefetch directory: %w", err)
	}

	var allFiles []collector.FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !strings.HasSuffix(strings.ToLower(e.Name()), ".pf") {
			continue
		}

		src := filepath.Join(prefetchDir, e.Name())
		dst := filepath.Join(outDir, e.Name())

		fi, err := utils.SafeCopyFile(src, dst)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to copy prefetch file %s: %v", e.Name(), err))
			continue
		}
		allFiles = append(allFiles, fi)
	}

	if len(allFiles) == 0 {
		return fmt.Errorf("no prefetch files found in %s", prefetchDir)
	}

	return nil
}
