// Package execution implements collectors for Windows execution artifacts.
package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterArtifact("execution", &prefetchCollector{}) }

type prefetchCollector struct{}

func (c *prefetchCollector) Name() string { return "prefetch" }
func (c *prefetchCollector) Description() string {
	return "Collect Prefetch files"
}

func (c *prefetchCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir(filepath.Join("execution", "prefetch"))
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create prefetch output dir: %w", err).Error()}
	}

	prefetchDir := filepath.Join(os.Getenv("SystemRoot"), "Prefetch")
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("read Prefetch directory: %w", err).Error()}
	}

	var allFiles []module.FileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
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
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no prefetch files found in %s", prefetchDir)}
	}
	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}

func (c *prefetchCollector) EstimatedBytes() int64 {
	return utils.PathsSize(filepath.Join(os.Getenv("SystemRoot"), "Prefetch"))
}
