// Package registry implements the Windows registry hive collector.
package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.RegisterArtifact("registry", &registryCollector{}) }

type registryCollector struct{}

func (c *registryCollector) Name() string { return "registry" }
func (c *registryCollector) Description() string {
	return "Collect registry hives"
}

var systemHives = []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}
var hiveLogSuffixes = []string{"", ".LOG1", ".LOG2"}

func (c *registryCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir := req.ArtifactDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "registry")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create registry output dir: %w", err).Error()}
	}

	var allFiles []module.FileInfo
	var errors []string

	files, err := collectRegistryDirect(ctx, outDir)
	if err != nil {
		errors = append(errors, err.Error())
		log.Warn(fmt.Sprintf("Failed to collect registry hives: %v", err))
	} else {
		allFiles = append(allFiles, files...)
	}
	if len(allFiles) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no registry hives collected: %s", strings.Join(errors, "; "))}
	}
	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}
