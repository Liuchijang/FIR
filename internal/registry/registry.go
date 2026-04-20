// Package registry implements the Windows registry hive collector.
package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
)

func init() { collector.Register(&registryCollector{}) }

type registryCollector struct{}

func (c *registryCollector) Name() string     { return "registry" }
func (c *registryCollector) Category() string { return "registry" }
func (c *registryCollector) Description() string {
	return "Collects Windows registry hives using native Windows file access with backup semantics"
}

var systemHives = []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}
var hiveLogSuffixes = []string{"", ".LOG1", ".LOG2"}

func (c *registryCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "registry")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create registry output dir: %w", err)
	}

	var allFiles []collector.FileInfo
	var errors []string

	files, err := collectRegistryDirect(ctx, outDir)
	if err != nil {
		errors = append(errors, err.Error())
		log.Warn(fmt.Sprintf("Failed to collect registry hives: %v", err))
	} else {
		allFiles = append(allFiles, files...)
	}
	if len(allFiles) == 0 {
		return nil, fmt.Errorf("no registry hives collected: %s", strings.Join(errors, "; "))
	}
	return allFiles, nil
}
