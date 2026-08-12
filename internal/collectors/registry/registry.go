// Package registry implements the Windows registry hive collector.
package registry

import (
	"context"
	"fmt"
	"strings"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterArtifact("registry", &registryCollector{}) }

type registryCollector struct{}

func (c *registryCollector) Name() string { return "registry" }
func (c *registryCollector) Description() string {
	return "Collect registry hives"
}

// SECURITY is deliberately excluded: HKLM\SECURITY's ACL denies read access to
// everyone except NT AUTHORITY\SYSTEM, so a process running merely as
// Administrator (even with SeBackupPrivilege) can never read it — every
// attempt fails with Access Denied, adding nothing but noise to the run.
var systemHives = []string{"SYSTEM", "SOFTWARE", "SAM", "DEFAULT"}
var hiveLogSuffixes = []string{"", ".LOG1", ".LOG2"}

func (c *registryCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir("registry")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create registry output dir: %w", err).Error()}
	}

	var allFiles []module.FileInfo
	var errors []string

	files, warnings, err := collectRegistryDirect(ctx, outDir)
	if err != nil {
		errors = append(errors, err.Error())
		log.Warn(fmt.Sprintf("Failed to collect registry hives: %v", err))
	} else {
		allFiles = append(allFiles, files...)
	}
	for _, w := range warnings {
		log.Warn(fmt.Sprintf("Partial registry hive collection failure: %s", w))
	}
	if len(allFiles) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no registry hives collected: %s", strings.Join(errors, "; "))}
	}
	if len(warnings) > 0 {
		return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: fmt.Sprintf("collected %d hive(s) with %d failure(s): %s", len(allFiles), len(warnings), strings.Join(warnings, "; "))}
	}
	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}

func (c *registryCollector) EstimatedBytes() int64 { return estimatedRegistryBytes() }
