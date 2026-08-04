// Package system implements collectors for Windows system activity artifacts.
package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.RegisterArtifact("system", &wmiCollector{}) }

type wmiCollector struct{}

func (c *wmiCollector) Name() string { return "wmi" }
func (c *wmiCollector) Description() string {
	return "Collect WMI repository"
}

var wmiFiles = []string{"OBJECTS.DATA", "INDEX.BTR"}

func (c *wmiCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir(filepath.Join("system", "wmi"))
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create WMI output dir: %w", err).Error()}
	}

	wmiDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "wbem", "Repository")
	var allFiles []module.FileInfo
	for _, name := range wmiFiles {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}
		src := filepath.Join(wmiDir, name)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			log.Debug(fmt.Sprintf("WMI file not found: %s", name))
			continue
		}
		dst := filepath.Join(outDir, name)
		fi, err := utils.SafeCopyFile(src, dst)
		if err != nil {
			log.Debug(fmt.Sprintf("Failed to copy WMI file %s: %v", name, err))
			continue
		}
		allFiles = append(allFiles, fi)
	}

	matches, err := filepath.Glob(filepath.Join(wmiDir, "MAPPING*.MAP"))
	if err == nil {
		for _, match := range matches {
			select {
			case <-ctx.Done():
				return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
			default:
			}
			name := filepath.Base(match)
			dst := filepath.Join(outDir, name)
			fi, err := utils.SafeCopyFile(match, dst)
			if err != nil {
				log.Debug(fmt.Sprintf("Failed to copy WMI mapping file %s: %v", name, err))
				continue
			}
			allFiles = append(allFiles, fi)
		}
	}

	if len(allFiles) == 0 {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no WMI repository files collected from %s", wmiDir)}
	}
	return module.CollectResult{Files: allFiles, OutputPath: outDir}
}
