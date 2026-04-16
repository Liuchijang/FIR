// Package system implements collectors for Windows system activity artifacts.
package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() { collector.Register(&wmiCollector{}) }

type wmiCollector struct{}

func (c *wmiCollector) Name() string     { return "wmi" }
func (c *wmiCollector) Category() string { return "system" }
func (c *wmiCollector) Description() string {
	return "Collects WMI repository files (OBJECTS.DATA, INDEX.BTR, MAPPING*.MAP)"
}

var wmiFiles = []string{"OBJECTS.DATA", "INDEX.BTR"}

func (c *wmiCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "system", "wmi")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create WMI output dir: %w", err)
	}

	wmiDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "wbem", "Repository")
	var allFiles []collector.FileInfo
	for _, name := range wmiFiles {
		select {
		case <-ctx.Done():
			return allFiles, ctx.Err()
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
				return allFiles, ctx.Err()
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
		return nil, fmt.Errorf("no WMI repository files collected from %s", wmiDir)
	}
	return allFiles, nil
}
