// Package system implements collectors for Windows system activity artifacts.
package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterArtifact("system", &wmiCollector{}) }

type wmiCollector struct{}

func (c *wmiCollector) Name() string { return "wmi" }
func (c *wmiCollector) Description() string {
	return "Collect WMI repository"
}

// wmiFiles is the repository's fixed set. OBJECTS.DATA is the object store every
// analyzer reads; INDEX.BTR and the MAPPING files are what a structural reader needs
// to resolve names and logical pages, so they are collected even though the carving
// analyzer does not use them — the analysis can be improved later, the evidence
// cannot be re-acquired later.
var wmiFiles = []string{"OBJECTS.DATA", "INDEX.BTR"}

func (c *wmiCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir(filepath.Join("system", "wmi"))
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create WMI output dir: %w", err).Error()}
	}

	wmiDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "wbem", "Repository")

	names := append([]string{}, wmiFiles...)
	matches, globErr := filepath.Glob(filepath.Join(wmiDir, "MAPPING*.MAP"))
	for _, match := range matches {
		names = append(names, filepath.Base(match))
	}

	rawPool := &acquisition.RawVolumePool{}
	defer rawPool.Close()

	var (
		allFiles []module.FileInfo
		failures []string
	)
	if globErr != nil {
		// The mapping files are named by pattern, so a failed glob is not "there are
		// none" — it is "we never looked", and that has to reach the summary.
		failures = append(failures, fmt.Sprintf("list MAPPING*.MAP: %v", globErr))
	}

	for _, name := range names {
		select {
		case <-ctx.Done():
			return module.CollectResult{Files: allFiles, OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		src := filepath.Join(wmiDir, name)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			// Only "the file is not there" stays silent. Not every build carries
			// three mapping files, and a hive-style transaction log that does not
			// exist is nothing to warn about.
			log.Debug(fmt.Sprintf("WMI file not found: %s", name))
			continue
		}

		fi, err := collectWMIFile(src, filepath.Join(outDir, name), rawPool)
		if err != nil {
			// A file that exists and could not be read is a warning, not a debug
			// line. The WMI service holds this repository open, so this is the
			// expected failure — and a run that reported success with OBJECTS.DATA
			// missing and error=(none) would leave nobody able to tell that the one
			// file the analyzers need never came home.
			log.Warn(fmt.Sprintf("Failed to collect WMI file %s: %v", name, err))
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		fi.Path = name
		allFiles = append(allFiles, fi)
	}

	if len(allFiles) == 0 {
		reason := fmt.Sprintf("no WMI repository files collected from %s", wmiDir)
		if len(failures) > 0 {
			reason += ": " + strings.Join(failures, "; ")
		}
		return module.CollectResult{OutputPath: outDir, Error: reason}
	}
	// Partial success stays success and names what is missing, which is what
	// applyModuleOutcome turns into a summary warning.
	return module.CollectResult{
		Files:      allFiles,
		OutputPath: outDir,
		Error:      strings.Join(failures, "; "),
	}
}

// collectWMIFile copies one repository file, escalating the same three ways the
// registry and Amcache collectors do.
//
// The escalation is not optional here. Winmgmt keeps OBJECTS.DATA and INDEX.BTR open
// for the life of the service, and a plain copy is the attempt most likely to lose
// to that; SeBackupPrivilege lifts an ACL but not a share-mode refusal, which is why
// the raw NTFS read has to be the last resort rather than the missing step.
func collectWMIFile(src, dst string, rawPool *acquisition.RawVolumePool) (module.FileInfo, error) {
	fi, plainErr := utils.SafeCopyFile(src, dst)
	if plainErr == nil {
		return fi, nil
	}

	fi, backupErr := utils.SafeCopyFileBackup(src, dst)
	if backupErr == nil {
		return fi, nil
	}

	if _, rawErr := rawPool.CopyFile(src, dst); rawErr != nil {
		return module.FileInfo{}, fmt.Errorf("copy failed: %v; backup semantics failed: %v; raw read failed: %w",
			plainErr, backupErr, rawErr)
	}
	return utils.FileInfoFromPath(dst)
}

func (c *wmiCollector) EstimatedBytes() int64 {
	return utils.PathsSize(filepath.Join(os.Getenv("SystemRoot"), "System32", "wbem", "Repository"))
}
