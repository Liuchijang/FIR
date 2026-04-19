// Package registry implements the Windows registry hive collector.
package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
)

func init() { collector.Register(&registryCollector{}) }

type registryCollector struct{}

func (c *registryCollector) Name() string     { return "registry" }
func (c *registryCollector) Category() string { return "registry" }
func (c *registryCollector) Description() string {
	return "Collects Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat)"
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

	files, err := collectRegistryFromSnapshot(ctx, outDir)
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

func collectRegistryFromSnapshot(ctx context.Context, outDir string) ([]collector.FileInfo, error) {
	configDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "config")
	pairs := make(map[string]string)

	for _, hive := range systemHives {
		for _, suffix := range hiveLogSuffixes {
			name := hive + suffix
			pairs[filepath.Join(configDir, name)] = filepath.Join(outDir, name)
		}
	}

	usersDir := filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf("read Users dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		username := entry.Name()
		if username == "Public" || username == "Default" || username == "Default User" || username == "All Users" {
			continue
		}

		profileDir := filepath.Join(usersDir, username)
		userOutDir := filepath.Join(outDir, "users", username)
		if err := os.MkdirAll(userOutDir, 0o755); err != nil {
			return nil, fmt.Errorf("create dir for %s: %w", username, err)
		}

		ntBase := filepath.Join(profileDir, "NTUSER.DAT")
		for _, suffix := range hiveLogSuffixes {
			src := ntBase + suffix
			if _, err := os.Stat(src); err == nil {
				pairs[src] = filepath.Join(userOutDir, "NTUSER.DAT"+suffix)
			}
		}

		usrBase := filepath.Join(profileDir, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
		for _, suffix := range hiveLogSuffixes {
			src := usrBase + suffix
			if _, err := os.Stat(src); err == nil {
				pairs[src] = filepath.Join(userOutDir, "UsrClass.dat"+suffix)
			}
		}
	}

	files, err := acquisition.CopyFilesFromVolumeSnapshot(ctx, acquisition.VolumeOfPath(configDir), pairs)
	if err != nil {
		return nil, err
	}

	for i := range files {
		name := filepath.Base(files[i].Path)
		switch {
		case strings.HasPrefix(strings.ToUpper(name), "NTUSER.DAT"), strings.HasPrefix(strings.ToUpper(name), "USRCLASS.DAT"):
			// Keep destination basename; parent folder already groups by user.
		default:
			files[i].Path = name
		}
	}
	return files, nil
}
