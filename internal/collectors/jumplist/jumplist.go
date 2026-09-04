// Package jumplist collects Windows jump lists.
package jumplist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
)

// CollectorName is what the registry, the layout switch and the analyzer's
// source lookup all agree to call this.
const CollectorName = "jumplist"

// recentRelPath is where Windows keeps a user's jump lists.
var recentRelPath = filepath.Join("AppData", "Roaming", "Microsoft", "Windows", "Recent")

// destinationDirs are the two jump list kinds, named as they are on disk so the
// collected tree can be read without a translation table.
var destinationDirs = []string{"AutomaticDestinations", "CustomDestinations"}

func init() { module.RegisterArtifact("execution", &jumplistCollector{}) }

type jumplistCollector struct{}

func (c *jumplistCollector) Name() string { return CollectorName }
func (c *jumplistCollector) Description() string {
	return "Collect jump lists: the files each application recorded a user opening"
}

// Collect copies both destination folders for every user profile.
//
// The .temp files beside the finished ones are taken too. Windows writes a
// custom destinations file by way of one, and they linger: on a real host the 27
// leftover .temp files held 155 embedded links against 120 in the 28 finished
// files, so skipping them would leave more behind than it collected.
func (c *jumplistCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir(filepath.Join("execution", CollectorName))
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create jumplist output dir: %w", err).Error()}
	}

	users, err := platform.UserProfiles()
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("list user profiles: %w", err).Error()}
	}

	var files []module.FileInfo
	var warnings []string
	for _, user := range users {
		for _, kind := range destinationDirs {
			if err := ctx.Err(); err != nil {
				return module.CollectResult{Files: files, OutputPath: outDir, Error: err.Error()}
			}

			collected, kindWarnings := collectDir(filepath.Join(user.Path, recentRelPath, kind), outDir, user.Name, kind)
			files = append(files, collected...)
			warnings = append(warnings, kindWarnings...)
			if len(collected) > 0 {
				log.Debug(fmt.Sprintf("Collected %d %s file(s) for %s", len(collected), kind, user.Name))
			}
		}
	}

	if len(files) == 0 {
		if len(warnings) > 0 {
			return module.CollectResult{OutputPath: outDir, Error: strings.Join(warnings, "; ")}
		}
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no jump lists found for %d user profile(s)", len(users))}
	}

	result := module.CollectResult{Files: files, OutputPath: outDir}
	if len(warnings) > 0 {
		result.Error = strings.Join(warnings, "; ")
	}
	return result
}

// collectDir copies one destination folder for one user.
func collectDir(srcDir, outDir, user, kind string) ([]module.FileInfo, []string) {
	files, warnings, err := utils.CopyDirFiles(srcDir, outDir, filepath.Join("users", user, kind), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("%s/%s: %v", user, kind, err)}
	}
	for i, warning := range warnings {
		warnings[i] = user + "/" + warning
	}
	return files, warnings
}

func (c *jumplistCollector) EstimatedBytes() int64 {
	users, err := platform.UserProfiles()
	if err != nil {
		return 0
	}

	var paths []string
	for _, user := range users {
		for _, kind := range destinationDirs {
			paths = append(paths, filepath.Join(user.Path, recentRelPath, kind))
		}
	}
	return utils.PathsSize(paths...)
}
