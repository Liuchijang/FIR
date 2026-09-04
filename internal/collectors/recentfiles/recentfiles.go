// Package recentfiles collects the shell links Windows and Office leave behind
// when a user opens a document.
package recentfiles

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
const CollectorName = "recentfiles"

// Source is one folder of shell links, named as the collected tree names it.
type Source struct {
	Name    string
	RelPath string
}

// Sources are the two places a user's recently-opened documents leave a link.
//
// Office keeps its own MRU rather than using the shell's, so a document opened
// from Word appears in one, in the other, or in both depending on how it was
// opened — and only the Office one survives a user clearing the shell's list
// from the taskbar properties. On the host this was built against the shell
// folder held 219 links and Office's held 59.
var Sources = []Source{
	{Name: "Recent", RelPath: filepath.Join("AppData", "Roaming", "Microsoft", "Windows", "Recent")},
	{Name: "OfficeRecent", RelPath: filepath.Join("AppData", "Roaming", "Microsoft", "Office", "Recent")},
}

func init() { module.RegisterArtifact("execution", &recentFilesCollector{}) }

type recentFilesCollector struct{}

func (c *recentFilesCollector) Name() string { return CollectorName }
func (c *recentFilesCollector) Description() string {
	return "Collect Recent and Office Recent shell links: the documents each user opened"
}

// IsShellLinkName reports whether a directory entry is one of the links to take.
//
// The extension is matched case-insensitively because it is not written
// consistently: the shell folder holds ".lnk" and Office's holds ".LNK". The
// folders also hold a desktop.ini and, in Office's case, other MRU files, which
// are not shell links and are left where they are.
func IsShellLinkName(name string) bool {
	return strings.EqualFold(filepath.Ext(name), ".lnk")
}

// Collect copies both link folders for every user profile.
//
// The jump list collector takes the AutomaticDestinations and CustomDestinations
// subfolders of the same Recent directory; this takes the links beside them,
// which is a different artifact with a different meaning — one link per document
// opened, rather than one file per application.
func (c *recentFilesCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir(filepath.Join("execution", CollectorName))
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create recentfiles output dir: %w", err).Error()}
	}

	users, err := platform.UserProfiles()
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("list user profiles: %w", err).Error()}
	}

	var files []module.FileInfo
	var warnings []string
	for _, user := range users {
		for _, source := range Sources {
			if err := ctx.Err(); err != nil {
				return module.CollectResult{Files: files, OutputPath: outDir, Error: err.Error()}
			}

			srcDir := filepath.Join(user.Path, source.RelPath)
			relPrefix := filepath.Join("users", user.Name, source.Name)

			collected, dirWarnings, err := utils.CopyDirFiles(srcDir, outDir, relPrefix, IsShellLinkName)
			if err != nil {
				// A folder that is not there is an account that has opened nothing
				// through that path, which is a fact about the host and not a failure.
				if !errors.Is(err, os.ErrNotExist) {
					warnings = append(warnings, fmt.Sprintf("%s/%s: %v", user.Name, source.Name, err))
				}
				continue
			}
			for _, warning := range dirWarnings {
				warnings = append(warnings, user.Name+"/"+warning)
			}

			files = append(files, collected...)
			if len(collected) > 0 {
				log.Debug(fmt.Sprintf("Collected %d %s link(s) for %s", len(collected), source.Name, user.Name))
			}
		}
	}

	if len(files) == 0 {
		if len(warnings) > 0 {
			return module.CollectResult{OutputPath: outDir, Error: strings.Join(warnings, "; ")}
		}
		return module.CollectResult{OutputPath: outDir, Error: fmt.Sprintf("no recent file links found for %d user profile(s)", len(users))}
	}

	result := module.CollectResult{Files: files, OutputPath: outDir}
	if len(warnings) > 0 {
		result.Error = strings.Join(warnings, "; ")
	}
	return result
}

func (c *recentFilesCollector) EstimatedBytes() int64 {
	users, err := platform.UserProfiles()
	if err != nil {
		return 0
	}

	var total int64
	for _, user := range users {
		for _, source := range Sources {
			dir := filepath.Join(user.Path, source.RelPath)
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !IsShellLinkName(entry.Name()) {
					continue
				}
				if info, err := entry.Info(); err == nil {
					total += info.Size()
				}
			}
		}
	}
	return total
}
