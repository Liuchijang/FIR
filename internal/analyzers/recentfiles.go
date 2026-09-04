package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	collector "github.com/Liuchijang/Tyto/internal/collectors/recentfiles"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/shelllink"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterAnalyzer(&recentFilesParser{}) }

type recentFilesParser struct{ offlineCapable }

func (c *recentFilesParser) Name() string     { return "recentfiles_parser" }
func (c *recentFilesParser) Category() string { return "execution" }
func (c *recentFilesParser) Description() string {
	return "Parse Recent and Office Recent links: which documents were opened, from where"
}

// Analyze reads every collected shell link.
//
// What the row carries beyond the target path is the point: a link records the
// target's own size and timestamps, the serial and label of the volume it sat
// on, and the machine the link was made on. So a link left behind by a document
// opened from a USB stick or a share still names that volume after the device is
// gone, which is the reason this artifact is collected at all.
func (c *recentFilesParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create recentfiles parser output dir: %w", err))
	}

	sourceDir, live, err := resolveArtifactSource(req, collector.CollectorName)
	if err != nil {
		return skippedNoSource(outDir, "collected Recent links")
	}

	links, err := recentLinkSources(sourceDir, live)
	if err != nil {
		return analyzerError(outDir, err)
	}
	if len(links) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no recent file links found"}
	}

	rows := make([][]string, 0, len(links))
	var failures []string
	for _, link := range links {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		created, modified := link.sourceTimes(req, live)

		body, err := os.ReadFile(link.path)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", link.name, err))
			rows = append(rows, append(link.columns(created, modified), lnkValues(nil, err)...))
			continue
		}

		// A file in the folder that is not a shell link still gets a row naming it.
		// The name of a link is the name of the document it pointed at, so it is
		// evidence even when the body is not readable.
		parsed, parseErr := shelllink.Parse(body)
		if parseErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", link.name, parseErr))
			rows = append(rows, append(link.columns(created, modified), lnkValues(nil, parseErr)...))
			continue
		}
		rows = append(rows, append(link.columns(created, modified), lnkValues(parsed, nil)...))
	}

	result := csvResult(outDir, "recent_files.csv", recentFilesHeader, rows)
	// A write failure has already filled Error in, and it is the more serious of
	// the two; the per-link failures are a warning about content, not the file.
	if result.Error == "" && len(failures) > 0 {
		result.Error = fmt.Sprintf("%d of %d link(s) could not be read: %s",
			len(failures), len(links), strings.Join(failures, "; "))
	}
	return result
}

var recentFilesHeader = append([]string{
	"User", "Source", "SourceFile", "LinkCreatedUTC", "LinkModifiedUTC",
}, lnkColumns...)

// recentLink is one .lnk to read, with where it came from.
type recentLink struct {
	user   string
	source string
	name   string
	path   string
}

// columns renders where the link came from, and when the link itself was written.
//
// LinkCreatedUTC and LinkModifiedUTC are the .lnk file's own timestamps, and for
// the Recent folder they are the artifact's whole point: the file is created the
// first time a document is opened and rewritten every time after, so the pair
// brackets the user's contact with that document. The link body's own
// TargetCreatedUTC and the rest describe the document instead, which is a
// different fact.
//
// They cannot come from the collected copy — nothing in the tree preserves file
// times, so that file is stamped with the moment Tyto copied it. Live, the
// analyzer is holding the subject's own file and reads it directly; from a
// collected run, the collector recorded them and they arrive through
// req.SourceFile. Both routes render the same way, so a row does not say which
// mode produced it.
func (l recentLink) columns(created, modified string) []string {
	return []string{l.user, l.source, l.name, created, modified}
}

// sourceTimes finds the link file's own timestamps by whichever route this run
// has.
func (l recentLink) sourceTimes(req module.AnalyzeRequest, live bool) (created, modified string) {
	if live {
		return utils.SourceTimesOf(l.path)
	}
	if file, ok := req.SourceFile(collector.CollectorName, l.relPath()); ok {
		return file.SourceCreated, file.SourceModified
	}
	return "", ""
}

// relPath is how the collector filed this link, which is the key the run's own
// record is addressed by.
func (l recentLink) relPath() string {
	return filepath.Join("users", l.user, l.source, l.name)
}

// recentLinkSources lists the links to parse, from the run's collected tree or,
// when no collector ran, from this machine.
//
// The live branch is behind resolveArtifactSource's decision and is never a
// fallback from a failed collected read: offline that would file the analyst's
// own recently-opened documents under the subject's hostname.
func recentLinkSources(root string, live bool) ([]recentLink, error) {
	type userDir struct {
		name string
		dirs map[string]string
	}

	var users []userDir
	if live {
		profiles, err := platform.UserProfiles()
		if err != nil {
			return nil, fmt.Errorf("list user profiles: %w", err)
		}
		for _, profile := range profiles {
			dirs := make(map[string]string, len(collector.Sources))
			for _, source := range collector.Sources {
				dirs[source.Name] = filepath.Join(profile.Path, source.RelPath)
			}
			users = append(users, userDir{name: profile.Name, dirs: dirs})
		}
	} else {
		entries, err := os.ReadDir(filepath.Join(root, "users"))
		if err != nil {
			return nil, fmt.Errorf("read collected recent links: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirs := make(map[string]string, len(collector.Sources))
			for _, source := range collector.Sources {
				dirs[source.Name] = filepath.Join(root, "users", entry.Name(), source.Name)
			}
			users = append(users, userDir{name: entry.Name(), dirs: dirs})
		}
	}

	var links []recentLink
	for _, user := range users {
		for _, source := range collector.Sources {
			entries, err := os.ReadDir(user.dirs[source.Name])
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !collector.IsShellLinkName(entry.Name()) {
					continue
				}
				links = append(links, recentLink{
					user:   user.name,
					source: source.Name,
					name:   entry.Name(),
					path:   filepath.Join(user.dirs[source.Name], entry.Name()),
				})
			}
		}
	}

	sort.Slice(links, func(i, j int) bool {
		if links[i].user != links[j].user {
			return links[i].user < links[j].user
		}
		if links[i].source != links[j].source {
			return links[i].source < links[j].source
		}
		return links[i].name < links[j].name
	})
	return links, nil
}
