package collection

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/resource"
	"github.com/Liuchijang/Tyto/internal/utils"
)

// SourceRun is a previously collected run being analyzed.
//
// It exists because collection and analysis happen on different machines in
// practice: acquisition runs on the subject during the incident, and the
// artifacts are analyzed afterwards on the investigator's workstation. Every
// piece of run identity therefore has to come from here rather than from the
// host doing the parsing.
type SourceRun struct {
	// Input is what the operator pointed at, directory or archive.
	Input string
	// Root is the run directory to read artifacts from — the extraction
	// directory when Input was an archive.
	Root string
	// Archive is set when Input was a .zip.
	Archive string

	Hostname    string
	CollectedAt time.Time
	// Timezone is the subject machine's zone, and nil when the analyzed run did
	// not record one — every run collected before manifests carried the field.
	// Nil has to stay distinguishable from UTC all the way to the output manifest:
	// substituting this machine's zone would put the analyst's clock on the
	// subject's evidence, which is the same failure the source policy exists to
	// prevent for artifact data.
	Timezone         *platform.TimezoneInfo
	CollectorVersion string
	OS               string
	Architecture     string
	ManifestFound    bool
	// ManifestError is set when a manifest.json is present but unreadable, which is
	// not the same finding as one that was never written: the run *has* recorded
	// hashes and this analysis could not use them. Both end with ManifestFound
	// false, so without this the log would tell an analyst to look for a missing
	// file while a corrupt one sat in the directory.
	ManifestError string

	// CollectedModules is the set of collectors whose output this run holds. It
	// becomes AnalyzeRequest.SelectedModules, which is what makes the
	// IsSelected-driven analyzers (amcache, browser, the USN/$MFT join) resolve
	// against the collected tree instead of looking for a live source.
	CollectedModules map[string]bool

	manifest      output.Manifest
	extractedInto string
}

// RunDirName is the name for the analysis run directory.
//
// It carries the subject's hostname and collection time, not the analyst
// machine's, so the CSVs describing one machine never end up in a directory
// named after another. The _analysis suffix keeps it distinct from the
// collection it came from when both sit in the same folder.
func (s SourceRun) RunDirName() string {
	base := ""
	if s.Hostname != "" && !s.CollectedAt.IsZero() {
		base = fmt.Sprintf("%s_%s", s.Hostname, s.CollectedAt.Format(output.RunTimestampLayout))
	}
	if base == "" {
		// No manifest to take identity from: the input's own name is the best
		// remaining link back to the collection.
		base = strings.TrimSuffix(filepath.Base(s.Input), filepath.Ext(s.Input))
	}
	if base == "" {
		base = "unknown"
	}
	return base + "_analysis"
}

// Info renders the manifest block describing this source and the verification of
// it.
func (s SourceRun) Info(integrity *output.IntegrityReport) *output.SourceRunInfo {
	return &output.SourceRunInfo{
		Path:             s.Root,
		Archive:          s.Archive,
		Hostname:         s.Hostname,
		CollectedAt:      s.CollectedAt,
		CollectorVersion: s.CollectorVersion,
		ManifestFound:    s.ManifestFound,
		AnalyzedOn:       platform.DetectHost().Hostname,
		Integrity:        integrity,
	}
}

// ResolveSourceRun prepares an input for analysis: an archive is extracted into
// workDir, and the run's manifest is read for its identity and file hashes.
//
// The returned cleanup removes an extraction directory this call created, and is
// never nil. It does nothing when the input was already a directory — deleting
// what the operator pointed at would destroy the evidence.
func ResolveSourceRun(input, workDir string) (SourceRun, func(), error) {
	noCleanup := func() {}

	input = filepath.Clean(input)
	stat, err := os.Stat(input)
	if err != nil {
		return SourceRun{}, noCleanup, fmt.Errorf("read analysis input %s: %w", input, err)
	}

	source := SourceRun{Input: input, Root: input}
	cleanup := noCleanup
	if !stat.IsDir() {
		if !strings.EqualFold(filepath.Ext(input), ".zip") {
			return SourceRun{}, noCleanup, fmt.Errorf("analysis input %s is neither a run directory nor a .zip archive", input)
		}
		root, err := extractSourceArchive(input, workDir)
		if err != nil {
			return SourceRun{}, noCleanup, err
		}
		source.Archive = input
		source.Root = root
		source.extractedInto = root
		cleanup = func() { os.RemoveAll(root) }
	}

	source.load()
	return source, cleanup, nil
}

// extractSourceArchive unpacks an archive into a sibling of the analysis output
// rather than inside it.
//
// Inside would be fatal at the end of the run: the archive step zips the whole
// run directory and RemoveRawOutputDir then deletes it, so the subject's evidence
// would be copied into the analysis archive and the extraction deleted with it.
func extractSourceArchive(archivePath, workDir string) (string, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", fmt.Errorf("create work directory %s: %w", workDir, err)
	}
	// Checked here, not in the run's storage estimate. That estimate runs after
	// this function returns, so by then the extraction has already consumed the
	// space — a gate reporting on bytes it has itself written protects nothing,
	// and adding them to the requirement double-counts against a free figure that
	// already reflects them.
	if required, err := output.ArchiveUncompressedSize(archivePath); err == nil {
		if free, err := resource.FreeSpaceBytes(workDir); err == nil && free < required {
			return "", fmt.Errorf("extracting %s needs %s, only %s free in %s",
				filepath.Base(archivePath), resource.FormatBytes(required), resource.FormatBytes(free), workDir)
		}
	}

	name := strings.TrimSuffix(filepath.Base(archivePath), filepath.Ext(archivePath))
	dest := filepath.Join(workDir, name+"_source")
	// A leftover extraction from an interrupted run would silently mix two
	// collections, so a name that is already taken is disambiguated rather than
	// reused.
	for attempt := 2; dirExists(dest); attempt++ {
		if attempt > 64 {
			return "", fmt.Errorf("cannot find a free extraction directory beside %s", workDir)
		}
		dest = filepath.Join(workDir, fmt.Sprintf("%s_source_%d", name, attempt))
	}

	if _, err := output.ExtractRunArchive(archivePath, dest); err != nil {
		os.RemoveAll(dest)
		return "", fmt.Errorf("extract %s: %w", archivePath, err)
	}
	return findRunRoot(dest), nil
}

// findRunRoot locates the run directory inside an extraction.
//
// Tyto's own archives hold the run's contents at the top level, but an operator
// who re-zipped a run by right-clicking it in Explorer gets one wrapping
// directory instead. Descending through a lone directory covers both without
// asking the operator which shape they have.
func findRunRoot(dest string) string {
	if fileExists(filepath.Join(dest, "manifest.json")) {
		return dest
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return dest
	}
	var dirs []string
	files := 0
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
			continue
		}
		files++
	}
	if len(dirs) == 1 && files == 0 {
		return findRunRoot(filepath.Join(dest, dirs[0]))
	}
	return dest
}

// load fills in the run's identity, preferring its manifest and falling back to
// what is on disk.
func (s *SourceRun) load() {
	manifest, err := output.ReadManifest(s.Root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.ManifestError = err.Error()
	}
	if err == nil {
		s.manifest = manifest
		s.ManifestFound = true
		s.Hostname = manifest.Hostname
		s.CollectedAt = manifest.StartTime
		s.Timezone = manifest.Timezone
		s.CollectorVersion = manifest.CollectorVersion
		s.OS = manifest.OS
		s.Architecture = manifest.Architecture
	}
	s.CollectedModules = s.collectedModules()
}

// collectedModules reports which collectors this run holds output for.
//
// The manifest is authoritative when present — it distinguishes a collector that
// ran and produced nothing from one that was never selected. Without it, the
// directories on disk are the only evidence, which also covers a collection that
// was interrupted before it could write a manifest.
func (s *SourceRun) collectedModules() map[string]bool {
	collected := make(map[string]bool)
	if s.ManifestFound {
		for _, artifact := range s.manifest.Artifacts {
			if len(artifact.Files) > 0 {
				collected[artifact.Name] = true
			}
		}
		if len(collected) > 0 {
			return collected
		}
	}
	for _, mod := range module.All() {
		if module.ModeOf(mod) != module.ModeCollector {
			continue
		}
		if dirExists(module.ModuleDir(s.Root, mod)) {
			collected[mod.Name()] = true
		}
	}
	return collected
}

// VerifyIntegrity re-hashes the collected artifacts the given analyzers will read
// and compares them against what the collecting run recorded.
//
// Only the artifacts behind the selected analyzers are hashed. Verifying a whole
// tree would mean reading gigabytes of memory image and browser cache that
// nothing in this run is going to parse, and the point of the check is to say
// whether the inputs to these CSVs are the bytes that were collected.
//
// A mismatch does not stop the run. The analyst still needs whatever the file
// holds; what they must not do is trust it silently, so every mismatch is
// reported here, logged, and recorded in the manifest.
// CollectedFiles is what the analyzed run's manifest recorded about each
// artifact, keyed by the collector that produced it.
//
// It is the offline half of AnalyzeRequest.CollectedFiles: a live run gets the
// same record from the collectors that just ran, and an analyzer cannot tell the
// two apart, which is the point.
func (s SourceRun) CollectedFiles() map[string][]module.FileInfo {
	if !s.ManifestFound {
		return nil
	}
	out := make(map[string][]module.FileInfo, len(s.manifest.Artifacts))
	for _, artifact := range s.manifest.Artifacts {
		out[artifact.Name] = artifact.Files
	}
	return out
}

func (s SourceRun) VerifyIntegrity(analyzers []module.Module) *output.IntegrityReport {
	if !s.ManifestFound {
		return nil
	}

	needed := sourceCollectorsFor(analyzers)
	report := &output.IntegrityReport{}
	for _, artifact := range s.manifest.Artifacts {
		if !needed[artifact.Name] {
			continue
		}
		mod, err := module.Get(artifact.Name)
		if err != nil {
			continue
		}
		moduleDir := module.ModuleDir(s.Root, mod)
		for _, file := range artifact.Files {
			if file.SHA256 == "" {
				continue
			}
			// FileInfo.Path is relative to the module directory — a bare name for
			// a flat collector, "users\<user>\NTUSER.DAT" for a nested one. The
			// OutputPath in the manifest is absolute on the subject's machine and
			// is useless here.
			path := filepath.Join(moduleDir, file.Path)
			label := filepath.Join(artifact.Name, file.Path)
			report.FilesChecked++

			digest, err := utils.HashFile(path)
			switch {
			case errors.Is(err, os.ErrNotExist):
				report.Missing = append(report.Missing, label)
			case err != nil:
				report.Unreadable = append(report.Unreadable, fmt.Sprintf("%s: %v", label, err))
			case !strings.EqualFold(digest, file.SHA256):
				report.Mismatched = append(report.Mismatched, label)
			default:
				report.Verified++
			}
		}
	}
	if report.FilesChecked == 0 {
		return nil
	}
	return report
}

// sourceCollectorsFor maps analyzers to the collectors whose artifacts they read.
//
// analyzerOutputRatios in internal/resource already records that relationship for
// the volume-scaled analyzers but not for the rest, and it is sized for an
// estimate rather than for provenance. Category is the reliable link that is
// already maintained: an analyzer shares its category with the collector it
// parses.
func sourceCollectorsFor(analyzers []module.Module) map[string]bool {
	categories := make(map[string]bool, len(analyzers))
	for _, mod := range analyzers {
		categories[mod.Category()] = true
	}

	needed := make(map[string]bool)
	for _, mod := range module.All() {
		if module.ModeOf(mod) != module.ModeCollector {
			continue
		}
		if categories[mod.Category()] {
			needed[mod.Name()] = true
		}
	}
	// srum_parser is the one analyzer that reads outside its own category: it
	// resolves provider names and WLAN profile SSIDs out of the SOFTWARE hive.
	// Adding the hives unconditionally instead would mean hashing half a gigabyte
	// of registry for a prefetch-only analysis.
	for _, mod := range analyzers {
		if mod.Name() == "srum_parser" {
			needed["registry"] = true
		}
	}
	return needed
}

func dirExists(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && stat.IsDir()
}

func fileExists(path string) bool {
	stat, err := os.Stat(path)
	return err == nil && !stat.IsDir()
}
