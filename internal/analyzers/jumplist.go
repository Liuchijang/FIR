package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	collector "github.com/Liuchijang/Tyto/internal/collectors/jumplist"
	"github.com/Liuchijang/Tyto/internal/jumplist"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/shelllink"
)

// lnkColumns are what the embedded shell link contributes to both CSVs.
//
// A jump list entry says a file was opened; the link inside says where it lived,
// how big it was, which volume it sat on and what the file's own timestamps read
// at the time. Those are different facts from different structures, which is why
// they are one block of columns appended to each row rather than mixed in.
var lnkColumns = []string{
	"TargetCreatedUTC", "TargetModifiedUTC", "TargetAccessedUTC", "TargetSize",
	"TargetIDAbsolutePath", "LocalPath", "CommonPath", "RelativePath", "WorkingDirectory",
	"Arguments", "LinkName", "Title", "FileAttributes", "HeaderFlags",
	"DriveType", "VolumeSerialNumber", "VolumeLabel", "NetworkShare",
	"TargetMFTEntryNumber", "TargetMFTSequenceNumber",
	"MachineID", "MachineMACAddress", "TrackerCreatedUTC", "ExtraBlocksPresent", "LnkNotes",
}

// lnkValues renders one link, or a row of empty cells when there is nothing to
// render.
//
// An empty cell says the link did not carry the field. That is the whole reason
// these are separate columns from the DestList's own: a target path missing here
// with a path present beside it is a link that names its target through the shell
// namespace rather than the file system, and that difference is a finding.
func lnkValues(link *shelllink.File, parseErr error) []string {
	values := make([]string, len(lnkColumns))
	if link == nil {
		if parseErr != nil {
			values[len(values)-1] = parseErr.Error()
		}
		return values
	}

	mft, sequence := "", ""
	if link.HasMFTReference {
		mft = strconv.FormatUint(link.MFTEntryNumber, 10)
		sequence = strconv.FormatUint(uint64(link.MFTSequenceNumber), 10)
	}
	serial := ""
	if link.HasVolumeID {
		serial = fmt.Sprintf("%08X", link.DriveSerial)
	}
	trackerCreated := ""
	if filetime, ok := link.DroidFile.CreatedFiletime(); ok {
		trackerCreated = formatFiletime(filetime, "")
	}

	return []string{
		formatFiletime(link.TargetCreated, ""),
		formatFiletime(link.TargetWritten, ""),
		formatFiletime(link.TargetAccessed, ""),
		strconv.FormatUint(uint64(link.TargetSize), 10),
		link.TargetPath,
		link.LocalPath(),
		link.CommonPathSuffix,
		link.RelativePath,
		link.WorkingDir,
		link.Arguments,
		link.Name,
		link.Title,
		strings.Join(link.AttributeNames(), "|"),
		strings.Join(link.FlagNames(), "|"),
		link.DriveTypeName(),
		serial,
		link.VolumeLabel,
		link.NetworkShare,
		mft,
		sequence,
		link.MachineID,
		link.DroidFile.MacAddress(),
		trackerCreated,
		strings.Join(link.ExtraBlocks, "|"),
		strings.Join(link.Warnings, "; "),
	}
}

// parseEmbeddedLnk reads a link body carved out of a jump list.
//
// A body that will not parse is reported in the row rather than dropped: the
// DestList entry beside it is still evidence that the file was opened, and a row
// that quietly loses its target columns cannot be told from one whose link
// carried none.
func parseEmbeddedLnk(body []byte) ([]string, error) {
	if len(body) == 0 {
		return lnkValues(nil, nil), nil
	}
	link, err := shelllink.Parse(body)
	if err != nil {
		return lnkValues(nil, err), err
	}
	return lnkValues(link, nil), nil
}

func init() { module.RegisterAnalyzer(&jumpListParser{}) }

type jumpListParser struct{ offlineCapable }

func (c *jumpListParser) Name() string     { return "jumplist_parser" }
func (c *jumpListParser) Category() string { return "execution" }
func (c *jumpListParser) Description() string {
	return "Parse jump lists: what each application opened, when, and on which machine"
}

const (
	kindAutomatic = "AutomaticDestinations"
	kindCustom    = "CustomDestinations"
)

// Analyze reads both jump list kinds for every user in the run.
//
// The LNK bodies inside are carried as far as their size and no further: reading
// one needs a shell link parser, and the DestList alone already answers what was
// opened, when, in what order, and on whose machine.
func (c *jumpListParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create jumplist parser output dir: %w", err))
	}

	sourceDir, live, err := resolveArtifactSource(req, collector.CollectorName)
	if err != nil {
		return skippedNoSource(outDir, "collected jump lists")
	}

	sources, err := jumpListSources(sourceDir, live)
	if err != nil {
		return analyzerError(outDir, err)
	}
	if len(sources) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "no jump list files found"}
	}

	var (
		fileRows   [][]string
		autoRows   [][]string
		customRows [][]string
		failures   []string
	)
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return analyzerError(outDir, err)
		}

		switch source.kind {
		case kindAutomatic:
			auto, err := jumplist.OpenAutomatic(source.path)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", filepath.Base(source.path), err))
				fileRows = append(fileRows, unreadableFileRow(source, err))
				continue
			}
			fileRows = append(fileRows, automaticFileRow(source, auto))
			autoRows = append(autoRows, automaticEntryRows(source, auto)...)
		case kindCustom:
			custom, err := jumplist.OpenCustom(source.path)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", filepath.Base(source.path), err))
				fileRows = append(fileRows, unreadableFileRow(source, err))
				continue
			}
			fileRows = append(fileRows, customFileRow(source, custom))
			customRows = append(customRows, customEntryRows(source, custom)...)
		}
	}

	files, err := writeJumpListCSVs(outDir, fileRows, autoRows, customRows)
	if err != nil {
		return analyzerError(outDir, err)
	}

	result := module.AnalyzeResult{Files: files, OutputPath: outDir}
	if len(failures) > 0 {
		result.Error = fmt.Sprintf("%d of %d jump list file(s) could not be read: %s",
			len(failures), len(sources), strings.Join(failures, "; "))
	}
	return result
}

// jumpListSource is one file to read, with the user it belongs to.
type jumpListSource struct {
	user string
	kind string
	path string
}

// jumpListSources lists the files to parse, from the run's collected tree or,
// when no collector ran, from this machine.
//
// The live branch is behind resolveArtifactSource's decision and never a
// fallback from a failed collected read: offline that would file the analyst's
// own jump lists under the subject's hostname.
func jumpListSources(root string, live bool) ([]jumpListSource, error) {
	type userDir struct {
		name string
		root string
	}

	var users []userDir
	if live {
		profiles, err := platform.UserProfiles()
		if err != nil {
			return nil, fmt.Errorf("list user profiles: %w", err)
		}
		for _, profile := range profiles {
			users = append(users, userDir{
				name: profile.Name,
				root: filepath.Join(profile.Path, "AppData", "Roaming", "Microsoft", "Windows", "Recent"),
			})
		}
	} else {
		entries, err := os.ReadDir(filepath.Join(root, "users"))
		if err != nil {
			return nil, fmt.Errorf("read collected jump lists: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				users = append(users, userDir{name: entry.Name(), root: filepath.Join(root, "users", entry.Name())})
			}
		}
	}

	var sources []jumpListSource
	for _, user := range users {
		for _, kind := range []string{kindAutomatic, kindCustom} {
			entries, err := os.ReadDir(filepath.Join(user.root, kind))
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				sources = append(sources, jumpListSource{user: user.name, kind: kind, path: filepath.Join(user.root, kind, entry.Name())})
			}
		}
	}

	sort.Slice(sources, func(i, j int) bool {
		if sources[i].user != sources[j].user {
			return sources[i].user < sources[j].user
		}
		if sources[i].kind != sources[j].kind {
			return sources[i].kind < sources[j].kind
		}
		return sources[i].path < sources[j].path
	})
	return sources, nil
}

var jumpListFilesHeader = []string{
	"User", "SourceFile", "Kind", "AppId", "AppIdDescription", "DestListVersion",
	"EntryCount", "PinnedCount", "LastUsedEntryNumber", "LnkCount", "OrphanStreams", "Notes",
}

var jumpListAutomaticHeader = append([]string{
	"User", "SourceFile", "AppId", "AppIdDescription", "DestListVersion", "MRU", "EntryNumber",
	"Path", "LastModifiedUTC", "DroidCreatedUTC", "Hostname", "MacAddress",
	"InteractionCount", "AccessCount", "PinStatus", "HasPropertyStore",
	"FileDroid", "FileBirthDroid", "VolumeDroid", "VolumeBirthDroid", "LnkBytes", "Notes",
}, lnkColumns...)

var jumpListCustomHeader = append([]string{
	"User", "SourceFile", "AppId", "AppIdDescription", "CategoryIndex", "CategoryName",
	"Rank", "FooterTerminated", "LnkIndex", "LnkBytes",
}, lnkColumns...)

// automaticFileRow accounts for one automaticDestinations-ms file.
//
// Every file gets a row here whether or not it holds entries, because an empty
// jump list is a real answer — 25 of 85 on one host — and a file that is missing
// from the output cannot be told apart from an application that was never used.
func automaticFileRow(source jumpListSource, auto *jumplist.Automatic) []string {
	lnks := 0
	for _, entry := range auto.Entries {
		if entry.Lnk != nil {
			lnks++
		}
	}
	return []string{
		source.user,
		filepath.Base(source.path),
		"automatic",
		auto.AppID,
		jumplist.AppIDDescription(auto.AppID),
		strconv.FormatUint(uint64(auto.Header.Version), 10),
		strconv.Itoa(len(auto.Entries)),
		strconv.FormatUint(uint64(auto.Header.NumberOfPinnedEntries), 10),
		strconv.FormatUint(uint64(auto.Header.LastEntryNumber), 10),
		strconv.Itoa(lnks),
		strconv.Itoa(len(auto.OrphanStreams)),
		strings.Join(auto.Warnings, "; "),
	}
}

func customFileRow(source jumpListSource, custom *jumplist.Custom) []string {
	return []string{
		source.user,
		filepath.Base(source.path),
		"custom",
		custom.AppID,
		jumplist.AppIDDescription(custom.AppID),
		"", "", "", "",
		strconv.Itoa(custom.LnkCount()),
		"",
		strings.Join(custom.Warnings, "; "),
	}
}

func unreadableFileRow(source jumpListSource, err error) []string {
	appID := jumplist.AppIDFromFileName(source.path)
	kind := "automatic"
	if source.kind == kindCustom {
		kind = "custom"
	}
	return []string{
		source.user, filepath.Base(source.path), kind, appID, jumplist.AppIDDescription(appID),
		"", "", "", "", "", "", err.Error(),
	}
}

func automaticEntryRows(source jumpListSource, auto *jumplist.Automatic) [][]string {
	rows := make([][]string, 0, len(auto.Entries))
	for _, entry := range auto.Entries {
		// The droid's timestamp dates the identifier, not the file: it has been
		// observed tracking the machine's boot time. The column is named after what
		// it is so nobody reads it as a creation date.
		droidCreated := ""
		if filetime, ok := entry.FileDroid.CreatedFiletime(); ok {
			droidCreated = formatFiletime(filetime, "")
		}

		notes := ""
		if entry.Lnk == nil {
			notes = "no LNK stream for this entry"
		}

		lnk, _ := parseEmbeddedLnk(entry.Lnk)

		row := []string{
			source.user,
			filepath.Base(source.path),
			auto.AppID,
			jumplist.AppIDDescription(auto.AppID),
			strconv.FormatUint(uint64(auto.Header.Version), 10),
			strconv.Itoa(entry.MRUPosition),
			entry.StreamName(),
			entry.Path,
			formatFiletime(entry.LastModified, ""),
			droidCreated,
			entry.Hostname,
			entry.FileDroid.MacAddress(),
			strconv.FormatInt(int64(entry.InteractionCount), 10),
			strconv.FormatFloat(float64(entry.AccessCount), 'f', -1, 32),
			strconv.FormatInt(int64(entry.PinStatus), 10),
			strconv.FormatBool(entry.HasSps()),
			entry.FileDroid.String(),
			entry.FileBirthDroid.String(),
			entry.VolumeDroid.String(),
			entry.VolumeBirthDroid.String(),
			strconv.Itoa(len(entry.Lnk)),
			notes,
		}
		rows = append(rows, append(row, lnk...))
	}
	return rows
}

func customEntryRows(source jumpListSource, custom *jumplist.Custom) [][]string {
	var rows [][]string
	for categoryIndex, category := range custom.Categories {
		// An unterminated tail's header fields were not read, so the columns fed
		// from them are left empty rather than filled with a zero that reads like
		// a measurement.
		rank := ""
		if category.HeaderParsed {
			rank = strconv.FormatUint(uint64(category.Rank), 10)
		}
		for lnkIndex, lnk := range category.Lnks {
			values, _ := parseEmbeddedLnk(lnk)
			row := []string{
				source.user,
				filepath.Base(source.path),
				custom.AppID,
				jumplist.AppIDDescription(custom.AppID),
				strconv.Itoa(categoryIndex),
				category.Name,
				rank,
				strconv.FormatBool(category.Terminated),
				strconv.Itoa(lnkIndex),
				strconv.Itoa(len(lnk)),
			}
			rows = append(rows, append(row, values...))
		}
	}
	return rows
}

func writeJumpListCSVs(outDir string, fileRows, autoRows, customRows [][]string) ([]module.FileInfo, error) {
	var files []module.FileInfo

	fi, err := writeCSV(filepath.Join(outDir, "jumplist_files.csv"), jumpListFilesHeader, fileRows)
	if err != nil {
		return files, err
	}
	files = append(files, fi)

	fi, err = writeCSV(filepath.Join(outDir, "jumplist_automatic.csv"), jumpListAutomaticHeader, autoRows)
	if err != nil {
		return files, err
	}
	files = append(files, fi)

	fi, err = writeCSV(filepath.Join(outDir, "jumplist_custom.csv"), jumpListCustomHeader, customRows)
	if err != nil {
		return files, err
	}
	return append(files, fi), nil
}
