package analyzers

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liuchijang/Tyto/internal/module"
)

// offlineCapable marks an analyzer that reads a collected artifact and can
// therefore run against a previously collected run instead of the live host.
//
// Embedded at the type declaration rather than written out as a method per
// analyzer, so the claim is one greppable line where a reader already is. The
// analyzers that do not embed it — wmi_parser and the live_response pair — are
// live queries with no artifact to read, and module.SupportsOffline excludes
// them from an offline run.
type offlineCapable struct{}

func (offlineCapable) SupportsOffline() bool { return true }

func requiredModuleDir(outputDir, name string) (string, error) {
	c, err := module.Get(name)
	if err != nil {
		return "", err
	}
	return module.ModuleDir(outputDir, c), nil
}

func existingModuleDir(outputDir, name string) (string, bool) {
	dir, err := requiredModuleDir(outputDir, name)
	if err != nil {
		return "", false
	}
	if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
		return dir, true
	}
	return "", false
}

// csvStream writes rows to a CSV as they are produced.
//
// It exists so an analyzer never has to hold its whole output in memory before
// any of it reaches disk: mft_parser turns a multi-GB $MFT into a row per
// record, and materialising that as [][]string first cost more than the
// artifact itself. It also hashes while writing, so a finished CSV does not
// have to be read back a second time just to compute its SHA-256.
type csvStream struct {
	path   string
	file   *os.File
	hasher hash.Hash
	writer *csv.Writer
	failed bool
}

func newCSVStream(path string, header []string) (*csvStream, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create csv dir: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create csv file: %w", err)
	}

	hasher := sha256.New()
	// The hash has to see exactly the bytes on disk, BOM included, so both
	// sinks sit behind the same writer.
	sink := io.MultiWriter(file, hasher)

	stream := &csvStream{path: path, file: file, hasher: hasher}
	if _, err := sink.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		stream.Abort()
		return nil, fmt.Errorf("write utf-8 bom: %w", err)
	}

	stream.writer = csv.NewWriter(sink)
	if err := stream.Write(header); err != nil {
		stream.Abort()
		return nil, err
	}
	return stream, nil
}

func (s *csvStream) Write(row []string) error {
	if err := s.writer.Write(sanitizeCSVRow(row)); err != nil {
		return fmt.Errorf("write csv row: %w", err)
	}
	return nil
}

// Close flushes and returns the evidence metadata for the finished CSV.
func (s *csvStream) Close() (module.FileInfo, error) {
	s.writer.Flush()
	if err := s.writer.Error(); err != nil {
		s.Abort()
		return module.FileInfo{}, fmt.Errorf("flush csv: %w", err)
	}
	info, err := s.file.Stat()
	if err != nil {
		s.Abort()
		return module.FileInfo{}, fmt.Errorf("stat csv: %w", err)
	}
	if err := s.file.Close(); err != nil {
		// Close is where a buffered write finally fails, so what is on disk here
		// is a partial CSV — the same thing Abort exists to remove.
		s.Abort()
		return module.FileInfo{}, fmt.Errorf("close csv: %w", err)
	}
	return module.FileInfo{
		Path:   filepath.Base(s.path),
		SHA256: hex.EncodeToString(s.hasher.Sum(nil)),
		Size:   info.Size(),
	}, nil
}

// Abort discards a partial CSV. A truncated file left in the output directory
// would be unhashed and unrecorded in the manifest, which is worse than no file
// at all when the directory is handed over as evidence.
func (s *csvStream) Abort() {
	if s.failed {
		return
	}
	s.failed = true
	s.file.Close()
	os.Remove(s.path)
}

func sanitizeCSVRow(row []string) []string {
	out := make([]string, len(row))
	for i, value := range row {
		out[i] = sanitizeCSVValue(value)
	}
	return out
}

func sanitizeCSVValue(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return strings.TrimSpace(value)
}

// maskFlag pairs a bit with its name. Flag tables are package-level so a
// million-record USN journal does not reallocate them per record.
type maskFlag[T ~uint16 | ~uint32] struct {
	value T
	name  string
}

func maskString[T ~uint16 | ~uint32](mask T, flags []maskFlag[T]) string {
	var names []string
	for _, flag := range flags {
		if mask&flag.value != 0 {
			names = append(names, flag.name)
		}
	}
	return strings.Join(names, "|")
}

// analyzerTimeLayout is the one timestamp layout every analyzer CSV emits.
//
// It used to be per-analyzer: mft_parser and prefetch_parser wrote RFC3339 while
// shimcache, browser history and the registry parsers wrote "2006-01-02
// 15:04:05". Both halves are UTC, but only one said so, and the two halves of an
// output directory could not be joined on time without reformatting one of them
// first. RFC3339 won because it carries the zone explicitly and because
// manifest.json and summary.txt already record the run's own timestamps that way.
//
// The Nano variant, not plain RFC3339, because a FILETIME carries 100ns and
// truncating to the second throws that away. It matters for ordering: a USN
// journal or an MFT records many events inside one second, and $J entries that
// differ by milliseconds collapsed into identical timestamps. Comparison against
// another SRUM parser on the same database showed the loss concretely —
// ConnectStartTime .789 and StartTime .012 were being written as whole seconds.
//
// This is not a format change for output that has no sub-second component:
// RFC3339Nano omits the fraction entirely when it is zero, so a whole-second
// instant renders byte-for-byte as it did before, and both forms parse as
// RFC3339.
const analyzerTimeLayout = time.RFC3339Nano

// windowsEpoch100ns is 1601-01-01 expressed in FILETIME ticks since the Unix epoch.
const windowsEpoch100ns = 116444736000000000

// A column named after a timestamp holds an RFC3339 instant or nothing at all.
// Nothing else may reach one — not the artifact's raw integer, not "N/A", not a
// value this code failed to recognise.
//
// The reason is that the consumers of these CSVs bind such a column to a real
// date type and reject the *whole file* on the first cell that will not convert.
// Timeline Explorer refused all 20 columns and every row of
// amcache_drive_binaries.csv over one DriverTimeStamp that had been passed
// through as the epoch integer "1468635696". A blank cell costs one value; an
// unconvertible one costs the artifact.
//
// So every helper below takes the caller's marker for "no value" and returns it
// for anything it cannot render as an instant, and the analyzers that hold a
// timestamp in a struct rather than formatting it inline pass "" for their time
// columns even when the rest of the row uses a different placeholder.

// analyzerTimeMinYear/analyzerTimeMaxYear bound what counts as an instant.
//
// Below 1601 is either a FILETIME that was never set or one whose decode
// overflowed — Windows has no artifact that predates its own epoch. Above 9999
// has no RFC3339 representation at all: Go prints a five- or six-digit year
// happily, and that string fails the same date parse the raw integer did.
const (
	analyzerTimeMinYear = 1601
	analyzerTimeMaxYear = 9999
)

// formatTime renders an analyzer timestamp. empty is the marker the calling
// analyzer uses for a missing value — most write "", shimcache writes "N/A"
// across its non-timestamp columns and stays internally consistent by passing it.
func formatTime(value time.Time, empty string) string {
	if value.IsZero() {
		return empty
	}
	utc := value.UTC()
	if year := utc.Year(); year < analyzerTimeMinYear || year > analyzerTimeMaxYear {
		return empty
	}
	return utc.Format(analyzerTimeLayout)
}

// formatFiletime renders a Windows FILETIME. Anything below the epoch is an
// unset field rather than a real timestamp in 1601, so it takes empty. The
// epoch itself is a representable instant and formats normally.
func formatFiletime(value uint64, empty string) string {
	if value < windowsEpoch100ns {
		return empty
	}
	return formatTime(time.Unix(0, int64(value-windowsEpoch100ns)*100), empty)
}

// formatFiletimeParts renders a FILETIME still split across its two halves, as
// the raw registry and ShimCache structures store it.
func formatFiletimeParts(low, high uint32, empty string) string {
	return formatFiletime((uint64(high)<<32)|uint64(low), empty)
}

// formatUnixMicro renders a microsecond timestamp, the unit both SQLite-backed
// browser history schemas use.
func formatUnixMicro(value int64, empty string) string {
	if value <= 0 {
		return empty
	}
	return formatTime(time.UnixMicro(value), empty)
}

// formatEpochSeconds renders a Unix-epoch seconds timestamp. That is the unit a
// PE header's TimeDateStamp uses, which is what Amcache copies verbatim into
// InventoryDriverBinary's DriverTimeStamp as a REG_DWORD.
func formatEpochSeconds(value int64, empty string) string {
	if value <= 0 {
		return empty
	}
	return formatTime(time.Unix(value, 0), empty)
}

func analyzerError(outDir string, err error) module.AnalyzeResult {
	return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
}

// resolveArtifactSource decides where an analyzer reads a collector's artifact
// from. Every analyzer follows this one rule; none of them decides for itself.
//
// Three cases, in the order they are tested:
//
//   - Offline (SourcePolicyCollectedOnly): the analyzed run or nothing. The live
//     host is a different machine — the investigator's — so there is no fallback
//     to have.
//   - The collector is part of this run: its output or nothing. Here the live
//     host *is* the same machine, which is exactly why the silent fallback was
//     dangerous rather than harmless: a collected SYSTEM that failed to load
//     sent shimcache_parser to the live registry and it reported success, so the
//     CSV described the machine's state minutes after acquisition while the
//     manifest said it came from the hashed artifact. Nothing in the output said
//     which.
//   - The collector is not part of this run: the live host, without consulting
//     the run directory at all. Running an analyzer on its own is a live triage
//     request, and that is what it should answer.
//
// A caller that gets errNoCollectedSource reports skippedNoSource: in the
// offline case the operator never collected the artifact, and in the live case
// its collector already failed and reported that failure itself.
func resolveArtifactSource(req module.AnalyzeRequest, collector string) (dir string, live bool, err error) {
	if req.AllowLive() && !req.IsSelected(collector) {
		return "", true, nil
	}
	dir, ok := existingModuleDir(req.SourceRoot(), collector)
	if !ok {
		return "", false, errNoCollectedSource
	}
	return dir, false, nil
}

// errNoCollectedSource is what a source-resolution helper returns when the
// analyzed run holds nothing for it and the policy forbids reading the live
// host. Callers turn it into skippedNoSource with their own artifact label, so
// the distinction between "never collected" and "collected but unparseable"
// survives into the summary.
var errNoCollectedSource = errors.New("artifact not present in the analyzed run")

// skippedNoSource reports that the analyzed run does not hold the artifact.
//
// Skipped rather than an error: under SourcePolicyCollectedOnly a missing
// artifact is a fact about the input — the operator collected prefetch but not
// the registry — not a failure of the parser. Reporting it as an error would
// fill the summary with red rows for artifacts nobody collected, and the
// distinction is what tells an analyst "not gathered" from "gathered but
// unreadable".
func skippedNoSource(outDir, artifact string) module.AnalyzeResult {
	return module.AnalyzeResult{
		OutputPath: outDir,
		Skipped:    true,
		Error:      fmt.Sprintf("%s not present in the analyzed run", artifact),
	}
}

// csvResult writes one CSV into outDir and returns the finished result for it.
// Analyzers whose output is bounded by the artifact they read (a few hundred
// registry values, one row per prefetch file) build their rows up front and
// hand them over here; the ones that scale with a volume's file count stream
// through csvStream directly.
func csvResult(outDir, name string, header []string, rows [][]string) module.AnalyzeResult {
	fi, err := writeCSV(filepath.Join(outDir, name), header, rows)
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: []module.FileInfo{fi}, OutputPath: outDir}
}

// writeCSV writes one CSV and returns its evidence metadata, for analyzers that
// emit several files and assemble the result themselves.
func writeCSV(path string, header []string, rows [][]string) (module.FileInfo, error) {
	stream, err := newCSVStream(path, header)
	if err != nil {
		return module.FileInfo{}, err
	}
	for _, row := range rows {
		if err := stream.Write(row); err != nil {
			stream.Abort()
			return module.FileInfo{}, err
		}
	}
	return stream.Close()
}
