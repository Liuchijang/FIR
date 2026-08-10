package resource

import (
	"fmt"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
)

const (
	gb                  = 1024 * 1024 * 1024
	mb                  = 1024 * 1024
	defaultModuleBytes  = 512 * 1024 * 1024
	defaultAnalyzerSize = 32 * mb
	// defaultArchiveRatioPct applies to registry hives, $MFT, browser DBs, and
	// CSV/report output: measured on a real run, a batch like this compressed
	// to ~24% of its raw size (deflate does very well on structured/text data).
	defaultArchiveRatioPct = 35
	safetyMarginPct        = 20
	// minSafetyMargin covers the run's own logs, manifest and summary plus a little
	// slack. It is deliberately small: a 1GB floor made a single 2MB EVTX file
	// report "Required 1.0 GiB", which reads as a broken estimate.
	minSafetyMargin = 128 * mb
)

type StorageEstimate struct {
	OutputBaseDir         string `json:"output_base_dir"`
	FreeBytes             int64  `json:"free_bytes"`
	EstimatedRawBytes     int64  `json:"estimated_raw_bytes"`
	EstimatedArchiveBytes int64  `json:"estimated_archive_bytes,omitempty"`
	RequiredBytes         int64  `json:"required_bytes"`
	Compress              bool   `json:"compress"`
	Healthy               bool   `json:"healthy"`
	Reason                string `json:"reason,omitempty"`
}

func EstimateStorage(outputBaseDir string, modules []module.Module, compress bool) StorageEstimate {
	if outputBaseDir == "" {
		outputBaseDir = "."
	}
	raw, archive := estimateBytes(modules, compress)
	required := raw + archive + safetyMargin(raw+archive)
	free, err := FreeSpaceBytes(outputBaseDir)

	estimate := StorageEstimate{
		OutputBaseDir:         outputBaseDir,
		FreeBytes:             free,
		EstimatedRawBytes:     raw,
		EstimatedArchiveBytes: archive,
		RequiredBytes:         required,
		Compress:              compress,
	}
	if err != nil {
		estimate.Healthy = false
		estimate.Reason = err.Error()
		return estimate
	}
	if free < required {
		estimate.Healthy = false
		estimate.Reason = fmt.Sprintf("not enough free space: need %s, free %s", FormatBytes(required), FormatBytes(free))
		return estimate
	}
	estimate.Healthy = true
	estimate.Reason = "enough free space for selected modules"
	return estimate
}

// estimateBytes sums each module's raw estimate and, if compress is set, its
// weighted archive contribution. A single flat compression ratio for the whole
// batch is wrong whenever "ram" is mixed with everything else: memory dumps
// barely compress while registry/MFT/CSV output compresses very well, so each
// module's raw bytes are compressed at its own ratio before being summed.
func estimateBytes(modules []module.Module, compress bool) (raw, archive int64) {
	// Sizes are memoised for the duration of one estimate: an analyzer sizes
	// itself from the artifact its collector produces, and measuring $MFT or
	// the USN journal means opening a raw volume handle per drive. Without this
	// the mft/mft_parser pair would pay for that twice.
	sizes := make(map[string]int64, len(modules)*2)
	for _, mod := range modules {
		b := estimateModuleBytes(mod, sizes)
		raw += b
		if compress {
			archive += b * archiveRatioForModule(mod) / 100
		}
	}
	if raw <= 0 {
		raw = defaultModuleBytes
		if compress {
			archive = defaultModuleBytes * defaultArchiveRatioPct / 100
		}
	}
	return raw, archive
}

// archiveRatioForModule reports how much of a module's raw output ends up in
// the archive, on top of the raw output itself.
//
// The memory image contributes nothing: it is delivered beside the archive
// rather than inside it (see output.MemoryImages), so it is never on disk
// twice. Every other module compresses well enough to be worth zipping.
func archiveRatioForModule(mod module.Module) int64 {
	if strings.ToLower(mod.Name()) == "ram" {
		return 0
	}
	return defaultArchiveRatioPct
}

// analyzerOutputRatios maps an analyzer to the collector whose artifact it reads
// and how large its CSV runs relative to that artifact, as a percentage.
//
// Analyzers used to be estimated at a flat 32MB each regardless of name, which
// is a large and systematic undercount for the four below: they emit a row per
// record of a volume-sized artifact, and a CSV row is routinely bigger than the
// binary record it came from. Every other analyzer really does produce bounded
// output — a few hundred registry values, one row per prefetch file — and keeps
// the flat estimate.
var analyzerOutputRatios = map[string]struct {
	collector string
	ratioPct  int64
}{
	// A 1KB MFT record becomes one ~200 byte row, and unused records are dropped.
	"mft_parser": {"mft", 30},
	// USN records are compact on disk; the CSV spells out reason and source
	// flags by name and adds resolved paths.
	"usnjrnl_parser": {"usnjrnl", 300},
	// EVTX is binary XML with a template table; flattening it to CSV expands it.
	"eventlog_parser": {"eventlog", 400},
	// $SDS security descriptors become SDDL text.
	"secure_sds_parser": {"secure_sds", 200},
	// The browser analyzers turn SQLite and JSON into CSV per profile. Measured on
	// a real 3-profile collection (Chrome, Edge, Firefox; 202 MB collected):
	// history 10.3%, cookies 0.8%, credentials 0.1%, profile 0.1%.
	//
	// The ratios below sit above those with room to spare, because the denominator
	// is the whole collected tree and most of it is artifacts these analyzers never
	// read — Favicons alone was 32 MB of it. A host whose browsing history is large
	// relative to its favicon cache shifts every figure up.
	//
	// Note that estimateAnalyzerBytes floors each of these at defaultAnalyzerSize,
	// so on a collection this size the ratio changes nothing; it starts to matter
	// once a browser tree runs to gigabytes, which is exactly where the previous
	// guesses would have reserved hundreds of megabytes for a 1 MB CSV.
	"browser_history_parser":     {"browser", 20},
	"browser_cookies_parser":     {"browser", 5},
	"browser_credentials_parser": {"browser", 3},
	"browser_profile_parser":     {"browser", 3},
	// One CSV per SRUM provider table. Measured at 48% of SRUDB.dat on a real
	// 92MB database (221k rows); the estimate keeps headroom above that because
	// the ratio rises with how densely the providers are populated, and an
	// under-estimate here is what fills the evidence drive mid-run.
	"srum_parser": {"srum", 100},
}

// estimateModuleBytes estimates the additional disk space a module needs.
//
// sizes memoises results by module name across one estimate, so that measuring
// an artifact is not repeated for a collector and the analyzer that reads it.
func estimateModuleBytes(mod module.Module, sizes map[string]int64) int64 {
	name := strings.ToLower(mod.Name())
	if cached, ok := sizes[name]; ok {
		return cached
	}
	size := measureModuleBytes(mod, name, sizes)
	sizes[name] = size
	return size
}

func measureModuleBytes(mod module.Module, name string, sizes map[string]int64) int64 {
	if module.ModeOf(mod) == module.ModeAnalyzer {
		return estimateAnalyzerBytes(name, sizes)
	}

	// A module that knows what it will write — because the user picked specific EVTX
	// files or browser profiles — outranks the flat per-artifact guess below.
	if est, ok := mod.(module.SizeEstimator); ok {
		if size := est.EstimatedBytes(); size > 0 {
			return size
		}
	}

	switch name {
	case "ram":
		if totalRAM := DetectHostResources().TotalRAMBytes; totalRAM > 0 {
			return totalRAM
		}
		return 8 * gb
	case "eventlog":
		// Only reached when the collector's own estimator found nothing to
		// measure, which means the log directory is unreadable.
		return 2 * gb
	case "mft":
		// Measured live: sums the real $MFT size across every fixed drive, since
		// MFT size scales with how many files a volume holds (a flat guess is
		// either a large overestimate on small/lightly-used drives or an
		// undercount on huge multi-million-file volumes).
		if size := liveMFTSize(); size > 0 {
			return size
		}
		return 2 * gb
	case "usnjrnl":
		// Measured live: the USN journal's actual configured MaximumSize, which
		// is what the collector reads. Windows defaults this to well under
		// 100MB; enterprise configs can raise it, but a flat multi-GB guess
		// wildly overestimates the common case.
		if size := liveUsnJournalSize(); size > 0 {
			return size
		}
		return 256 * mb
	case "browser":
		// Browser artifact sizes (History/Cookies/Favicons across profiles) vary
		// widely with history retention, so this keeps more headroom than the
		// other flat estimates below.
		return 768 * mb
	case "registry":
		// Hive sizes scale with installed software and number of user profiles,
		// but rarely approach the previous 1GB default on typical machines.
		return 512 * mb
	case "secure_sds":
		// $Secure:$SDS holds unique security descriptors; typically a few MB,
		// rarely more than tens of MB even on heavily used systems.
		return 64 * mb
	case "amcache", "prefetch":
		// Amcache.hve and the Prefetch folder (capped by Windows at ~1024 files)
		// are typically well under 100MB combined.
		return 128 * mb
	case "wmi":
		// The WMI repository is typically tens of MB.
		return 128 * mb
	case "srum":
		// SRUDB.dat is size-managed by Windows and rarely exceeds ~100-200MB.
		return 256 * mb
	default:
		return defaultModuleBytes
	}
}

// estimateAnalyzerBytes sizes an analyzer from the artifact it will read. A
// parser whose source collector cannot be measured, or whose output does not
// scale with a volume, falls back to the flat estimate.
func estimateAnalyzerBytes(name string, sizes map[string]int64) int64 {
	source, ok := analyzerOutputRatios[name]
	if !ok {
		return defaultAnalyzerSize
	}
	collector, err := module.Get(source.collector)
	if err != nil {
		return defaultAnalyzerSize
	}
	// The floor matters: a machine with a tiny USN journal should still be
	// credited the space the CSV, headers and report scaffolding take up.
	return max(estimateModuleBytes(collector, sizes)*source.ratioPct/100, defaultAnalyzerSize)
}

func safetyMargin(size int64) int64 {
	margin := size * safetyMarginPct / 100
	if margin < minSafetyMargin {
		return minSafetyMargin
	}
	return margin
}

func FormatBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}
