package resource

import (
	"fmt"
	"os"
	"path/filepath"
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
	// ramArchiveRatioPct applies only to the "ram" module: a physical memory
	// dump is high-entropy, so generic deflate barely shrinks it.
	ramArchiveRatioPct = 80
	safetyMarginPct    = 20
	minSafetyMargin    = 1 * gb
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
	for _, mod := range modules {
		b := estimateModuleBytes(mod)
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

func archiveRatioForModule(mod module.Module) int64 {
	if strings.ToLower(mod.Name()) == "ram" {
		return ramArchiveRatioPct
	}
	return defaultArchiveRatioPct
}

// estimateModuleBytes estimates the additional disk space a module needs.
//
// Analyzer modules only read artifacts collected by an earlier collector run (or,
// as a fallback, a small amount of live data) and write a small CSV/report — they
// do not duplicate the raw artifact, so they get a small flat estimate regardless
// of name. Only collector modules, which write the actual raw acquisition (memory
// dump, registry hives, $MFT, etc.), use the size-by-artifact-type table below.
func estimateModuleBytes(mod module.Module) int64 {
	if module.ModeOf(mod) == module.ModeAnalyzer {
		return defaultAnalyzerSize
	}

	switch strings.ToLower(mod.Name()) {
	case "ram":
		if totalRAM := DetectHostResources().TotalRAMBytes; totalRAM > 0 {
			return totalRAM
		}
		return 8 * gb
	case "eventlog":
		if size := liveEventLogSize(); size > 0 {
			return size
		}
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

func liveEventLogSize() int64 {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return 0
	}
	dir := filepath.Join(root, "System32", "winevt", "Logs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".evtx") {
			continue
		}
		info, err := entry.Info()
		if err == nil {
			total += info.Size()
		}
	}
	return total
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
