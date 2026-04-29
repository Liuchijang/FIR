package resource

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
)

const (
	gb                 = 1024 * 1024 * 1024
	defaultModuleBytes = 512 * 1024 * 1024
	archiveRatioPct    = 65
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
	raw := estimateRawBytes(modules)
	archive := int64(0)
	if compress {
		archive = raw * archiveRatioPct / 100
	}
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

func estimateRawBytes(modules []module.Module) int64 {
	var total int64
	for _, mod := range modules {
		total += estimateModuleBytes(mod)
	}
	if total <= 0 {
		return defaultModuleBytes
	}
	return total
}

func estimateModuleBytes(mod module.Module) int64 {
	name := strings.ToLower(mod.Name())
	switch name {
	case "ram":
		if totalRAM := DetectHostResources().TotalRAMBytes; totalRAM > 0 {
			return totalRAM
		}
		return 8 * gb
	case "eventlog", "eventlog_parser":
		if size := liveEventLogSize(); size > 0 {
			return size
		}
		return 2 * gb
	case "browser", "browser_history_parser":
		return 2 * gb
	case "mft", "mft_parser":
		return 2 * gb
	case "registry", "shimcache_parser", "userassist_parser", "runmru_parser", "recentdocs_parser":
		return 1 * gb
	case "usnjrnl", "usnjrnl_parser":
		return 2 * gb
	case "secure_sds", "secure_sds_parser":
		return 512 * 1024 * 1024
	case "amcache", "amcache_parser", "prefetch", "prefetch_parser", "wmi", "wmi_parser", "srum":
		return 512 * 1024 * 1024
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
