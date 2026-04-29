// Package artifact contains small shared helpers for artifact module metadata.
package artifact

import "path/filepath"

const (
	ModeCollector = "collector"
	ModeAnalyzer  = "analyzer"
)

func ModeDirName(mode string) string {
	if mode == ModeAnalyzer {
		return "Analyzer"
	}
	return "Collector"
}

// ModuleDir returns the legacy-compatible output directory for a module.
func ModuleDir(outputDir, mode, name, category string) string {
	if mode == ModeAnalyzer {
		return filepath.Join(outputDir, ModeDirName(ModeAnalyzer), name)
	}

	switch name {
	case "browser":
		return filepath.Join(outputDir, "browser")
	case "process_explorer", "autoruns":
		return filepath.Join(outputDir, "live", name)
	case "wmi":
		return filepath.Join(outputDir, "system", "wmi")
	case "prefetch":
		return filepath.Join(outputDir, "execution", "prefetch")
	case "amcache":
		return filepath.Join(outputDir, "execution")
	case "eventlog":
		return filepath.Join(outputDir, "eventlog")
	case "ram":
		return filepath.Join(outputDir, "memory")
	case "registry":
		return filepath.Join(outputDir, "registry")
	case "srum":
		return filepath.Join(outputDir, "system")
	case "mft", "usnjrnl", "secure_sds":
		return filepath.Join(outputDir, "ntfs")
	default:
		return filepath.Join(outputDir, category)
	}
}
