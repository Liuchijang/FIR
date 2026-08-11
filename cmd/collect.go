package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Liuchijang/FIR/internal/collection"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/spf13/cobra"
)

var (
	artifactFlag    string
	analyzeFlag     bool
	timeoutFlag     time.Duration
	cpuLimitFlag    int
	diskIOFlag      string
	diskIOBytesFlag int64
	compressFlag    bool
	noCompressFlag  bool
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect forensic artifacts (flag-driven mode)",
	Long: `Collect specific forensic artifacts using command-line flags.

Examples:
  fir collect --artifact registry,eventlog,prefetch
  fir collect --artifact ram,mft,registry --output C:\triage --timeout 10m
  fir collect --artifact all --cpu-limit 60 --disk-io 80MB
  fir collect --artifact all --compress
  fir collect --artifact eventlog --analyze

By default, --artifact only runs collector modules (the ones that acquire raw
artifacts) — analyzer modules (*_parser, autoruns, process_explorer, etc.) are
skipped even if a category or "all" would otherwise include them. Pass
--analyze to also run the analyzer for each selected category, once its
collector has finished.

Available artifact names:
  ram, mft, usnjrnl, secure_sds, registry, eventlog,
  prefetch, amcache, wmi, srum, browser,
  process_explorer, autoruns, mft_parser, usnjrnl_parser,
  secure_sds_parser, prefetch_parser, amcache_parser,
  browser_history_parser, browser_cookies_parser,
  browser_credentials_parser, browser_profile_parser, srum_parser,
  shimcache_parser, userassist_parser, recentdocs_parser,
  runmru_parser, eventlog_parser, wmi_parser

Category shortcuts:
  all       - All modules
  browser   - Browser forensic artifacts from popular browsers
  live      - Live process and autoruns triage analysis
  memory    - RAM acquisition
  ntfs      - MFT, USN Journal, Secure SDS
  registry  - Registry hives
  eventlog  - Windows Event Logs
  execution - Prefetch, Amcache
  system    - WMI, SRUM`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCollect()
	},
}

func init() {
	collectCmd.Flags().StringVarP(&artifactFlag, "artifact", "a", "", "Comma-separated list of artifacts or categories to collect (required)")
	collectCmd.Flags().BoolVar(&analyzeFlag, "analyze", false, "Also run the analyzer modules for the selected artifacts/categories (default: collect only)")
	collectCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", collection.DefaultTimeout, "Optional timeout per module (0 disables timeout)")
	collectCmd.Flags().IntVar(&cpuLimitFlag, "cpu-limit", 0, "CPU limit percentage")
	collectCmd.Flags().StringVar(&diskIOFlag, "disk-io", "", "Cap disk bandwidth for FIR and its child processes, e.g. 80MB (default: no cap)")
	collectCmd.Flags().BoolVar(&compressFlag, "compress", true, "Compress run directory after collection")
	collectCmd.Flags().BoolVar(&noCompressFlag, "no-compress", false, "Disable run directory compression")
	collectCmd.MarkFlagRequired("artifact")

	rootCmd.AddCommand(collectCmd)
}

func runCollect() error {
	var err error
	diskIOBytesFlag, err = parseByteSize(diskIOFlag)
	if err != nil {
		return err
	}
	if noCompressFlag {
		compressFlag = false
	}

	modules, err := collection.ResolveModules(artifactFlag)
	if err != nil {
		return err
	}
	if !analyzeFlag {
		modules = collectorsOnly(modules)
		if len(modules) == 0 {
			return fmt.Errorf("--artifact %s resolved only to analyzer modules; pass --analyze to run them", artifactFlag)
		}
	}
	runtimeCfg := runtimeConfigFromFlags()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err = collection.Run(ctx, modules, runtimeCfg.CollectionOptions(false, collection.Callbacks{}))
	return err
}

// collectorsOnly drops analyzer-mode modules, since --artifact/category/"all"
// resolution otherwise mixes both collector and analyzer modules together
// (they share the same Category) and --analyze is what opts into analyzers.
func collectorsOnly(modules []module.Module) []module.Module {
	result := make([]module.Module, 0, len(modules))
	for _, mod := range modules {
		if module.ModeOf(mod) == module.ModeCollector {
			result = append(result, mod)
		}
	}
	return result
}
