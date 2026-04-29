package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Liuchijang/FIR/internal/collection"
	"github.com/spf13/cobra"
)

var (
	artifactFlag    string
	timeoutFlag     time.Duration
	concurrencyFlag int
	workersFlag     int
	cpuLimitFlag    int
	ramCapFlag      string
	diskIOFlag      string
	ramCapBytesFlag int64
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
  fir collect --artifact all --workers 3 --compress

Available artifact names:
  ram, mft, usnjrnl, secure_sds, registry, eventlog,
  prefetch, amcache, wmi, srum, browser,
  process_explorer, autoruns, mft_parser, usnjrnl_parser,
  secure_sds_parser, prefetch_parser, amcache_parser,
  browser_history_parser,
  shimcache_parser, eventlog_parser, wmi_parser

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
	collectCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", collection.DefaultTimeout, "Optional timeout per module (0 disables timeout)")
	collectCmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 0, "Deprecated alias for --workers")
	collectCmd.Flags().IntVar(&workersFlag, "workers", 0, "Maximum number of concurrent modules")
	collectCmd.Flags().IntVar(&cpuLimitFlag, "cpu-limit", 0, "CPU limit percentage")
	collectCmd.Flags().StringVar(&ramCapFlag, "ram-cap", "", "RAM cap, e.g. 2GB")
	collectCmd.Flags().StringVar(&diskIOFlag, "disk-io", "", "Disk IO limit, e.g. 80MB")
	collectCmd.Flags().BoolVar(&compressFlag, "compress", true, "Compress run directory after collection")
	collectCmd.Flags().BoolVar(&noCompressFlag, "no-compress", false, "Disable run directory compression")
	collectCmd.MarkFlagRequired("artifact")

	rootCmd.AddCommand(collectCmd)
}

func runCollect() error {
	var err error
	ramCapBytesFlag, err = parseByteSize(ramCapFlag)
	if err != nil {
		return err
	}
	diskIOBytesFlag, err = parseByteSize(diskIOFlag)
	if err != nil {
		return err
	}
	if workersFlag <= 0 {
		workersFlag = concurrencyFlag
	}
	if noCompressFlag {
		compressFlag = false
	}

	modules, err := collection.ResolveModules(artifactFlag)
	if err != nil {
		return err
	}
	runtimeCfg := runtimeConfigFromFlags()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err = collection.Run(ctx, modules, runtimeCfg.CollectionOptions(false, collection.Callbacks{}))
	return err
}
