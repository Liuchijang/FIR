package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Liuchijang/Tyto/internal/collection"
	"github.com/Liuchijang/Tyto/internal/module"
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
	Long: `Collect forensic artifacts from this machine.

Collector modules only by default; --analyze also runs the analyzers for the
selected categories.

` + moduleCategoryHelp(),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCollect()
	},
}

func init() {
	collectCmd.Flags().StringVarP(&artifactFlag, "artifact", "a", "", "Comma-separated list of artifacts or categories to collect (required)")
	collectCmd.Flags().BoolVar(&analyzeFlag, "analyze", false, "Also run the analyzer modules for the selected artifacts/categories (default: collect only)")
	collectCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", collection.DefaultTimeout, "Optional timeout per module (0 disables timeout)")
	collectCmd.Flags().IntVar(&cpuLimitFlag, "cpu-limit", 0, "CPU limit percentage")
	collectCmd.Flags().StringVar(&diskIOFlag, "disk-io", "", "Cap disk bandwidth for Tyto and its child processes, e.g. 80MB (default: no cap)")
	collectCmd.Flags().BoolVar(&compressFlag, "compress", true, "Compress run directory after collection")
	collectCmd.Flags().BoolVar(&noCompressFlag, "no-compress", false, "Disable run directory compression")
	collectCmd.MarkFlagRequired("artifact")

	rootCmd.AddCommand(collectCmd)
}

func runCollect() error {
	if strings.EqualFold(strings.TrimSpace(artifactFlag), artifactListKeyword) {
		printModuleList(os.Stdout)
		return nil
	}

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
