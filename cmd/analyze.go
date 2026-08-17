package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Liuchijang/Tyto/internal/collection"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/resource"
	"github.com/spf13/cobra"
)

// Analyze keeps its own flag variables rather than sharing collect's.
//
// pflag assigns a flag's default to its variable at registration, so two commands
// binding one variable with different defaults leave whichever init() ran last
// deciding both. That is how "tyto analyze" would silently inherit --artifact ""
// and --compress true from collect.
var (
	analyzeInputFlag     string
	analyzeArtifactFlag  string
	analyzeTimeoutFlag   time.Duration
	analyzeCPULimitFlag  int
	analyzeDiskIOFlag    string
	analyzeCompressFlag  bool
	analyzeKeepExtracted bool
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Run analyzer modules, against a collected run (--input) or the live machine",
	// With --input this reads files the operator already holds, which needs no
	// privilege. Without it the analyzers read the live machine and the gate
	// applies again — elevationRequired resolves that per invocation.
	Annotations: map[string]string{elevationOptional: elevationOptionalYes},
	Long: `Run analyzer modules.

With --input, they parse a run collected earlier and never touch this machine.
Without it, they analyze the live machine, which requires Administrator.

Collectors in the selection are ignored: this command acquires nothing.

` + moduleCategoryHelp(),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAnalyze()
	},
}

func init() {
	analyzeCmd.Flags().StringVarP(&analyzeInputFlag, "input", "i", "", "Run directory or .zip to analyze; omit to analyze the live machine")
	analyzeCmd.Flags().StringVarP(&analyzeArtifactFlag, "artifact", "a", "all", "Comma-separated analyzers or categories to run")
	analyzeCmd.Flags().DurationVarP(&analyzeTimeoutFlag, "timeout", "t", collection.DefaultTimeout, "Optional timeout per analyzer (0 disables timeout)")
	analyzeCmd.Flags().IntVar(&analyzeCPULimitFlag, "cpu-limit", 0, "CPU limit percentage")
	analyzeCmd.Flags().StringVar(&analyzeDiskIOFlag, "disk-io", "", "Cap disk bandwidth for Tyto and its child processes, e.g. 80MB (default: no cap)")
	// Compression is off by default here, unlike collection: the output is CSV an
	// analyst opens straight away, and delivery of the evidence already happened.
	analyzeCmd.Flags().BoolVar(&analyzeCompressFlag, "compress", false, "Compress the analysis output directory when finished")
	analyzeCmd.Flags().BoolVar(&analyzeKeepExtracted, "keep-extracted", false, "Keep the directory an input archive was extracted into")

	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze() error {
	diskIOBytes, err := parseByteSize(analyzeDiskIOFlag)
	if err != nil {
		return err
	}

	if strings.EqualFold(strings.TrimSpace(analyzeArtifactFlag), artifactListKeyword) {
		printModuleList(os.Stdout)
		return nil
	}

	offline := analyzeInputFlag != ""
	modules, err := analyzeModules(offline)
	if err != nil {
		return err
	}

	runtimeCfg := analyzeRuntimeConfig(diskIOBytes)
	opts := runtimeCfg.CollectionOptions(false, collection.Callbacks{})

	if offline {
		source, cleanup, err := collection.ResolveSourceRun(analyzeInputFlag, runtimeCfg.OutputBaseDir)
		if err != nil {
			return err
		}
		if analyzeKeepExtracted {
			if source.Archive != "" {
				fmt.Fprintf(os.Stderr, "[i] Extracted archive kept at %s\n", source.Root)
			}
			cleanup = func() {}
		}
		defer cleanup()
		// Setting Source is what puts the run on the collected-only policy; leaving
		// it nil is the live path, where no collector is selected so every analyzer
		// resolves to the live machine.
		opts.Source = &source
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err = collection.Run(ctx, modules, opts)
	return err
}

// analyzeModules resolves --artifact to the analyzers this invocation can run.
//
// Collectors always go: there is nothing to acquire here either way, and that now
// covers autoruns and process_explorer, which acquire live state rather than parse
// an artifact. What differs between the modes is the live-only analyzer wmi_parser.
// Against a collected run it cannot answer at all, so it is dropped with a note;
// analyzing the live machine is exactly what it is for, so there it stays.
func analyzeModules(offline bool) ([]module.Module, error) {
	resolved, err := collection.ResolveModules(analyzeArtifactFlag)
	if err != nil {
		return nil, err
	}

	modules, excluded := analyzersOnly(resolved, offline)
	if len(modules) == 0 {
		if offline {
			return nil, fmt.Errorf("--artifact %s resolved to no analyzer that can run against collected artifacts%s", analyzeArtifactFlag, describeExcluded(excluded))
		}
		return nil, fmt.Errorf("--artifact %s resolved to no analyzer module%s", analyzeArtifactFlag, describeExcluded(excluded))
	}
	if len(excluded) > 0 {
		fmt.Fprintf(os.Stderr, "[i] Not run%s\n", describeExcluded(excluded))
	}
	return modules, nil
}

// analyzeRuntimeConfig builds the run configuration from analyze's own flags.
//
// It goes through runtimeConfig.normalized() like every other caller, which is
// what keeps resource.Config.IsZero() from mistaking "--compress=false with no
// other limits set" for an unconfigured struct and replacing it with the
// compress-on default.
func analyzeRuntimeConfig(diskIOBytes int64) runtimeConfig {
	cfg := runtimeConfig{
		OutputBaseDir: outputDir,
		Verbose:       verbose,
		Timeout:       analyzeTimeoutFlag,
		Resources: resource.Config{
			CPULimitPercent: analyzeCPULimitFlag,
			DiskIOLimitBps:  diskIOBytes,
			Compress:        analyzeCompressFlag,
		},
	}
	return cfg.normalized()
}

// analyzersOnly keeps the analyzer modules and reports what was dropped and why.
//
// Collectors go in both modes, because "all" and every category resolve to both
// modes and this command acquires nothing — the same reason collect.go has
// collectorsOnly. offline additionally drops the analyzers that exist only as a
// live query of the running host: against a collected run they would describe the
// investigator's own machine, so module.SupportsOffline has to say yes.
func analyzersOnly(modules []module.Module, offline bool) (kept []module.Module, excluded map[string]string) {
	excluded = make(map[string]string)
	for _, mod := range modules {
		switch {
		case module.ModeOf(mod) != module.ModeAnalyzer:
			excluded[mod.Name()] = "collector"
		case offline && !module.SupportsOffline(mod):
			excluded[mod.Name()] = "live-only"
		default:
			kept = append(kept, mod)
		}
	}
	return kept, excluded
}

func describeExcluded(excluded map[string]string) string {
	if len(excluded) == 0 {
		return ""
	}
	var liveOnly, collectors []string
	for name, reason := range excluded {
		if reason == "live-only" {
			liveOnly = append(liveOnly, name)
			continue
		}
		collectors = append(collectors, name)
	}
	sort.Strings(liveOnly)
	sort.Strings(collectors)

	var parts []string
	if len(liveOnly) > 0 {
		parts = append(parts, fmt.Sprintf("%s (needs the live host)", strings.Join(liveOnly, ", ")))
	}
	if len(collectors) > 0 {
		parts = append(parts, fmt.Sprintf("%d collector module(s) (nothing to acquire in this mode)", len(collectors)))
	}
	return ": " + strings.Join(parts, "; ")
}
