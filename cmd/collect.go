package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/spf13/cobra"
)

var (
	artifactFlag    string
	timeoutFlag     time.Duration
	concurrencyFlag int
)

type collectionCallbacks struct {
	OnOutputReady  func(string)
	OnModuleQueued func(int, module.Module)
	OnModuleStart  func(int, module.Module)
	OnModuleFinish func(int, module.Result)
}

type collectionOptions struct {
	SilentConsole bool
	Callbacks     collectionCallbacks
}

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect forensic artifacts (flag-driven mode)",
	Long: `Collect specific forensic artifacts using command-line flags.

Examples:
  fir collect --artifact registry,eventlog,prefetch
  fir collect --artifact ram,mft,registry --output C:\triage --timeout 10m
  fir collect --artifact all --concurrency 3

Available artifact names:
  ram, mft, usnjrnl, secure_sds, registry, eventlog,
  prefetch, amcache, wmi, srum, browser_chromium,
  process_explorer, autoruns

Category shortcuts:
  all       - All modules
  browser   - Chromium browser forensic artifacts
  live      - Live process and autoruns forensic collection
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
	collectCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", 5*time.Minute, "Timeout per module")
	collectCmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 2, "Maximum number of concurrent modules")
	collectCmd.MarkFlagRequired("artifact")

	rootCmd.AddCommand(collectCmd)
}

func runCollect() error {
	// Resolve which modules to run.
	modules, err := resolveModules(artifactFlag)
	if err != nil {
		return err
	}

	return executeCollection(modules)
}

// executeCollection is the core orchestration logic shared by interactive and flag modes.
func executeCollection(modules []module.Module) error {
	_, err := executeCollectionWithOptions(modules, collectionOptions{})
	return err
}

func executeCollectionWithOptions(modules []module.Module, opts collectionOptions) (output.SummaryReport, error) {
	// Create output directory.
	mgr, err := output.NewManager(outputDir)
	if err != nil {
		return output.SummaryReport{}, fmt.Errorf("create output directory: %w", err)
	}
	if opts.Callbacks.OnOutputReady != nil {
		opts.Callbacks.OnOutputReady(mgr.BaseDir())
	}

	// Write collector.log at the session root beside metadata.json.
	if err := logging.Init(mgr.BaseDir(), verbose); err != nil {
		return output.SummaryReport{}, fmt.Errorf("initialize logging: %w", err)
	}
	defer logging.Close()
	if opts.SilentConsole {
		logging.SetConsoleOutput(false)
		defer logging.SetConsoleOutput(true)
	}

	log := logging.G()
	log.Info(fmt.Sprintf("Output directory: %s", mgr.BaseDir()))
	log.Info(fmt.Sprintf("Modules to run: %d", len(modules)))
	for idx, m := range modules {
		if opts.Callbacks.OnModuleQueued != nil {
			opts.Callbacks.OnModuleQueued(idx, m)
		}
	}

	startTime := time.Now()
	results := runModules(modules, mgr, opts.Callbacks)
	totalDuration := time.Since(startTime)
	report := output.NewSummaryReport(mgr.BaseDir(), startTime, totalDuration, timeoutFlag, concurrencyFlag, results)

	// Write metadata.
	if err := output.WriteMetadata(mgr.BaseDir(), results, totalDuration); err != nil {
		log.Error(fmt.Sprintf("Failed to write metadata: %v", err))
	}
	if err := output.WriteSummary(mgr.BaseDir(), report); err != nil {
		log.Error(fmt.Sprintf("Failed to write summary: %v", err))
	}

	if !opts.SilentConsole {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintln(os.Stderr, report.Render())
	}
	log.Info(fmt.Sprintf("Collection completed in %.1fs", totalDuration.Seconds()))
	log.Success(fmt.Sprintf("Results: %d succeeded, %d failed", report.SuccessCount, report.FailureCount))
	log.Info(fmt.Sprintf("Output: %s", mgr.BaseDir()))
	log.Info(fmt.Sprintf("Summary: %s", outputSummaryPath(mgr.BaseDir())))

	return report, nil
}

// runModules executes modules with concurrency limits and timeouts.
func runModules(modules []module.Module, mgr *output.Manager, callbacks collectionCallbacks) []module.Result {
	log := logging.G()
	results := make([]module.Result, len(modules))
	sem := make(chan struct{}, concurrencyFlag)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, m := range modules {
		wg.Add(1)
		go func(idx int, mod module.Module) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire semaphore.
			defer func() { <-sem }() // Release semaphore.

			if callbacks.OnModuleStart != nil {
				callbacks.OnModuleStart(idx, mod)
			}
			log.Progress(mod.Name(), fmt.Sprintf("Starting %s module", mod.Name()))

			ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
			defer cancel()

			start := time.Now()
			files, err := mod.Collect(ctx, mgr.BaseDir())
			elapsed := time.Since(start)

			result := module.Result{
				CollectorName:  mod.Name(),
				Category:       mod.Category(),
				FilesCollected: files,
				Duration:       elapsed,
				DurationSec:    elapsed.Seconds(),
				Success:        err == nil,
			}

			if err != nil {
				result.Error = err.Error()
				log.Failed(mod.Name(), err)
			} else {
				log.Done(mod.Name(), len(files), "artifacts", elapsed)
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
			if callbacks.OnModuleFinish != nil {
				callbacks.OnModuleFinish(idx, result)
			}
		}(i, m)
	}

	wg.Wait()
	return results
}

// resolveModules converts a comma-separated artifact string to a list of modules.
func resolveModules(artifactStr string) ([]module.Module, error) {
	names := strings.Split(artifactStr, ",")
	var result []module.Module
	seen := make(map[string]bool)

	for _, name := range names {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}

		if name == "all" {
			return module.All(), nil
		}

		// Check if it's a category name.
		categoryModules := module.GetByCategory(name)
		if len(categoryModules) > 0 {
			for _, m := range categoryModules {
				if !seen[m.Name()] {
					result = append(result, m)
					seen[m.Name()] = true
				}
			}
			continue
		}

		// Check if it's a specific module name.
		m, err := module.Get(name)
		if err != nil {
			return nil, fmt.Errorf("unknown artifact or category: %s\nUse 'fir collect --help' to see available artifacts", name)
		}
		if !seen[m.Name()] {
			result = append(result, m)
			seen[m.Name()] = true
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no modules resolved from: %s", artifactStr)
	}

	return result, nil
}

func outputSummaryPath(baseDir string) string {
	return filepath.Join(baseDir, "summary.txt")
}
