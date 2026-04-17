package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Liuchijang/FIR/internal/collector"
	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/spf13/cobra"
)

var (
	artifactFlag    string
	timeoutFlag     time.Duration
	concurrencyFlag int
)

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
  prefetch, amcache, wmi, srum

Category shortcuts:
  all       - All collectors
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
	collectCmd.Flags().DurationVarP(&timeoutFlag, "timeout", "t", 5*time.Minute, "Timeout per collector")
	collectCmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 2, "Maximum number of concurrent collectors")
	collectCmd.MarkFlagRequired("artifact")

	rootCmd.AddCommand(collectCmd)
}

func runCollect() error {
	// Resolve which collectors to run.
	collectors, err := resolveCollectors(artifactFlag)
	if err != nil {
		return err
	}

	return executeCollection(collectors)
}

// executeCollection is the core orchestration logic shared by interactive and flag modes.
func executeCollection(collectors []collector.Collector) error {
	// Create output directory.
	mgr, err := output.NewManager(outputDir)
	if err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Initialize logging into the output directory.
	logsDir, err := mgr.CategoryDir("logs")
	if err != nil {
		return fmt.Errorf("create logs directory: %w", err)
	}
	if err := logging.Init(logsDir, verbose); err != nil {
		return fmt.Errorf("initialize logging: %w", err)
	}
	defer logging.Close()

	log := logging.G()
	log.Info(fmt.Sprintf("Output directory: %s", mgr.BaseDir()))
	log.Info(fmt.Sprintf("Collectors to run: %d", len(collectors)))

	startTime := time.Now()
	results := runCollectors(collectors, mgr)
	totalDuration := time.Since(startTime)

	// Write metadata.
	if err := output.WriteMetadata(mgr.BaseDir(), results, totalDuration); err != nil {
		log.Error(fmt.Sprintf("Failed to write metadata: %v", err))
	}

	// Summary.
	successCount := 0
	failCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failCount++
		}
	}

	fmt.Fprintf(os.Stderr, "\n")
	log.Info(fmt.Sprintf("Collection completed in %.1fs", totalDuration.Seconds()))
	log.Success(fmt.Sprintf("Results: %d succeeded, %d failed", successCount, failCount))
	log.Info(fmt.Sprintf("Output: %s", mgr.BaseDir()))

	return nil
}

// runCollectors executes collectors with concurrency limits and timeouts.
func runCollectors(collectors []collector.Collector, mgr *output.Manager) []collector.Result {
	log := logging.G()
	results := make([]collector.Result, len(collectors))
	sem := make(chan struct{}, concurrencyFlag)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, c := range collectors {
		wg.Add(1)
		go func(idx int, col collector.Collector) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire semaphore.
			defer func() { <-sem }() // Release semaphore.

			log.Progress(col.Name(), fmt.Sprintf("Starting %s collector", col.Name()))

			ctx, cancel := context.WithTimeout(context.Background(), timeoutFlag)
			defer cancel()

			start := time.Now()
			files, err := col.Collect(ctx, mgr.BaseDir())
			elapsed := time.Since(start)

			result := collector.Result{
				CollectorName:  col.Name(),
				Category:       col.Category(),
				FilesCollected: files,
				Duration:       elapsed,
				DurationSec:    elapsed.Seconds(),
				Success:        err == nil,
			}

			if err != nil {
				result.Error = err.Error()
				log.Failed(col.Name(), err)
			} else {
				log.Done(col.Name(), len(files), "artifacts", elapsed)
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, c)
	}

	wg.Wait()
	return results
}

// resolveCollectors converts a comma-separated artifact string to a list of collectors.
func resolveCollectors(artifactStr string) ([]collector.Collector, error) {
	names := strings.Split(artifactStr, ",")
	var result []collector.Collector
	seen := make(map[string]bool)

	for _, name := range names {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}

		if name == "all" {
			return collector.All(), nil
		}

		// Check if it's a category name.
		catCollectors := collector.GetByCategory(name)
		if len(catCollectors) > 0 {
			for _, c := range catCollectors {
				if !seen[c.Name()] {
					result = append(result, c)
					seen[c.Name()] = true
				}
			}
			continue
		}

		// Check if it's a specific collector name.
		c, err := collector.Get(name)
		if err != nil {
			return nil, fmt.Errorf("unknown artifact or category: %s\nUse 'fir collect --help' to see available artifacts", name)
		}
		if !seen[c.Name()] {
			result = append(result, c)
			seen[c.Name()] = true
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no collectors resolved from: %s", artifactStr)
	}

	return result, nil
}
