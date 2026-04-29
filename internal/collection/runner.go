// Package collection orchestrates FIR artifact collection independently of CLI/TUI.
package collection

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
)

const (
	DefaultTimeout     = 5 * time.Minute
	DefaultConcurrency = 2
)

type Callbacks struct {
	OnOutputReady  func(string)
	OnModuleQueued func(int, module.Module)
	OnModuleStart  func(int, module.Module)
	OnModuleFinish func(int, module.Result)
}

type Options struct {
	OutputBaseDir string
	Verbose       bool
	Timeout       time.Duration
	Concurrency   int
	SilentConsole bool
	Callbacks     Callbacks
}

func Run(ctx context.Context, modules []module.Module, opts Options) (output.SummaryReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)

	mgr, err := output.NewManager(opts.OutputBaseDir)
	if err != nil {
		return output.SummaryReport{}, fmt.Errorf("create output directory: %w", err)
	}
	if opts.Callbacks.OnOutputReady != nil {
		opts.Callbacks.OnOutputReady(mgr.BaseDir())
	}

	if err := logging.Init(mgr.BaseDir(), opts.Verbose); err != nil {
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
	for idx, mod := range modules {
		if opts.Callbacks.OnModuleQueued != nil {
			opts.Callbacks.OnModuleQueued(idx, mod)
		}
	}

	startedAt := time.Now()
	results := runModules(ctx, modules, mgr, opts)
	totalDuration := time.Since(startedAt)
	finishedAt := startedAt.Add(totalDuration)
	report := output.NewSummaryReport(mgr.BaseDir(), startedAt, totalDuration, opts.Timeout, opts.Concurrency, results)
	manifest := output.NewManifest(mgr.BaseDir(), startedAt, finishedAt, results)

	if err := output.WriteManifest(mgr.BaseDir(), manifest); err != nil {
		log.Error(fmt.Sprintf("Failed to write manifest: %v", err))
	}
	if err := output.WriteSummary(mgr.BaseDir(), report); err != nil {
		log.Error(fmt.Sprintf("Failed to write summary: %v", err))
	}

	if !opts.SilentConsole {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, report.Render())
	}
	log.Info(fmt.Sprintf("Collection completed in %.1fs", totalDuration.Seconds()))
	log.Success(fmt.Sprintf("Results: %d succeeded, %d failed, %d skipped", report.SuccessCount, report.FailureCount, report.SkippedCount))
	log.Info(fmt.Sprintf("Output: %s", mgr.BaseDir()))
	log.Info(fmt.Sprintf("Summary: %s", filepath.Join(mgr.BaseDir(), "summary.txt")))
	log.Info(fmt.Sprintf("Manifest: %s", filepath.Join(mgr.BaseDir(), "manifest.json")))

	return report, nil
}

func normalizeOptions(opts Options) Options {
	if opts.OutputBaseDir == "" {
		opts.OutputBaseDir = "."
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	return opts
}
