// Package collection orchestrates FIR artifact collection independently of CLI/TUI.
package collection

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/resource"
	"github.com/Liuchijang/FIR/internal/utils"
)

const (
	DefaultTimeout     = 0
	DefaultConcurrency = 2
)

type Callbacks struct {
	OnOutputReady  func(string)
	OnModuleQueued func(int, module.Module)
	OnModuleStart  func(int, module.Module)
	OnModuleFinish func(int, module.Result)
}

type Options struct {
	OutputBaseDir   string
	Verbose         bool
	Timeout         time.Duration
	Concurrency     int
	Resources       resource.Config
	StorageEstimate resource.StorageEstimate
	SilentConsole   bool
	Callbacks       Callbacks
}

func Run(ctx context.Context, modules []module.Module, opts Options) (output.SummaryReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	restoreRuntime := applyResourceConfig(opts.Resources)
	defer restoreRuntime()

	opts.StorageEstimate = resource.EstimateStorage(opts.OutputBaseDir, modules, opts.Resources.Compress)
	if !opts.StorageEstimate.Healthy {
		return output.SummaryReport{}, fmt.Errorf("storage check failed: %s", opts.StorageEstimate.Reason)
	}

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
	logClosed := false
	defer func() {
		if !logClosed {
			logging.Close()
		}
	}()
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
	manifest.Resources = opts.Resources
	manifest.StorageEstimate = opts.StorageEstimate

	if err := output.WriteManifest(mgr.BaseDir(), manifest); err != nil {
		log.Error(fmt.Sprintf("Failed to write manifest: %v", err))
	}
	if err := output.WriteSummary(mgr.BaseDir(), report); err != nil {
		log.Error(fmt.Sprintf("Failed to write summary: %v", err))
	}
	archivePath := ""
	if opts.Resources.Compress {
		manifest.CompressEnabled = true
		manifest.Archive = output.ArchiveInfo{Path: mgr.BaseDir() + ".zip"}
		if err := output.WriteManifest(mgr.BaseDir(), manifest); err != nil {
			log.Error(fmt.Sprintf("Failed to update manifest compression info: %v", err))
		}
		archive, err := output.CompressRunDirectory(mgr.BaseDir())
		if err != nil {
			log.Error(fmt.Sprintf("Failed to compress output: %v", err))
		} else {
			archivePath = archive.Path
			if err := output.WriteArchiveHashFile(archive); err != nil {
				log.Error(fmt.Sprintf("Failed to write archive hash sidecar: %v", err))
			}
			log.Info(fmt.Sprintf("Archive: %s", archivePath))
		}
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
	if archivePath != "" {
		log.Info(fmt.Sprintf("Raw output will be removed after successful compression: %s", mgr.BaseDir()))
	}

	logging.Close()
	logClosed = true
	if archivePath != "" {
		if err := output.RemoveRawOutputDir(mgr.BaseDir(), archivePath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove raw output %s: %v\n", mgr.BaseDir(), err)
		}
	}

	return report, nil
}

func normalizeOptions(opts Options) Options {
	if opts.OutputBaseDir == "" {
		opts.OutputBaseDir = "."
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 0
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = opts.Resources.Workers
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Resources.IsZero() {
		opts.Resources = resource.DefaultConfig()
	}
	if opts.Resources.Workers <= 0 {
		opts.Resources.Workers = opts.Concurrency
	}
	opts.Resources = opts.Resources.Normalized()
	opts.Concurrency = opts.Resources.Workers
	return opts
}

func applyResourceConfig(cfg resource.Config) func() {
	cfg = cfg.Normalized()
	oldProcs := runtime.GOMAXPROCS(0)
	if cfg.CPULimitPercent > 0 {
		procs := oldProcs * cfg.CPULimitPercent / 100
		if procs < 1 {
			procs = 1
		}
		runtime.GOMAXPROCS(procs)
	}

	oldMemoryLimit := debug.SetMemoryLimit(cfg.RAMCapBytes)
	utils.SetDiskIOLimit(cfg.DiskIOLimitBps)

	return func() {
		runtime.GOMAXPROCS(oldProcs)
		debug.SetMemoryLimit(oldMemoryLimit)
		utils.SetDiskIOLimit(0)
	}
}
