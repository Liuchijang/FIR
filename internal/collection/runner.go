// Package collection orchestrates Tyto artifact collection independently of CLI/TUI.
package collection

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/resource"
)

const DefaultTimeout = 0

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
	Resources       resource.Config
	StorageEstimate resource.StorageEstimate
	SilentConsole   bool
	Callbacks       Callbacks
	// Source is the previously collected run to analyze instead of acquiring
	// anything. Set it and the run reads that tree and never the live host; leave
	// it nil for a normal collection.
	Source *SourceRun
}

// offline reports whether this run parses a previously collected tree.
func (o Options) offline() bool { return o.Source != nil }

// sourceRoot is the run directory analyzers read artifacts from — the analyzed
// run offline, and the run being written for a live collection.
func (o Options) sourceRoot() string {
	if o.Source != nil {
		return o.Source.Root
	}
	return ""
}

func (o Options) sourcePolicy() module.SourcePolicy {
	if o.offline() {
		return module.SourcePolicyCollectedOnly
	}
	return module.SourcePolicyCollectedThenLive
}

func Run(ctx context.Context, modules []module.Module, opts Options) (output.SummaryReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts = normalizeOptions(opts)
	cpuMechanism, diskMechanism, restoreRuntime := applyResourceConfig(opts.Resources)
	defer restoreRuntime()
	opts.Resources.CPULimitMechanism = cpuMechanism
	opts.Resources.DiskIOMechanism = diskMechanism

	// Offline analysis is sized differently: the live measurements behind
	// EstimateStorage would describe the investigator's disks, not the artifacts
	// actually on hand.
	if opts.offline() {
		opts.StorageEstimate = resource.EstimateAnalysisStorage(opts.OutputBaseDir, opts.Source.Root, modules, opts.Resources.Compress)
	} else {
		opts.StorageEstimate = resource.EstimateStorage(opts.OutputBaseDir, modules, opts.Resources.Compress)
	}
	if !opts.StorageEstimate.Healthy {
		return output.SummaryReport{}, fmt.Errorf("storage check failed: %s", opts.StorageEstimate.Reason)
	}

	mgr, err := newOutputManager(opts)
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
	log.Info(fmt.Sprintf("CPU limit: %d%% via %s | Disk budget: %s | Workers: %s (%s)",
		opts.Resources.CPULimitPercent,
		cpuMechanism,
		describeDiskBudget(opts.Resources),
		opts.Resources.WorkerSummary(),
		opts.Resources.WorkersRationale))
	if opts.Resources.DiskIOLimitBps > 0 && diskMechanism == platform.DiskMechanismNone {
		log.Warn("Disk budget was requested but this host does not support storage rate control; the run is unthrottled")
	}
	if cpuMechanism == platform.CPUMechanismGOMAXPROCS {
		// Worth a warning: winpmem and the PowerShell-hosted parsers run
		// outside the Go runtime, so this path leaves them uncapped.
		log.Warn("CPU limit could not be applied to child processes; only goroutines are capped")
	}
	// Started before the integrity check, not after: re-hashing a collected tree
	// is minutes of real work on a large one, and a duration that leaves it out
	// understates what the run cost.
	startedAt := time.Now()

	// The check runs before any analyzer opens an artifact, so the log says
	// whether the inputs were intact ahead of the output derived from them.
	integrity := logSourceRun(log, opts, modules)
	for idx, mod := range modules {
		if opts.Callbacks.OnModuleQueued != nil {
			opts.Callbacks.OnModuleQueued(idx, mod)
		}
	}

	results := runModules(ctx, modules, mgr, opts)
	totalDuration := time.Since(startedAt)
	finishedAt := startedAt.Add(totalDuration)
	report := output.NewSummaryReport(mgr.BaseDir(), startedAt, totalDuration, opts.Timeout, opts.Resources.WorkerSummary(), results)
	manifest := output.NewManifest(mgr.BaseDir(), startedAt, finishedAt, results)
	manifest.Resources = opts.Resources
	manifest.StorageEstimate = opts.StorageEstimate
	if opts.offline() {
		manifest.SourceRun = opts.Source.Info(integrity)
		// Both NewManifest and NewSummaryReport describe the machine they run on.
		// For an analysis run that is the investigator's workstation, while every
		// CSV in the directory describes the subject — so the subject's identity
		// wins in both, and SourceRun.AnalyzedOn records where the parsing
		// happened. Setting only one of them is worse than setting neither: the
		// two files ship side by side and would name different machines for the
		// same data.
		if opts.Source.Hostname != "" {
			manifest.Hostname = opts.Source.Hostname
			report.Hostname = opts.Source.Hostname
		}
		if opts.Source.OS != "" {
			manifest.OS = opts.Source.OS
			manifest.Architecture = opts.Source.Architecture
			report.OS = opts.Source.OS
			report.Architecture = opts.Source.Architecture
		}
		// Unconditional, including when the source has none. NewManifest filled
		// this in from the machine it ran on, which here is the analyst's
		// workstation — so leaving it alone on a run whose input predates the field
		// would label the subject's evidence with the analyst's timezone. Absent is
		// the honest answer and the only one available.
		manifest.Timezone = opts.Source.Timezone
		report.Timezone = opts.Source.Timezone
	}

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

	// These log lines must be emitted before CompressRunDirectory runs below, or they
	// would be missing from collector.log inside the archive that gets delivered as evidence.
	archivePath := ""
	if opts.Resources.Compress {
		// The memory image is archived by reference, not by content: see
		// output.MemoryImages for why compressing it is all cost and no saving.
		memoryImages := output.MemoryImages(mgr.BaseDir())

		manifest.CompressEnabled = true
		manifest.Archive = output.ArchiveInfo{Path: mgr.BaseDir() + ".zip"}
		for _, image := range memoryImages {
			manifest.UncompressedFiles = append(manifest.UncompressedFiles, mgr.BaseDir()+"_"+filepath.Base(image))
		}
		if err := output.WriteManifest(mgr.BaseDir(), manifest); err != nil {
			log.Error(fmt.Sprintf("Failed to update manifest compression info: %v", err))
		}
		for _, image := range memoryImages {
			log.Info(fmt.Sprintf("Memory image kept outside the archive: %s", filepath.Base(image)))
		}
		log.Info(fmt.Sprintf("Raw output will be removed after successful compression: %s", mgr.BaseDir()))

		archive, err := output.CompressRunDirectory(mgr.BaseDir(), memoryImages)
		if err != nil {
			log.Error(fmt.Sprintf("Failed to compress output: %v", err))
		} else {
			archivePath = archive.Path
			if err := output.WriteArchiveHashFile(archive); err != nil {
				log.Error(fmt.Sprintf("Failed to write archive hash sidecar: %v", err))
			}
			log.Info(fmt.Sprintf("Archive: %s", archivePath))

			// Only after the archive is on disk: until then the run directory
			// is still the evidence, and moving anything out of it early would
			// leave a failed compression with its artifacts scattered.
			kept, err := output.PreserveOutsideArchive(mgr.BaseDir(), memoryImages)
			if err != nil {
				log.Error(fmt.Sprintf("Failed to preserve memory image outside the archive: %v", err))
				// The dump is still inside the run directory, so that directory
				// must not be deleted or the image goes with it.
				archivePath = ""
			}
			for _, path := range kept {
				log.Info(fmt.Sprintf("Memory image: %s", path))
			}
		}
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

// logSourceRun records what is being analyzed and verifies it, returning the
// integrity report for the manifest.
//
// Nothing here stops the run. A mismatch means the analyst has to weigh the CSVs
// against a file that changed since collection, which is a judgement they make
// with the evidence in hand — but they can only make it if it is stated, so this
// is a warning rather than a silent pass.
func logSourceRun(log *logging.Logger, opts Options, modules []module.Module) *output.IntegrityReport {
	if !opts.offline() {
		return nil
	}

	source := opts.Source
	log.Info(fmt.Sprintf("Analyzing collected run: %s", source.Root))
	if source.Archive != "" {
		log.Info(fmt.Sprintf("Extracted from archive: %s", source.Archive))
	}
	if source.ManifestFound {
		log.Info(fmt.Sprintf("Collected on %s by Tyto %s at %s",
			source.Hostname, source.CollectorVersion, source.CollectedAt.Format(time.RFC3339)))
	} else {
		log.Warn("No manifest.json in the analyzed run: artifact hashes cannot be verified and the run is named after the input")
	}
	log.Info("Live sources are disabled for this run; an analyzer without its artifact is skipped")

	integrity := source.VerifyIntegrity(modules)
	if integrity == nil {
		return nil
	}
	if integrity.OK() {
		log.Success(fmt.Sprintf("Integrity: %d/%d collected file(s) match the source manifest", integrity.Verified, integrity.FilesChecked))
		return integrity
	}
	log.Warn(fmt.Sprintf("Integrity: %d/%d collected file(s) match the source manifest", integrity.Verified, integrity.FilesChecked))
	for _, name := range integrity.Mismatched {
		log.Warn(fmt.Sprintf("Integrity: %s does not match the hash recorded at collection", name))
	}
	for _, name := range integrity.Missing {
		log.Warn(fmt.Sprintf("Integrity: %s is recorded in the source manifest but missing", name))
	}
	for _, entry := range integrity.Unreadable {
		log.Warn(fmt.Sprintf("Integrity: could not read %s", entry))
	}
	return integrity
}

// newOutputManager creates the run directory. An offline analysis names it after
// the collection it read rather than after the machine doing the reading.
func newOutputManager(opts Options) (*output.Manager, error) {
	if opts.offline() {
		return output.NewManagerWithName(opts.OutputBaseDir, opts.Source.RunDirName())
	}
	return output.NewManager(opts.OutputBaseDir)
}

// describeDiskBudget reports the budget together with how it is enforced, so a
// log line never implies a cap that was never installed.
func describeDiskBudget(cfg resource.Config) string {
	if cfg.DiskIOLimitBps <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%s/s via %s", resource.FormatBytes(cfg.DiskIOLimitBps), cfg.DiskIOMechanism)
}

func normalizeOptions(opts Options) Options {
	if opts.OutputBaseDir == "" {
		opts.OutputBaseDir = "."
	}
	if opts.Resources.IsZero() {
		opts.Resources = resource.DefaultConfig()
	}
	// ResolveWorkers needs the output directory: how many collectors can run in
	// parallel depends on the device the evidence is being written to.
	opts.Resources = opts.Resources.Normalized().ResolveWorkers(opts.OutputBaseDir)
	return opts
}

// applyResourceConfig installs the run's limits and reports the CPU mechanism
// that was actually used along with a restore func.
//
// There is deliberately no memory cap here. debug.SetMemoryLimit is a soft
// limit: it cannot refuse an allocation, it only makes the GC run harder as the
// heap approaches the ceiling. The analyzers read whole artifacts into memory,
// so a cap below their working set bought continuous GC instead of protection —
// and still OOMed. Bounding analyzer memory is the analyzers' job (stream the
// parse) and the scheduler's (fewer concurrent workers), not a runtime knob's.
func applyResourceConfig(cfg resource.Config) (cpuMechanism, diskMechanism string, restore func()) {
	cfg = cfg.Normalized()
	cpuMechanism, restoreCPU := platform.LimitCPU(cfg.CPULimitPercent)
	diskMechanism, restoreDisk := platform.LimitDiskIO(cfg.DiskIOLimitBps)

	return cpuMechanism, diskMechanism, func() {
		restoreCPU()
		restoreDisk()
	}
}
