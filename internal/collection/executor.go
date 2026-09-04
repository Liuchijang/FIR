package collection

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Liuchijang/Tyto/internal/logging"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/output"
	"github.com/Liuchijang/Tyto/internal/platform"
)

func runModules(ctx context.Context, modules []module.Module, mgr *output.Manager, opts Options) []module.Result {
	results := make([]module.Result, len(modules))
	selectedModules := selectedModuleSet(modules, opts)

	var collectorIdx []int
	var analyzerIdx []int
	for idx, mod := range modules {
		if module.ModeOf(mod) == module.ModeAnalyzer {
			analyzerIdx = append(analyzerIdx, idx)
			continue
		}
		collectorIdx = append(collectorIdx, idx)
	}

	runCtx := runContext{selected: selectedModules}

	// The two batches get their own worker counts: collection is I/O against a
	// single device, analysis is CPU and memory against artifacts already on
	// disk, and the right degree of parallelism is not the same number.
	runBatch(ctx, modules, results, collectorIdx, mgr, opts, runCtx, opts.Resources.CollectorWorkers)

	// Between the batches, which is the only place this can be built: every
	// collector has finished and no analyzer has started, so what the collectors
	// recorded is complete and nothing is still writing to it.
	runCtx.collected = collectedFileIndex(modules, results, opts)

	runBatch(ctx, modules, results, analyzerIdx, mgr, opts, runCtx, opts.Resources.AnalyzerWorkers)
	return results
}

// runContext is what a module needs to know about the run around it.
//
// The two facts travel together because they answer the same kind of question —
// what else is in this run, and what did it find — and threading each one through
// runBatch and runModule as its own parameter is how a signature grows until
// nobody reads it.
type runContext struct {
	selected  map[string]bool
	collected map[string][]module.FileInfo
}

// collectedFileIndex is what an analyzer reads a collected artifact's own
// timestamps out of.
//
// The copy cannot carry them: nothing in the tree preserves file times, so the
// file an analyzer opens is stamped with the moment it was copied. The collector
// read the real ones and recorded them, and this is how they cross the barrier.
// Offline the same index comes from the analyzed run's manifest, so an analyzer
// cannot tell the two modes apart.
func collectedFileIndex(modules []module.Module, results []module.Result, opts Options) map[string][]module.FileInfo {
	if opts.offline() {
		return opts.Source.CollectedFiles()
	}

	index := make(map[string][]module.FileInfo)
	for i, mod := range modules {
		if module.ModeOf(mod) == module.ModeAnalyzer || len(results[i].FilesCollected) == 0 {
			continue
		}
		index[mod.Name()] = results[i].FilesCollected
	}
	return index
}

// selectedModuleSet is what req.IsSelected answers from: the modules taking part
// in this run.
//
// Offline analysis substitutes the collectors the analyzed run holds output for.
// The question the analyzers ask through IsSelected is "is this artifact part of
// what I am working from" — for a live run that is the run's own selection, and
// for an offline one it is what the earlier collection produced.
func selectedModuleSet(modules []module.Module, opts Options) map[string]bool {
	selected := make(map[string]bool, len(modules))
	for _, mod := range modules {
		selected[mod.Name()] = true
	}
	if opts.offline() {
		for name := range opts.Source.CollectedModules {
			selected[name] = true
		}
	}
	return selected
}

func runBatch(ctx context.Context, modules []module.Module, results []module.Result, indices []int, mgr *output.Manager, opts Options, runCtx runContext, workers int) {
	if len(indices) == 0 {
		return
	}

	workerCount := workers
	if workerCount > len(indices) {
		workerCount = len(indices)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan int)
	var wg sync.WaitGroup

	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				mod := modules[idx]
				if opts.Callbacks.OnModuleStart != nil {
					opts.Callbacks.OnModuleStart(idx, mod)
				}
				result := runModule(ctx, mod, mgr, opts, runCtx)
				results[idx] = result
				if opts.Callbacks.OnModuleFinish != nil {
					opts.Callbacks.OnModuleFinish(idx, result)
				}
			}
		}()
	}

	for _, idx := range indices {
		select {
		case <-ctx.Done():
			results[idx] = skippedResult(modules[idx], mgr.BaseDir(), ctx.Err())
			if opts.Callbacks.OnModuleFinish != nil {
				opts.Callbacks.OnModuleFinish(idx, results[idx])
			}
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()
}

func runModule(parent context.Context, mod module.Module, mgr *output.Manager, opts Options, runCtx runContext) (result module.Result) {
	timeout := opts.Timeout
	log := logging.G()
	artifactDir := module.ModuleDir(mgr.BaseDir(), mod)
	result = module.Result{
		CollectorName: mod.Name(),
		Category:      mod.Category(),
		OutputPath:    artifactDir,
	}

	select {
	case <-parent.Done():
		return skippedResult(mod, mgr.BaseDir(), parent.Err())
	default:
	}

	log.Progress(mod.Name(), fmt.Sprintf("Starting %s module", mod.Name()))
	ctx := parent
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	}
	defer cancel()

	startedAt := time.Now()
	defer func() {
		result.Duration = time.Since(startedAt)
		result.DurationSec = result.Duration.Seconds()
		if recovered := recover(); recovered != nil {
			result.Success = false
			result.Status = module.StatusFailed
			result.ErrorKind = module.ErrorKindPanic
			result.Error = fmt.Sprintf("panic: %v", recovered)
			log.Failed(mod.Name(), fmt.Errorf("%s", result.Error))
			return
		}
		finalizeResult(ctx, &result)
	}()

	// A module that ignores ctx would otherwise block this worker forever — raw-volume
	// reads are unbounded blocking syscalls — and wg.Wait() would never return, so the
	// run could never write its manifest or summary. Watch the module instead and
	// abandon the goroutine on timeout: a leaked goroutine costs less than a run that
	// never finishes and produces no evidence metadata.
	completed := make(chan moduleRun, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				completed <- moduleRun{panicValue: recovered}
			}
		}()
		if outcome, ok := runRequestModule(ctx, mod, mgr.BaseDir(), artifactDir, startedAt, opts, runCtx); ok {
			completed <- moduleRun{outcome: outcome, viaRequest: true}
			return
		}
		files, err := mod.Collect(ctx, mgr.BaseDir())
		completed <- moduleRun{files: files, err: err}
	}()

	var run moduleRun
	select {
	case run = <-completed:
	case <-ctx.Done():
		result.Success = false
		result.Error = fmt.Sprintf("module did not return before %s", ctx.Err())
		log.Failed(mod.Name(), fmt.Errorf("%s", result.Error))
		return result
	}

	if run.panicValue != nil {
		panic(run.panicValue)
	}
	if run.viaRequest {
		applyModuleOutcome(ctx, mod, &result, run.outcome, log, startedAt)
		return result
	}

	files, err := run.files, run.err
	result.FilesCollected = files
	if err != nil {
		result.Error = err.Error()
		if ctx.Err() != nil {
			result.Error = ctx.Err().Error() + ": " + err.Error()
		}
		if len(files) == 0 {
			result.Success = false
			log.Failed(mod.Name(), fmt.Errorf("%s", result.Error))
			return result
		}
		// Partial success — see applyModuleOutcome below for why.
		result.Success = true
		log.Warn(fmt.Sprintf("%s: %s", mod.Name(), result.Error))
		log.Done(mod.Name(), len(files), "artifacts", time.Since(startedAt))
		return result
	}

	result.Success = true
	log.Done(mod.Name(), len(files), "artifacts", time.Since(startedAt))
	return result
}

type moduleRun struct {
	outcome    moduleOutcome
	viaRequest bool
	files      []module.FileInfo
	err        error
	panicValue any
}

type moduleOutcome struct {
	files      []module.FileInfo
	outputPath string
	skipped    bool
	errMessage string
}

func runRequestModule(ctx context.Context, mod module.Module, outputDir string, moduleDir string, startedAt time.Time, opts Options, runCtx runContext) (moduleOutcome, bool) {
	hostname := hostnameOrUnknown()
	if opts.offline() && opts.Source.Hostname != "" {
		// An analyzer that stamps a hostname into its output is describing the
		// machine the artifacts came from, not the one parsing them.
		hostname = opts.Source.Hostname
	}
	if requestCollector, ok := mod.(module.RequestCollector); ok {
		result := requestCollector.CollectWithRequest(ctx, module.CollectRequest{
			OutputDir:       outputDir,
			ArtifactDir:     moduleDir,
			Hostname:        hostname,
			StartedAt:       startedAt,
			SourcePolicy:    module.SourcePolicyCollectedThenLive,
			SelectedModules: runCtx.selected,
		})
		return moduleOutcome{
			files:      result.Files,
			outputPath: firstNonEmpty(result.OutputPath, moduleDir),
			skipped:    result.Skipped,
			errMessage: result.Error,
		}, true
	}
	if requestAnalyzer, ok := mod.(module.RequestAnalyzer); ok {
		result := requestAnalyzer.AnalyzeWithRequest(ctx, module.AnalyzeRequest{
			OutputDir:       outputDir,
			SourceDir:       opts.sourceRoot(),
			AnalyzerDir:     moduleDir,
			Hostname:        hostname,
			StartedAt:       startedAt,
			SourcePolicy:    opts.sourcePolicy(),
			SelectedModules: runCtx.selected,
			CollectedFiles:  runCtx.collected,
		})
		return moduleOutcome{
			files:      result.Files,
			outputPath: firstNonEmpty(result.OutputPath, moduleDir),
			skipped:    result.Skipped,
			errMessage: result.Error,
		}, true
	}
	return moduleOutcome{}, false
}

// maxZeroFilledNamed bounds how many names the warning lists. A module that came home
// entirely empty would otherwise put hundreds of file names into summary.txt; the
// count is the part that matters and a few names say which kind of file it was.
const maxZeroFilledNamed = 5

// describeZeroFilled renders the artifacts that copied with no content.
func describeZeroFilled(files []module.FileInfo) string {
	var names []string
	total := 0
	for _, file := range files {
		if !file.ZeroFilled {
			continue
		}
		total++
		if len(names) < maxZeroFilledNamed {
			names = append(names, file.Path)
		}
	}
	if total == 0 {
		return ""
	}
	listed := strings.Join(names, ", ")
	if total > len(names) {
		listed += fmt.Sprintf(", and %d more", total-len(names))
	}
	return fmt.Sprintf("%d artifact(s) copied at their full size but contain no data, so the reads returned nothing: %s", total, listed)
}

func applyModuleOutcome(ctx context.Context, mod module.Module, result *module.Result, outcome moduleOutcome, log *logging.Logger, startedAt time.Time) {
	result.FilesCollected = outcome.files
	result.OutputPath = outcome.outputPath
	result.Skipped = outcome.skipped
	// Folded in here rather than in each collector, so a module cannot ship without
	// it. An artifact that copied at the right size with no content is a collection
	// failure that every layer below reported as success: the reads succeeded, the
	// hash is valid, the file count is right. This is the only place all of that
	// meets a human-readable warning.
	if note := describeZeroFilled(outcome.files); note != "" {
		if outcome.errMessage == "" {
			outcome.errMessage = note
		} else {
			outcome.errMessage += "; " + note
		}
	}
	// Skipped is checked before the message, because a skipped module's message is
	// a reason and not a failure — "the analyzed run holds no $MFT" would
	// otherwise be logged as Failed and then be corrected to SKIPPED by
	// finalizeResult, with the two disagreeing in the log and the summary.
	if outcome.skipped {
		if outcome.errMessage != "" {
			result.Error = outcome.errMessage
			log.Warn(fmt.Sprintf("Skipped: %s (%s)", mod.Name(), outcome.errMessage))
			return
		}
		log.Warn(fmt.Sprintf("Skipped: %s", mod.Name()))
		return
	}
	if outcome.errMessage != "" {
		result.Error = errorWithContext(ctx, outcome.errMessage)
		if len(outcome.files) == 0 {
			result.Success = false
			log.Failed(mod.Name(), fmt.Errorf("%s", result.Error))
			return
		}
		// Some files were still collected despite the error(s) — only a total
		// loss (no files at all) counts as a failed run; a partial run keeps
		// its success status, with the error kept visible as a warning.
		result.Success = true
		log.Warn(fmt.Sprintf("%s: %s", mod.Name(), result.Error))
		log.Done(mod.Name(), len(outcome.files), "artifacts", time.Since(startedAt))
		return
	}
	result.Success = true
	log.Done(mod.Name(), len(outcome.files), "artifacts", time.Since(startedAt))
}

func hostnameOrUnknown() string {
	return platform.DetectHost().Hostname
}

func errorWithContext(ctx context.Context, message string) string {
	if ctx.Err() != nil {
		return ctx.Err().Error() + ": " + message
	}
	return message
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func finalizeResult(ctx context.Context, result *module.Result) {
	switch {
	case result.Skipped:
		if errors.Is(ctx.Err(), context.Canceled) {
			result.Status = module.StatusCancelled
			result.ErrorKind = module.ErrorKindCancelled
			return
		}
		result.Status = module.StatusSkipped
	case result.Success:
		result.Status = module.StatusSuccess
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Status = module.StatusTimeout
		result.ErrorKind = module.ErrorKindTimeout
	case errors.Is(ctx.Err(), context.Canceled):
		result.Status = module.StatusCancelled
		result.ErrorKind = module.ErrorKindCancelled
	default:
		result.Status = module.StatusFailed
		if result.Error != "" && result.ErrorKind == "" {
			result.ErrorKind = module.ErrorKindModule
		}
	}
}

func skippedResult(mod module.Module, outputDir string, err error) module.Result {
	if err == nil {
		err = context.Canceled
	}
	status := module.StatusSkipped
	errorKind := ""
	if errors.Is(err, context.Canceled) {
		status = module.StatusCancelled
		errorKind = module.ErrorKindCancelled
	}
	return module.Result{
		CollectorName: mod.Name(),
		Category:      mod.Category(),
		OutputPath:    module.ModuleDir(outputDir, mod),
		Skipped:       true,
		Success:       false,
		Status:        status,
		ErrorKind:     errorKind,
		Error:         err.Error(),
	}
}
