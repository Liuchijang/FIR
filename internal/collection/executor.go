package collection

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/platform"
)

func runModules(ctx context.Context, modules []module.Module, mgr *output.Manager, opts Options) []module.Result {
	results := make([]module.Result, len(modules))
	selectedModules := selectedModuleSet(modules)

	var collectorIdx []int
	var analyzerIdx []int
	for idx, mod := range modules {
		if module.ModeOf(mod) == module.ModeAnalyzer {
			analyzerIdx = append(analyzerIdx, idx)
			continue
		}
		collectorIdx = append(collectorIdx, idx)
	}

	runBatch(ctx, modules, results, collectorIdx, mgr, opts, selectedModules)
	runBatch(ctx, modules, results, analyzerIdx, mgr, opts, selectedModules)
	return results
}

func selectedModuleSet(modules []module.Module) map[string]bool {
	selected := make(map[string]bool, len(modules))
	for _, mod := range modules {
		selected[mod.Name()] = true
	}
	return selected
}

func runBatch(ctx context.Context, modules []module.Module, results []module.Result, indices []int, mgr *output.Manager, opts Options, selectedModules map[string]bool) {
	if len(indices) == 0 {
		return
	}

	workerCount := opts.Concurrency
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
				result := runModule(ctx, mod, mgr, opts.Timeout, selectedModules)
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

func runModule(parent context.Context, mod module.Module, mgr *output.Manager, timeout time.Duration, selectedModules map[string]bool) (result module.Result) {
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
		if outcome, ok := runRequestModule(ctx, mod, mgr.BaseDir(), artifactDir, startedAt, selectedModules); ok {
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

func runRequestModule(ctx context.Context, mod module.Module, outputDir string, moduleDir string, startedAt time.Time, selectedModules map[string]bool) (moduleOutcome, bool) {
	hostname := hostnameOrUnknown()
	if requestCollector, ok := mod.(module.RequestCollector); ok {
		result := requestCollector.CollectWithRequest(ctx, module.CollectRequest{
			OutputDir:       outputDir,
			ArtifactDir:     moduleDir,
			Hostname:        hostname,
			StartedAt:       startedAt,
			SourcePolicy:    module.SourcePolicyCollectedThenLive,
			SelectedModules: selectedModules,
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
			AnalyzerDir:     moduleDir,
			Hostname:        hostname,
			StartedAt:       startedAt,
			SourcePolicy:    module.SourcePolicyCollectedThenLive,
			SelectedModules: selectedModules,
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

func applyModuleOutcome(ctx context.Context, mod module.Module, result *module.Result, outcome moduleOutcome, log *logging.Logger, startedAt time.Time) {
	result.FilesCollected = outcome.files
	result.OutputPath = outcome.outputPath
	result.Skipped = outcome.skipped
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
	if outcome.skipped {
		log.Warn(fmt.Sprintf("Skipped: %s", mod.Name()))
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
