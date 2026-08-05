package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.RegisterAnalyzer(&eventLogParser{}) }

type eventLogParser struct{}

func (c *eventLogParser) Name() string     { return "eventlog_parser" }
func (c *eventLogParser) Category() string { return "eventlog" }
func (c *eventLogParser) Description() string {
	return "Parse EVTX logs"
}

func (c *eventLogParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create eventlog parser output dir: %w", err))
	}

	sourceDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	if dir, ok := existingModuleDir(req.OutputDir, "eventlog"); ok {
		sourceDir = dir
	}
	selectedFiles, err := eventlogpkg.ResolveSelectedOrAllLogs(sourceDir)
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("resolve selected EVTX files: %w", err))
	}
	if len(selectedFiles) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no selected or available EVTX files found in %s", sourceDir)}
	}

	quotedFiles := make([]string, 0, len(selectedFiles))
	for _, file := range selectedFiles {
		quotedFiles = append(quotedFiles, utils.PSQuote(file))
	}

	// Perf notes (a full run measured 543.9s for 382 files / ~375k events):
	//   1. Export-Csv was called once per file (382 calls) instead of once for
	//      the whole batch — each call reopens/reformats the output file.
	//   2. $event.LevelDisplayName resolves the severity string via the
	//      provider's message-table resources on every single event, which is
	//      far slower than mapping the small numeric Level enum ourselves.
	// Streaming every event straight into one Export-Csv call, and replacing
	// LevelDisplayName with a local lookup, removes both costs. As a side
	// effect this also fixes a correctness bug where a file with exactly one
	// event was silently dropped: $rows for a single event was a scalar
	// pscustomobject (not an array), so $rows.Count was $null and the
	// "$rows.Count -gt 0" check evaluated false.
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$sourceDir = ` + utils.PSQuote(sourceDir) + `
$outCsv = Join-Path ` + utils.PSQuote(outDir) + ` 'eventlog_records.csv'
$selectedFiles = @(` + strings.Join(quotedFiles, ",\n") + `)
if (Test-Path $outCsv) { Remove-Item -LiteralPath $outCsv -Force }

$levelNames = @{0='LogAlways';1='Critical';2='Error';3='Warning';4='Information';5='Verbose'}

$selectedFiles | ForEach-Object {
    $fileName = $_
    $path = Join-Path $sourceDir $fileName
    if (-not (Test-Path $path)) { return }

    foreach ($event in Get-WinEvent -Oldest -Path $path -ErrorAction SilentlyContinue) {
        $levelName = $levelNames[[int]$event.Level]
        if (-not $levelName) { $levelName = "Level$($event.Level)" }
        [pscustomobject]@{
            SourceFile    = $fileName
            LogName       = $event.LogName
            ProviderName  = $event.ProviderName
            Id            = $event.Id
            Level         = $levelName
            TimeCreated   = $event.TimeCreated
            RecordId      = $event.RecordId
            ProcessId     = $event.ProcessId
            ThreadId      = $event.ThreadId
            MachineName   = $event.MachineName
            UserId        = [string]$event.UserId
            Message       = ''
        }
    }
} | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

if (-not (Test-Path $outCsv)) {
    throw 'no selected EVTX records could be parsed'
}
`

	if err := utils.RunPowerShell(ctx, script); err != nil {
		files, fileErr := utils.CollectGeneratedCSVs(outDir)
		if fileErr == nil && len(files) > 0 {
			return module.AnalyzeResult{Files: files, OutputPath: outDir, Error: fmt.Errorf("parse event logs: %w", err).Error()}
		}
		return analyzerError(outDir, fmt.Errorf("parse event logs: %w", err))
	}

	files, err := utils.CollectGeneratedCSVs(outDir)
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}
