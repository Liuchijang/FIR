package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.RegisterAnalyzer(&eventLogParser{}) }

type eventLogParser struct{}

func (c *eventLogParser) Name() string     { return "eventlog_parser" }
func (c *eventLogParser) Category() string { return "eventlog" }
func (c *eventLogParser) Description() string {
	return "Parse EVTX logs"
}

func (c *eventLogParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir := req.AnalyzerDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "Analyzer", c.Name())
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create eventlog parser output dir: %w", err).Error()}
	}

	sourceDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	if dir, ok := existingModuleDir(req.OutputDir, "eventlog"); ok {
		sourceDir = dir
	}
	selectedFiles, err := eventlogpkg.ResolveSelectedOrAllLogs(sourceDir)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("resolve selected EVTX files: %w", err).Error()}
	}
	if len(selectedFiles) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no selected or available EVTX files found in %s", sourceDir)}
	}

	quotedFiles := make([]string, 0, len(selectedFiles))
	for _, file := range selectedFiles {
		quotedFiles = append(quotedFiles, psQuote(file))
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$sourceDir = ` + psQuote(sourceDir) + `
$outCsv = Join-Path ` + psQuote(outDir) + ` 'eventlog_records.csv'
$selectedFiles = @(` + strings.Join(quotedFiles, ",\n") + `)
if (Test-Path $outCsv) { Remove-Item -LiteralPath $outCsv -Force }

$written = 0
foreach ($fileName in $selectedFiles) {
    $path = Join-Path $sourceDir $fileName
    if (-not (Test-Path $path)) { continue }

    $rows = foreach ($event in Get-WinEvent -Oldest -Path $path -ErrorAction SilentlyContinue) {
        [pscustomobject]@{
            SourceFile    = $fileName
            LogName       = $event.LogName
            ProviderName  = $event.ProviderName
            Id            = $event.Id
            Level         = $event.LevelDisplayName
            TimeCreated   = $event.TimeCreated
            RecordId      = $event.RecordId
            ProcessId     = $event.ProcessId
            ThreadId      = $event.ThreadId
            MachineName   = $event.MachineName
            UserId        = [string]$event.UserId
            Message       = ''
        }
    }

    if ($rows -and $rows.Count -gt 0) {
        if ($written -eq 0) {
            $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
        } else {
            $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Append
        }
        $written += $rows.Count
    }
}

if ($written -eq 0) {
    throw 'no selected EVTX records could be parsed'
}
`

	if err := runPowerShell(ctx, script); err != nil {
		files, fileErr := collectGeneratedCSVs(outDir)
		if fileErr == nil && len(files) > 0 {
			return module.AnalyzeResult{Files: files, OutputPath: outDir, Error: fmt.Errorf("parse event logs: %w", err).Error()}
		}
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("parse event logs: %w", err).Error()}
	}

	files, err := collectGeneratedCSVs(outDir)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}
