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

func init() { module.Register(&eventLogParser{}) }

type eventLogParser struct{}

func (c *eventLogParser) Name() string     { return "eventlog_parser" }
func (c *eventLogParser) Category() string { return "eventlog" }
func (c *eventLogParser) Mode() string     { return module.ModeAnalyzer }
func (c *eventLogParser) Description() string {
	return "Parse EVTX logs"
}

func (c *eventLogParser) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	outDir := module.ModuleDir(outputDir, c)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create eventlog parser output dir: %w", err)
	}

	sourceDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	if dir, ok := existingModuleDir(outputDir, "eventlog"); ok {
		sourceDir = dir
	}
	selectedFiles, err := eventlogpkg.ResolveSelectedOrAllLogs(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("resolve selected EVTX files: %w", err)
	}
	if len(selectedFiles) == 0 {
		return nil, fmt.Errorf("no selected or available EVTX files found in %s", sourceDir)
	}

	quotedFiles := make([]string, 0, len(selectedFiles))
	for _, file := range selectedFiles {
		quotedFiles = append(quotedFiles, psQuote(file))
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$sourceDir = ` + psQuote(sourceDir) + `
$outCsv = Join-Path ` + psQuote(outDir) + ` 'eventlog_records.csv'
$selectedFiles = @(` + strings.Join(quotedFiles, ",\n") + `)

$rows = foreach ($fileName in $selectedFiles) {
    $path = Join-Path $sourceDir $fileName
    if (-not (Test-Path $path)) { continue }

    foreach ($event in Get-WinEvent -Oldest -Path $path -ErrorAction SilentlyContinue) {
        $message = ''
        try { $message = $event.FormatDescription() } catch {}

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
            Message       = $message
        }
    }
}

if (-not $rows -or $rows.Count -eq 0) {
    throw 'no selected EVTX records could be parsed'
}

$rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
`

	if err := runPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("parse event logs: %w", err)
	}

	return collectGeneratedCSVs(outDir)
}
