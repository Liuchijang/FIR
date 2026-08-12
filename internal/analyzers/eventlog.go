package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eventlogpkg "github.com/Liuchijang/Tyto/internal/collectors/eventlog"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
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

	// The per-event work runs in a compiled helper rather than in PowerShell: a
	// [pscustomobject] per event piped into Export-Csv spends most of its time in
	// PowerShell's object pipeline and Export-Csv's per-property reflection. On a
	// 3-file, 86,694-event corpus this went from 19.1s to 1.7s, byte-for-byte
	// identical output. EventLogReader yields the same EventRecord objects
	// Get-WinEvent wraps, and the writer reproduces Export-Csv's format exactly:
	// UTF-8 with BOM, CRLF, every field quoted and embedded quotes doubled. The
	// header is written with the first row on purpose: an empty pipeline left
	// Export-Csv with a BOM-only file and a successful result, which a zero-event
	// run must still produce.
	//
	// Values are rendered with the invariant culture rather than the session's.
	// Export-Csv used the current one, which made TimeCreated whatever the
	// operator's regional settings happened to say — "8/12/2026 1:52:11 AM" on one
	// host, "12/08/2026 01:52:11" on another, and neither joinable against the
	// RFC3339 every other analyzer writes. The round-trip "o" format is that same
	// RFC3339, and it is taken in UTC because a local-time column silently
	// misorders events across a DST boundary.
	//
	// Do not reintroduce $event.LevelDisplayName here: it resolves the severity
	// string from the provider's message-table resources per event, which is far
	// slower than mapping the numeric Level enum.
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$sourceDir = ` + utils.PSQuote(sourceDir) + `
$outCsv = Join-Path ` + utils.PSQuote(outDir) + ` 'eventlog_records.csv'
$selectedFiles = [string[]]@(` + strings.Join(quotedFiles, ",\n") + `)
if (Test-Path $outCsv) { Remove-Item -LiteralPath $outCsv -Force }

Add-Type -ReferencedAssemblies 'System.Core' -TypeDefinition @'
using System;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Text;

public static class FirEvtx
{
    static readonly string[] LevelNames = { "LogAlways", "Critical", "Error", "Warning", "Information", "Verbose" };

    static void Field(StringBuilder sb, string value, bool last)
    {
        sb.Append('"');
        if (value != null)
        {
            if (value.IndexOf('"') >= 0) sb.Append(value.Replace("\"", "\"\""));
            else sb.Append(value);
        }
        sb.Append('"');
        if (!last) sb.Append(',');
    }

    static string Num(long? value)
    {
        return value.HasValue ? value.Value.ToString(CultureInfo.InvariantCulture) : null;
    }

    // Utc renders an event's timestamp as RFC3339 in UTC, the one layout every
    // Tyto analyzer writes. "o" keeps the 100ns precision an EVTX record carries,
    // which is what keeps events inside the same second in the order they
    // happened.
    static string Utc(DateTime? value)
    {
        return value.HasValue
            ? value.Value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)
            : null;
    }

    public static long Export(string sourceDir, string outCsv, string[] files)
    {
        long rows = 0;
        using (var w = new StreamWriter(outCsv, false, new UTF8Encoding(true)))
        {
            w.NewLine = "\r\n";

            var sb = new StringBuilder(512);
            foreach (var fileName in files)
            {
                var path = Path.Combine(sourceDir, fileName);
                if (!File.Exists(path)) continue;

                EventLogReader reader;
                try
                {
                    var query = new EventLogQuery(path, PathType.FilePath);
                    query.ReverseDirection = false;
                    reader = new EventLogReader(query);
                }
                catch { continue; }

                using (reader)
                {
                    while (true)
                    {
                        EventRecord rec;
                        try { rec = reader.ReadEvent(); }
                        catch { break; }
                        if (rec == null) break;

                        using (rec)
                        {
                            try
                            {
                                int level = rec.Level.HasValue ? rec.Level.Value : 0;
                                string levelName = level < LevelNames.Length
                                    ? LevelNames[level]
                                    : "Level" + level.ToString(CultureInfo.InvariantCulture);

                                if (rows == 0)
                                {
                                    w.WriteLine("\"SourceFile\",\"LogName\",\"ProviderName\",\"Id\",\"Level\",\"TimeCreatedUTC\",\"RecordId\",\"ProcessId\",\"ThreadId\",\"MachineName\",\"UserId\",\"Message\"");
                                }

                                sb.Length = 0;
                                Field(sb, fileName, false);
                                Field(sb, rec.LogName, false);
                                Field(sb, rec.ProviderName, false);
                                Field(sb, rec.Id.ToString(CultureInfo.InvariantCulture), false);
                                Field(sb, levelName, false);
                                Field(sb, Utc(rec.TimeCreated), false);
                                Field(sb, Num(rec.RecordId), false);
                                Field(sb, Num(rec.ProcessId), false);
                                Field(sb, Num(rec.ThreadId), false);
                                Field(sb, rec.MachineName, false);
                                Field(sb, rec.UserId != null ? rec.UserId.ToString() : null, false);
                                Field(sb, "", true);
                                w.WriteLine(sb.ToString());
                                rows++;
                            }
                            catch { }
                        }
                    }
                }
            }
        }
        return rows;
    }
}
'@

[FirEvtx]::Export($sourceDir, $outCsv, $selectedFiles) | Out-Null

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
