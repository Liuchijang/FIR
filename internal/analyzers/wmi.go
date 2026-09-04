package analyzers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/platform"
	"github.com/Liuchijang/Tyto/internal/utils"
	"github.com/Liuchijang/Tyto/internal/wmirepo"
)

func init() { module.RegisterAnalyzer(&wmiParser{}) }

type wmiParser struct{ offlineCapable }

func (c *wmiParser) Name() string     { return "wmi_parser" }
func (c *wmiParser) Category() string { return "system" }
func (c *wmiParser) Description() string {
	return "Parse WMI event subscriptions from a collected repository, and query the live machine when analyzing it"
}

// Analyze reports WMI event-subscription persistence from two independent sources,
// and the split is what lets this run offline at all.
//
//   - The object store. wmirepo carves __FilterToConsumerBinding, __EventFilter and
//     the consumer instances straight out of OBJECTS.DATA, so it works against a
//     collected run and recovers records the repository has already freed. Which
//     store it reads follows the one source rule: the run's collected copy, or the
//     live host's file, or nothing.
//   - A CIM query of root\subscription. Authoritative for what WMI would answer
//     right now, and impossible offline, so it is gated on AllowLive.
//
// This used to be the CIM query alone, which is why the module could not run
// offline and why its name was a misnomer — it never read the wmi collector's
// output at all. The two outputs keep separate file names because they are separate
// evidence: one is what the store holds, including the deleted, and the other is
// what the running service reports.
func (c *wmiParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create WMI parser output dir: %w", err))
	}

	repoFiles, repoErr := c.analyzeRepository(req, outDir)

	if !req.AllowLive() {
		// Offline: the store is the only source there is. A run that did not collect
		// the repository has nothing for this analyzer, which is a fact about the
		// input rather than a failure.
		if repoErr != nil {
			if errors.Is(repoErr, errNoCollectedSource) {
				return skippedNoSource(outDir, "collected WMI repository")
			}
			return analyzerError(outDir, repoErr)
		}
		return module.AnalyzeResult{Files: repoFiles, OutputPath: outDir}
	}

	liveFiles, liveErr := c.analyzeLive(ctx, outDir)

	files := append(repoFiles, liveFiles...)
	switch {
	case len(files) == 0 && liveErr != nil:
		return analyzerError(outDir, liveErr)
	case len(files) == 0 && repoErr != nil:
		return analyzerError(outDir, repoErr)
	}
	// Partial success stays success and says what was lost, because the two sources
	// fail for unrelated reasons: a locked or absent object store does not stop the
	// CIM query, and a host that refuses the query still has a store to carve.
	return module.AnalyzeResult{
		Files:      files,
		OutputPath: outDir,
		Error:      joinAnalyzerWarnings(repoErr, liveErr),
	}
}

// joinAnalyzerWarnings renders the errors that did not stop the run.
func joinAnalyzerWarnings(errs ...error) string {
	var parts []string
	for _, err := range errs {
		if err != nil && !errors.Is(err, errNoCollectedSource) {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}

func (c *wmiParser) analyzeLive(ctx context.Context, outDir string) ([]module.FileInfo, error) {
	before, err := utils.CollectGeneratedCSVs(outDir)
	if err != nil {
		return nil, err
	}
	written := make(map[string]bool, len(before))
	for _, fi := range before {
		written[fi.Path] = true
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$outDir = ` + utils.PSQuote(outDir) + `

$filtersCsv = Join-Path $outDir 'wmi_event_filters.csv'
$consumersCsv = Join-Path $outDir 'wmi_event_consumers.csv'
$bindingsCsv = Join-Path $outDir 'wmi_filter_bindings.csv'
$namespacesCsv = Join-Path $outDir 'wmi_namespaces.csv'

$filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
    Select-Object Name, EventNamespace, QueryLanguage, Query, CreatorSID
$filters | Export-Csv -Path $filtersCsv -NoTypeInformation -Encoding UTF8

$consumerClasses = @(
    'CommandLineEventConsumer',
    'ActiveScriptEventConsumer',
    'LogFileEventConsumer',
    'NTEventLogEventConsumer',
    'SMTPEventConsumer'
)

$consumerRows = foreach ($className in $consumerClasses) {
    foreach ($item in Get-CimInstance -Namespace root\subscription -ClassName $className -ErrorAction SilentlyContinue) {
        [pscustomobject]@{
            ClassName            = $className
            Name                 = $item.Name
            ExecutablePath       = $item.ExecutablePath
            CommandLineTemplate  = $item.CommandLineTemplate
            ScriptFileName       = $item.ScriptFileName
            ScriptingEngine      = $item.ScriptingEngine
            ScriptText           = $item.ScriptText
            Filename             = $item.Filename
            Text                 = $item.Text
            Category             = $item.Category
            EventID              = $item.EventID
            Subject              = $item.Subject
            SMTPServer           = $item.SMTPServer
            ToLine               = $item.ToLine
        }
    }
}
$consumerRows | Export-Csv -Path $consumersCsv -NoTypeInformation -Encoding UTF8

$bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object Filter, Consumer, DeliverSynchronously, MaintainSecurityContext, SlowDownProviders
$bindings | Export-Csv -Path $bindingsCsv -NoTypeInformation -Encoding UTF8

function Get-WmiNamespaceRows {
    param([string]$Namespace)

    $rows = @()
    $rows += [pscustomobject]@{ Namespace = $Namespace }

    foreach ($child in Get-CimInstance -Namespace $Namespace -ClassName __Namespace -ErrorAction SilentlyContinue) {
        $childNamespace = $Namespace + '\' + $child.Name
        $rows += Get-WmiNamespaceRows -Namespace $childNamespace
    }

    return $rows
}

Get-WmiNamespaceRows -Namespace 'root' |
    Sort-Object Namespace -Unique |
    Export-Csv -Path $namespacesCsv -NoTypeInformation -Encoding UTF8
`

	if err := utils.RunPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("query live WMI subscriptions: %w", err)
	}

	after, err := utils.CollectGeneratedCSVs(outDir)
	if err != nil {
		return nil, err
	}
	// Only the files this half produced. CollectGeneratedCSVs lists the whole
	// directory, so without the diff the repository CSVs written a moment ago would
	// be counted a second time and appear twice in the manifest.
	var files []module.FileInfo
	for _, fi := range after {
		if !written[fi.Path] {
			files = append(files, fi)
		}
	}
	return files, nil
}

// analyzeRepository carves the object store this run is entitled to read.
func (c *wmiParser) analyzeRepository(req module.AnalyzeRequest, outDir string) ([]module.FileInfo, error) {
	sourceDir, live, err := resolveArtifactSource(req, "wmi")
	if err != nil {
		return nil, err
	}

	objectsPath := filepath.Join(sourceDir, wmiObjectStoreName)
	if live {
		objectsPath = filepath.Join(platform.SystemRoot(), "System32", "wbem", "Repository", wmiObjectStoreName)
	}
	if _, err := os.Stat(objectsPath); err != nil {
		// Live, the store is simply where Windows keeps it; collected, its absence
		// means the run holds a repository directory without the file that matters.
		return nil, fmt.Errorf("%s not available at %s: %w", wmiObjectStoreName, objectsPath, errNoCollectedSource)
	}

	result, err := wmirepo.Scan(objectsPath)
	if err != nil {
		return nil, err
	}
	return writeWMIRepositoryCSVs(outDir, result)
}

const wmiObjectStoreName = "OBJECTS.DATA"

// writeWMIRepositoryCSVs renders the carve.
//
// No column here is named after a timestamp because the carve recovers none: the
// object store keeps no creation time for a subscription, and inventing a column the
// data cannot fill is how an importer ends up rejecting the file.
func writeWMIRepositoryCSVs(outDir string, result wmirepo.Result) ([]module.FileInfo, error) {
	bindings := make([][]string, 0, len(result.Bindings))
	for _, b := range result.Bindings {
		query, found := result.QueryFor(b.FilterName)
		bindings = append(bindings, []string{
			b.ConsumerType,
			b.ConsumerName,
			b.FilterName,
			query,
			strconv.FormatBool(found),
			strconv.FormatBool(b.Paired),
			strconv.FormatInt(b.Offset, 10),
		})
	}

	filters := make([][]string, 0, len(result.Filters))
	for _, f := range result.Filters {
		filters = append(filters, []string{
			f.Name, f.Namespace, f.Query, f.QueryLanguage, strconv.FormatInt(f.Offset, 10),
		})
	}

	consumers := make([][]string, 0, len(result.Consumers))
	for _, c := range result.Consumers {
		consumers = append(consumers, []string{
			c.Type, c.Name, strings.Join(c.Payload, " | "), strconv.FormatInt(c.Offset, 10),
		})
	}

	// Written even when empty. "No subscription persistence in this store" is a
	// finding an analyst needs stated, and an absent file cannot distinguish it from
	// an analyzer that never ran.
	sets := []struct {
		name    string
		headers []string
		rows    [][]string
	}{
		{"wmi_repository_bindings.csv", []string{
			"ConsumerType", "ConsumerName", "FilterName", "FilterQuery",
			"FilterRecordFound", "BothReferencesPresent", "StoreOffset",
		}, bindings},
		{"wmi_repository_filters.csv", []string{
			"Name", "EventNamespace", "Query", "QueryLanguage", "StoreOffset",
		}, filters},
		{"wmi_repository_consumers.csv", []string{
			"ConsumerType", "Name", "CarvedFields", "StoreOffset",
		}, consumers},
	}

	var files []module.FileInfo
	for _, set := range sets {
		fi, err := writeCSV(filepath.Join(outDir, set.name), set.headers, set.rows)
		if err != nil {
			return files, err
		}
		files = append(files, fi)
	}
	return files, nil
}
