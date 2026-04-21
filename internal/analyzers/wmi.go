package analyzers

import (
	"context"
	"fmt"
	"os"

	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.Register(&wmiParser{}) }

type wmiParser struct{}

func (c *wmiParser) Name() string     { return "wmi_parser" }
func (c *wmiParser) Category() string { return "system" }
func (c *wmiParser) Mode() string     { return module.ModeAnalyzer }
func (c *wmiParser) Description() string {
	return "Parses WMI persistence and namespace inventory into CSV"
}

func (c *wmiParser) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	outDir := module.ModuleDir(outputDir, c)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create WMI parser output dir: %w", err)
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$outDir = ` + psQuote(outDir) + `

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

	if err := runPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("parse WMI data: %w", err)
	}

	return collectGeneratedCSVs(outDir)
}
