package live

import (
	"context"
	"fmt"
	"os"

	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.Register(&processExplorerAnalyzer{}) }

type processExplorerAnalyzer struct{}

func (a *processExplorerAnalyzer) Name() string     { return "process_explorer" }
func (a *processExplorerAnalyzer) Category() string { return "live" }
func (a *processExplorerAnalyzer) Mode() string     { return module.ModeAnalyzer }
func (a *processExplorerAnalyzer) Description() string {
	return "Generates live process, module, and network triage CSV from the running system"
}

func (a *processExplorerAnalyzer) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	outDir := module.ModuleDir(outputDir, a)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create process explorer analyzer output dir: %w", err)
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$outDir = ` + psQuote(outDir) + `

$processCsv = Join-Path $outDir 'processes.csv'
$moduleCsv = Join-Path $outDir 'process_modules.csv'
$connCsv = Join-Path $outDir 'process_connections.csv'

$procs = Get-CimInstance Win32_Process | Sort-Object ProcessId
$procRows = foreach ($p in $procs) {
    $owner = ''
    try {
        $ownerResult = Invoke-CimMethod -InputObject $p -MethodName GetOwner
        if ($ownerResult.ReturnValue -eq 0) {
            $owner = if ($ownerResult.Domain) { "$($ownerResult.Domain)\$($ownerResult.User)" } else { $ownerResult.User }
        }
    } catch {}

    [pscustomobject]@{
        ProcessId       = $p.ProcessId
        ParentProcessId = $p.ParentProcessId
        Name            = $p.Name
        ExecutablePath  = $p.ExecutablePath
        CommandLine     = $p.CommandLine
        CreationDate    = $p.CreationDate
        SessionId       = $p.SessionId
        ThreadCount     = $p.ThreadCount
        HandleCount     = $p.HandleCount
        WorkingSetSize  = $p.WorkingSetSize
        Owner           = $owner
    }
}
$procRows | Export-Csv -Path $processCsv -NoTypeInformation -Encoding UTF8

$moduleRows = foreach ($gp in Get-Process | Sort-Object Id) {
    foreach ($m in $gp.Modules) {
        [pscustomobject]@{
            ProcessId      = $gp.Id
            ProcessName    = $gp.ProcessName
            ModuleName     = $m.ModuleName
            FileName       = $m.FileName
            BaseAddress    = ('0x{0:X}' -f $m.BaseAddress.ToInt64())
            ModuleMemoryMB = [math]::Round($m.ModuleMemorySize / 1MB, 3)
            FileVersion    = $m.FileVersionInfo.FileVersion
            ProductName    = $m.FileVersionInfo.ProductName
            CompanyName    = $m.FileVersionInfo.CompanyName
        }
    }
}
$moduleRows | Export-Csv -Path $moduleCsv -NoTypeInformation -Encoding UTF8

$procMap = @{}
foreach ($p in $procRows) { $procMap[[int]$p.ProcessId] = $p }

function New-ConnRow {
    param(
        [string]$Protocol,
        [int]$ProcessId,
        [string]$LocalAddress,
        [string]$LocalPort,
        [string]$RemoteAddress,
        [string]$RemotePort,
        [string]$State,
        [string]$CreationTime
    )

    $proc = $procMap[[int]$ProcessId]
    [pscustomobject]@{
        Protocol       = $Protocol
        ProcessId      = $ProcessId
        ProcessName    = if ($proc) { $proc.Name } else { '' }
        ExecutablePath = if ($proc) { $proc.ExecutablePath } else { '' }
        CommandLine    = if ($proc) { $proc.CommandLine } else { '' }
        LocalAddress   = $LocalAddress
        LocalPort      = $LocalPort
        RemoteAddress  = $RemoteAddress
        RemotePort     = $RemotePort
        State          = $State
        CreationTime   = $CreationTime
    }
}

function Split-EndPoint {
    param([string]$Endpoint)

    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        return @('', '')
    }
    if ($Endpoint -eq '*:*') {
        return @('*', '*')
    }
    if ($Endpoint -eq '*') {
        return @('*', '')
    }

    $lastColon = $Endpoint.LastIndexOf(':')
    if ($lastColon -lt 0) {
        return @($Endpoint, '')
    }

    $address = $Endpoint.Substring(0, $lastColon)
    $port = $Endpoint.Substring($lastColon + 1)
    return @($address.Trim('[', ']'), $port)
}

function Get-ConnectionRowsFromNetCmdlets {
    $rows = @()

    $tcpCmd = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
    if ($tcpCmd) {
        foreach ($c in Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $rows += New-ConnRow 'TCP' $c.OwningProcess $c.LocalAddress $c.LocalPort $c.RemoteAddress $c.RemotePort $c.State $c.CreationTime
        }
    }

    $udpCmd = Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    if ($udpCmd) {
        foreach ($c in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            $rows += New-ConnRow 'UDP' $c.OwningProcess $c.LocalAddress $c.LocalPort '' '' '' ''
        }
    }

    return $rows
}

function Get-ConnectionRowsFromNetstat {
    $rows = @()
    foreach ($line in netstat -ano) {
        if ($line -match '^\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
            $local = Split-EndPoint $matches[1]
            $remote = Split-EndPoint $matches[2]
            $rows += New-ConnRow 'TCP' ([int]$matches[4]) $local[0] $local[1] $remote[0] $remote[1] $matches[3] ''
            continue
        }
        if ($line -match '^\s*UDP\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
            $local = Split-EndPoint $matches[1]
            $rows += New-ConnRow 'UDP' ([int]$matches[3]) $local[0] $local[1] '' '' '' ''
            continue
        }
        if ($line -match '^\s*UDP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$') {
            $local = Split-EndPoint $matches[1]
            $rows += New-ConnRow 'UDP' ([int]$matches[4]) $local[0] $local[1] '' '' $matches[3] ''
        }
    }
    return $rows
}

$connectionRows = @(Get-ConnectionRowsFromNetCmdlets)
if ($connectionRows.Count -eq 0) {
    $connectionRows = @(Get-ConnectionRowsFromNetstat)
}

$connectionRows | Sort-Object Protocol, ProcessId, LocalAddress, LocalPort, RemoteAddress, RemotePort | Export-Csv -Path $connCsv -NoTypeInformation -Encoding UTF8
`

	if err := runPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("analyze live process data: %w", err)
	}

	return collectGeneratedCSVs(outDir)
}
