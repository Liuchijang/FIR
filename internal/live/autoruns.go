package live

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Liuchijang/FIR/internal/collector"
)

func init() { collector.Register(&autorunsCollector{}) }

type autorunsCollector struct{}

func (c *autorunsCollector) Name() string     { return "autoruns" }
func (c *autorunsCollector) Category() string { return "live" }
func (c *autorunsCollector) Description() string {
	return "Collects live autoruns-style persistence data for services, Run keys, startup folders, and scheduled tasks into CSV"
}

func (c *autorunsCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	outDir := filepath.Join(outputDir, "live", "autoruns")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create autoruns output dir: %w", err)
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$outDir = ` + psQuote(outDir) + `

$servicesCsv = Join-Path $outDir 'services.csv'
$runKeysCsv = Join-Path $outDir 'run_keys.csv'
$tasksCsv = Join-Path $outDir 'scheduled_tasks.csv'
$startupCsv = Join-Path $outDir 'startup_folder.csv'

$services = Get-CimInstance Win32_Service | Sort-Object Name | Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName, ServiceType
$services | Export-Csv -Path $servicesCsv -NoTypeInformation -Encoding UTF8

$runLocations = @(
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
    'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)

$sidHives = Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-' }
foreach ($sid in $sidHives) {
    $base = 'Registry::HKEY_USERS\' + $sid.PSChildName
    $runLocations += @(
        ($base + '\Software\Microsoft\Windows\CurrentVersion\Run'),
        ($base + '\Software\Microsoft\Windows\CurrentVersion\RunOnce'),
        ($base + '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'),
        ($base + '\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run')
    )
}

$runRows = foreach ($path in $runLocations | Sort-Object -Unique) {
    if (-not (Test-Path $path)) { continue }
    $item = Get-ItemProperty -Path $path
    foreach ($prop in $item.PSObject.Properties) {
        if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
        [pscustomobject]@{
            Location = $path
            EntryName = $prop.Name
            Command = [string]$prop.Value
        }
    }
}
$runRows | Export-Csv -Path $runKeysCsv -NoTypeInformation -Encoding UTF8

$tasks = foreach ($task in Get-ScheduledTask) {
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    $actions = ($task.Actions | ForEach-Object {
        if ($_.Execute) {
            if ($_.Arguments) { $_.Execute + ' ' + $_.Arguments } else { $_.Execute }
        }
    }) -join ' | '
    [pscustomobject]@{
        TaskName      = $task.TaskName
        TaskPath      = $task.TaskPath
        State         = $info.State
        LastRunTime   = $info.LastRunTime
        NextRunTime   = $info.NextRunTime
        LastTaskResult= $info.LastTaskResult
        Author        = $task.Principal.UserId
        RunLevel      = $task.Principal.RunLevel
        Description   = $task.Description
        Actions       = $actions
        Triggers      = (($task.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ' | ')
    }
}
$tasks | Sort-Object TaskPath, TaskName | Export-Csv -Path $tasksCsv -NoTypeInformation -Encoding UTF8

$startupLocations = @(
    [pscustomobject]@{ Scope = 'AllUsers'; Path = [Environment]::GetFolderPath('CommonStartup') },
    [pscustomobject]@{ Scope = 'CurrentUser'; Path = [Environment]::GetFolderPath('Startup') }
)

$userProfileRoot = Join-Path $env:SystemDrive 'Users'
Get-ChildItem -Path $userProfileRoot -Directory |
    Where-Object { $_.Name -notin '.', '..', 'Public', 'Default', 'Default User', 'All Users', 'DefaultAppPool' } |
    ForEach-Object {
    $startupPath = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    $startupLocations += [pscustomobject]@{ Scope = $_.Name; Path = $startupPath }
}

$startupRows = foreach ($loc in $startupLocations) {
    if (-not (Test-Path $loc.Path)) { continue }
    Get-ChildItem -Path $loc.Path -Force | ForEach-Object {
        [pscustomobject]@{
            Scope        = $loc.Scope
            StartupPath  = $loc.Path
            Name         = $_.Name
            FullName     = $_.FullName
            Length       = if ($_.PSIsContainer) { '' } else { $_.Length }
            LastWriteTime= $_.LastWriteTime
            IsDirectory  = $_.PSIsContainer
        }
    }
}
$startupRows | Sort-Object Scope, Name | Export-Csv -Path $startupCsv -NoTypeInformation -Encoding UTF8
`

	if err := runPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("collect live autoruns data: %w", err)
	}

	return collectGeneratedCSVs(outDir)
}
