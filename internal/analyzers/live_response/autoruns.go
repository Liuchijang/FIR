package live

import (
	"context"
	"fmt"

	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
)

func init() { module.RegisterAnalyzer(&autorunsAnalyzer{}) }

type autorunsAnalyzer struct{}

func (a *autorunsAnalyzer) Name() string     { return "autoruns" }
func (a *autorunsAnalyzer) Category() string { return "live" }
func (a *autorunsAnalyzer) Description() string {
	return "Live autoruns triage"
}

func (a *autorunsAnalyzer) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(a.Name())
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create autoruns analyzer output dir: %w", err).Error()}
	}
	// Services, run keys and scheduled tasks are read out of the running system,
	// so there is nothing here an offline run could point at.
	if !req.AllowLive() {
		return module.LiveOnlyResult(outDir, a.Name())
	}

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$outDir = ` + utils.PSQuote(outDir) + `
` + utils.PSTimestampFunction + `

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
        LastRunTimeUTC = ConvertTo-TytoUtc $info.LastRunTime
        NextRunTimeUTC = ConvertTo-TytoUtc $info.NextRunTime
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
            LastWriteTimeUTC = ConvertTo-TytoUtc $_.LastWriteTime
            IsDirectory  = $_.PSIsContainer
        }
    }
}
$startupRows | Sort-Object Scope, Name | Export-Csv -Path $startupCsv -NoTypeInformation -Encoding UTF8
`

	if err := utils.RunPowerShell(ctx, script); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("analyze live autoruns data: %w", err).Error()}
	}

	files, err := utils.CollectGeneratedCSVs(outDir)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}
