package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.Register(&amcacheParser{}) }

type amcacheParser struct{}

func (c *amcacheParser) Name() string     { return "amcache_parser" }
func (c *amcacheParser) Category() string { return "execution" }
func (c *amcacheParser) Mode() string     { return module.ModeAnalyzer }
func (c *amcacheParser) Description() string {
	return "Parses Amcache into flattened CSV rows from a collected hive or the live mounted hive"
}

func (c *amcacheParser) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	outDir := module.ModuleDir(outputDir, c)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create amcache parser output dir: %w", err)
	}

	sourceBase := `Registry::HKEY_LOCAL_MACHINE\AMCACHE`
	loadHive := false
	hivePath := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	if dir, ok := existingModuleDir(outputDir, "amcache"); ok {
		collected := filepath.Join(dir, "Amcache.hve")
		if _, err := os.Stat(collected); err == nil {
			hivePath = collected
			loadHive = true
		}
	}

	mountName := fmt.Sprintf("FIR_AMCACHE_%d", time.Now().UnixNano())
	script := `
$ErrorActionPreference = 'Stop'
$base = ` + psQuote(sourceBase) + `
$outCsv = Join-Path ` + psQuote(outDir) + ` 'amcache_values.csv'

function Expand-AmcacheValues {
    param(
        [string]$RootLabel,
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return @()
    }

    $targets = @((Get-Item -LiteralPath $LiteralPath))
    $targets += Get-ChildItem -LiteralPath $LiteralPath -Recurse -ErrorAction SilentlyContinue

    $rows = foreach ($item in $targets) {
        $props = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            [pscustomobject]@{
                Section   = $RootLabel
                KeyPath   = $item.Name
                ValueName = $prop.Name
                ValueData = [string]$prop.Value
            }
        }
    }

    return $rows
}
`
	if loadHive {
		script += `
$hivePath = ` + psQuote(hivePath) + `
$mountName = ` + psQuote(mountName) + `
$mountKey = 'HKLM\' + $mountName
$base = 'Registry::HKEY_LOCAL_MACHINE\' + $mountName

& reg.exe load $mountKey $hivePath | Out-Null
try {
`
	}

	script += `
    $rows = @()
    $rows += Expand-AmcacheValues -RootLabel 'InventoryApplication' -LiteralPath (Join-Path $base 'Root\InventoryApplication')
    $rows += Expand-AmcacheValues -RootLabel 'InventoryApplicationFile' -LiteralPath (Join-Path $base 'Root\InventoryApplicationFile')
    $rows += Expand-AmcacheValues -RootLabel 'InventoryApplicationShortcut' -LiteralPath (Join-Path $base 'Root\InventoryApplicationShortcut')
    $rows += Expand-AmcacheValues -RootLabel 'InventoryDriverBinary' -LiteralPath (Join-Path $base 'Root\InventoryDriverBinary')
    $rows += Expand-AmcacheValues -RootLabel 'InventoryDeviceContainer' -LiteralPath (Join-Path $base 'Root\InventoryDeviceContainer')

    if (-not $rows -or $rows.Count -eq 0) {
        throw 'no Amcache values could be extracted from the available hive source'
    }

    $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
}
`
	if loadHive {
		script += `
finally {
    & reg.exe unload $mountKey | Out-Null
}
`
	}

	if err := runPowerShell(ctx, script); err != nil {
		return nil, fmt.Errorf("parse Amcache hive: %w", err)
	}

	return collectGeneratedCSVs(outDir)
}
