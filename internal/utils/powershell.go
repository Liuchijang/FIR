package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
)

// RunPowerShell executes script via a non-interactive powershell.exe, returning
// combined stdout/stderr on failure so callers can surface the real cause.
func RunPowerShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

func PSQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// PSTimestampFunction defines ConvertTo-TytoUtc, the PowerShell counterpart of
// the analyzers' formatTime.
//
// Every timestamp Tyto writes is RFC3339 in UTC, and a column named after a
// timestamp holds one of those or nothing at all. A PowerShell-hosted analyzer
// gets neither for free: piping a DateTime into Export-Csv renders it with the
// session's current culture, so the same column came out "7/12/2026 9:14:02 AM"
// on one host and would come out "12/07/2026 09:14:02" on another — not
// joinable against the Go-side analyzers, and rejected outright by an importer
// that types the column.
//
// Scripts prepend this and wrap every date-bearing property in it.
const PSTimestampFunction = `
function ConvertTo-TytoUtc {
    param($Value)

    if ($null -eq $Value) { return '' }
    $dt = $Value -as [datetime]
    if ($null -eq $dt) { return '' }
    # Get-NetTCPConnection reports an unset CreationTime as FILETIME zero, which
    # surfaces as a real DateTime in 1601 and would otherwise be exported as a
    # connection opened four centuries ago.
    if ($dt.Year -lt 1602 -or $dt.Year -gt 9999) { return '' }
    if ($dt.Kind -eq [System.DateTimeKind]::Unspecified) {
        $dt = [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Local)
    }
    return $dt.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
}
`

// CollectGeneratedCSVs returns FileInfo for every .csv file directly inside
// dir, sorted by path. Used by analyzers that let a PowerShell script write
// its own CSV output via Export-Csv rather than through Go's csv package.
func CollectGeneratedCSVs(dir string) ([]module.FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read output dir %s: %w", dir, err)
	}

	var files []module.FileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".csv") {
			continue
		}

		fi, err := FileInfoFromPath(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		files = append(files, fi)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	if len(files) == 0 {
		return nil, fmt.Errorf("no CSV files generated in %s", dir)
	}
	return files, nil
}
