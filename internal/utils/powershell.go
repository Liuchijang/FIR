package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
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

// PSQuote single-quotes value for safe interpolation into a PowerShell script.
func PSQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

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
