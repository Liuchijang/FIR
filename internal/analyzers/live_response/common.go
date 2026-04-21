package live

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func runPowerShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func collectGeneratedCSVs(dir string) ([]module.FileInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read output dir %s: %w", dir, err)
	}

	var files []module.FileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".csv") {
			continue
		}

		fi, err := utils.FileInfoFromPath(filepath.Join(dir, entry.Name()))
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
