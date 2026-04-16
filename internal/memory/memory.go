// Package memory implements the RAM acquisition collector using winpmem.
package memory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() { collector.Register(&memoryCollector{}) }

type memoryCollector struct{}

func (c *memoryCollector) Name() string     { return "ram" }
func (c *memoryCollector) Category() string { return "memory" }
func (c *memoryCollector) Description() string {
	return "Acquires physical memory (RAM) using winpmem (must be present in PATH or tool directory)"
}

func winpmemBinaries() []string {
	if runtime.GOARCH == "amd64" {
		return []string{"winpmem_mini_x64.exe", "winpmem_x64.exe", "winpmem.exe"}
	}
	return []string{"winpmem_mini_x86.exe", "winpmem_x86.exe", "winpmem.exe"}
}

func (c *memoryCollector) Collect(ctx context.Context, outputDir string) ([]collector.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "memory")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create memory output dir: %w", err)
	}

	winpmemPath, err := findWinpmem()
	if err != nil {
		return nil, fmt.Errorf("winpmem not found: %w\nPlace winpmem in the same directory as FIR or add it to PATH", err)
	}
	log.Debug(fmt.Sprintf("Using winpmem: %s", winpmemPath))

	outputPath := filepath.Join(outDir, "memory.raw")
	cmd := exec.CommandContext(ctx, winpmemPath, outputPath)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("winpmem execution failed: %w", err)
	}

	stat, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("verify memory dump: %w", err)
	}
	if stat.Size() == 0 {
		return nil, fmt.Errorf("memory dump is empty (0 bytes)")
	}

	hash, err := utils.HashFile(outputPath)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash memory dump: %v", err))
		hash = "HASH_FAILED"
	}

	log.Debug(fmt.Sprintf("RAM acquired: %d bytes, SHA256: %s", stat.Size(), hash))
	return []collector.FileInfo{{Path: "memory.raw", SHA256: hash, Size: stat.Size()}}, nil
}

func findWinpmem() (string, error) {
	binaries := winpmemBinaries()
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		for _, bin := range binaries {
			candidate := filepath.Join(exeDir, bin)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		for _, bin := range binaries {
			candidate := filepath.Join(cwd, bin)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	for _, bin := range binaries {
		if p, err := exec.LookPath(bin); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("winpmem executable not found (searched: %v)", binaries)
}
