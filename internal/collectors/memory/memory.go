// Package memory implements the RAM acquisition collector using winpmem.
package memory

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.RegisterArtifact("memory", &memoryCollector{}) }

type memoryCollector struct{}

func (c *memoryCollector) Name() string { return "ram" }
func (c *memoryCollector) Description() string {
	return "Collect memory"
}

func winpmemBinaries() []string {
	if runtime.GOARCH == "amd64" {
		return []string{"winpmem_mini_x64.exe", "winpmem_x64.exe", "winpmem.exe"}
	}
	return []string{"winpmem_mini_x86.exe", "winpmem_x86.exe", "winpmem.exe"}
}

func (c *memoryCollector) Collect(ctx context.Context, req module.CollectRequest) module.CollectResult {
	log := logging.G()
	outDir, err := req.EnsureOutputDir("memory")
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("create memory output dir: %w", err).Error()}
	}

	winpmemPath, err := findWinpmem()
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("winpmem not found: %w\nPlace winpmem in the same directory as FIR or add it to PATH", err).Error()}
	}
	// Info, not Debug: the imaging tool is part of the acquisition's chain of
	// custody, and findWinpmem picks it from three different places. Which
	// binary produced the image has to be in collector.log without needing
	// -verbose to have been passed.
	log.Info(fmt.Sprintf("Acquiring memory with %s", winpmemPath))

	outputPath := filepath.Join(outDir, "memory.raw")
	cmd := exec.CommandContext(ctx, winpmemPath, outputPath)
	// winpmem reports why it refused (no driver signature, PAGE_SIZE mismatch,
	// destination unwritable) on its own streams; without them the run records
	// only an exit status for a failed memory acquisition.
	var toolOutput bytes.Buffer
	cmd.Stdout = &toolOutput
	cmd.Stderr = &toolOutput
	if err := cmd.Run(); err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("winpmem execution failed: %w\nOutput: %s", err, strings.TrimSpace(toolOutput.String())).Error()}
	}

	stat, err := os.Stat(outputPath)
	if err != nil {
		return module.CollectResult{OutputPath: outDir, Error: fmt.Errorf("verify memory dump: %w", err).Error()}
	}
	if stat.Size() == 0 {
		return module.CollectResult{OutputPath: outDir, Error: "memory dump is empty (0 bytes)"}
	}

	// This is the one artifact FIR cannot hash while writing it — winpmem writes
	// the image from a child process — so the digest costs a second full pass.
	hash, err := utils.HashFile(outputPath)
	hashErr := ""
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to hash memory dump: %v", err))
		// An unhashed image is still evidence, but the manifest must not imply
		// it was verified. The SHA-256 stays empty and the failure is returned
		// alongside the file so it shows up as a warning on the run instead of
		// only in the log.
		hash = ""
		hashErr = fmt.Errorf("memory image collected but not hashed: %w", err).Error()
	}

	log.Debug(fmt.Sprintf("RAM acquired: %d bytes, SHA256: %s", stat.Size(), hash))
	return module.CollectResult{
		Files:      []module.FileInfo{{Path: "memory.raw", SHA256: hash, Size: stat.Size()}},
		OutputPath: outDir,
		Error:      hashErr,
	}
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
