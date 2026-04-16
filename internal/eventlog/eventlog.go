// Package eventlog implements the Windows Event Log (.evtx) collector.
package eventlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fir/fir/internal/collector"
	"github.com/fir/fir/internal/logging"
	"github.com/fir/fir/internal/utils"
)

func init() {
	collector.Register(&eventLogCollector{})
}

type eventLogCollector struct{}

func (c *eventLogCollector) Name() string        { return "eventlog" }
func (c *eventLogCollector) Category() string     { return "eventlog" }
func (c *eventLogCollector) Description() string {
	return "Collects Windows Event Log files (.evtx) from System32\\winevt\\Logs"
}

// priorityLogs are the most forensically relevant event logs, collected first.
var priorityLogs = []string{
	"Security",
	"System",
	"Application",
	"Microsoft-Windows-PowerShell%4Operational",
	"Microsoft-Windows-Sysmon%4Operational",
	"Microsoft-Windows-TaskScheduler%4Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
	"Microsoft-Windows-Windows Defender%4Operational",
	"Microsoft-Windows-WMI-Activity%4Operational",
	"Microsoft-Windows-Bits-Client%4Operational",
}

func (c *eventLogCollector) Collect(ctx context.Context, outputDir string) error {
	log := logging.G()
	outDir := filepath.Join(outputDir, "eventlog")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create eventlog output dir: %w", err)
	}

	evtxDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	entries, err := os.ReadDir(evtxDir)
	if err != nil {
		return fmt.Errorf("read event log directory: %w", err)
	}

	// Filter to .evtx files and sort by priority.
	var evtxFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".evtx") {
			evtxFiles = append(evtxFiles, e.Name())
		}
	}

	// Sort: priority logs first, then alphabetical.
	sort.Slice(evtxFiles, func(i, j int) bool {
		iPriority := getPriority(evtxFiles[i])
		jPriority := getPriority(evtxFiles[j])
		if iPriority != jPriority {
			return iPriority < jPriority
		}
		return evtxFiles[i] < evtxFiles[j]
	})

	var allFiles []collector.FileInfo
	var errorCount int

	for _, name := range evtxFiles {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		src := filepath.Join(evtxDir, name)
		dst := filepath.Join(outDir, name)

		fi, err := utils.SafeCopyFile(src, dst)
		if err != nil {
			errorCount++
			log.Debug(fmt.Sprintf("Failed to copy event log %s: %v", name, err))
			continue
		}
		allFiles = append(allFiles, fi)
	}

	if len(allFiles) == 0 {
		return fmt.Errorf("no event log files collected (%d errors)", errorCount)
	}

	return nil
}

// getPriority returns a sort priority for the given log file (lower = higher priority).
func getPriority(filename string) int {
	baseName := strings.TrimSuffix(filename, ".evtx")
	for i, p := range priorityLogs {
		if strings.EqualFold(baseName, p) {
			return i
		}
	}
	return len(priorityLogs) + 1 // Non-priority logs sorted after.
}
