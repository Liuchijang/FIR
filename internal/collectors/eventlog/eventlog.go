// Package eventlog implements the Windows Event Log (.evtx) collector.
package eventlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Liuchijang/FIR/internal/logging"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.Register(&eventLogCollector{}) }

type eventLogCollector struct{}

type EventLogFile struct {
	Name string
	Path string
}

var eventLogSelection = struct {
	mu    sync.RWMutex
	names []string
}{}

func (c *eventLogCollector) Name() string     { return "eventlog" }
func (c *eventLogCollector) Category() string { return "eventlog" }
func (c *eventLogCollector) Description() string {
	return "Collect EVTX logs"
}

var priorityLogs = []string{"Security", "System", "Application", "Microsoft-Windows-PowerShell%4Operational", "Microsoft-Windows-Sysmon%4Operational", "Microsoft-Windows-TaskScheduler%4Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational", "Microsoft-Windows-Windows Defender%4Operational", "Microsoft-Windows-WMI-Activity%4Operational", "Microsoft-Windows-Bits-Client%4Operational"}

func ConfigureSelectedLogs(names []string) {
	eventLogSelection.mu.Lock()
	defer eventLogSelection.mu.Unlock()

	eventLogSelection.names = append([]string(nil), names...)
}

func DiscoverAvailableLogs() ([]EventLogFile, error) {
	evtxDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	return discoverLogsInDir(evtxDir)
}

func ResolveSelectedOrAllLogs(dir string) ([]string, error) {
	logs, err := discoverLogsInDir(dir)
	if err != nil {
		return nil, err
	}

	eventLogSelection.mu.RLock()
	selected := append([]string(nil), eventLogSelection.names...)
	eventLogSelection.mu.RUnlock()

	if len(selected) == 0 {
		names := make([]string, 0, len(logs))
		for _, log := range logs {
			names = append(names, log.Name)
		}
		return names, nil
	}

	available := make(map[string]bool, len(logs))
	for _, log := range logs {
		available[strings.ToLower(log.Name)] = true
	}

	var resolved []string
	seen := make(map[string]bool)
	for _, name := range selected {
		key := strings.ToLower(name)
		if key == "" || seen[key] || !available[key] {
			continue
		}
		seen[key] = true
		resolved = append(resolved, name)
	}
	return resolved, nil
}

func (c *eventLogCollector) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	log := logging.G()
	outDir := filepath.Join(outputDir, "eventlog")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create eventlog output dir: %w", err)
	}

	evtxDir := filepath.Join(os.Getenv("SystemRoot"), "System32", "winevt", "Logs")
	evtxFiles, err := ResolveSelectedOrAllLogs(evtxDir)
	if err != nil {
		return nil, fmt.Errorf("resolve event log files: %w", err)
	}

	var allFiles []module.FileInfo
	var errorCount int
	for _, name := range evtxFiles {
		select {
		case <-ctx.Done():
			return allFiles, ctx.Err()
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
		return nil, fmt.Errorf("no event log files collected (%d errors)", errorCount)
	}
	return allFiles, nil
}

func getPriority(filename string) int {
	baseName := strings.TrimSuffix(filename, ".evtx")
	for i, p := range priorityLogs {
		if strings.EqualFold(baseName, p) {
			return i
		}
	}
	return len(priorityLogs) + 1
}

func discoverLogsInDir(dir string) ([]EventLogFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read event log directory: %w", err)
	}

	var logs []EventLogFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".evtx") {
			continue
		}
		logs = append(logs, EventLogFile{
			Name: e.Name(),
			Path: filepath.Join(dir, e.Name()),
		})
	}

	sort.Slice(logs, func(i, j int) bool {
		iPriority := getPriority(logs[i].Name)
		jPriority := getPriority(logs[j].Name)
		if iPriority != jPriority {
			return iPriority < jPriority
		}
		return logs[i].Name < logs[j].Name
	})
	return logs, nil
}
