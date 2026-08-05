package tui

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	_ "github.com/Liuchijang/FIR/internal/analyzers"
	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/resource"
)

func menuWithModule(t *testing.T, name string) menuModel {
	t.Helper()

	model := NewInteractiveMenuTeaModelWithConfig(".", resource.DefaultConfig())
	sized, _ := model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m := sized.(menuModel)

	found := false
	for i, opt := range m.modules {
		if opt.module.Name() == name {
			m.collectorCursor, found = i, true
			break
		}
	}
	if !found {
		t.Fatalf("%s is not registered", name)
	}
	selected, _ := m.updateCollectors(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	return selected.(menuModel)
}

// The eventlog collector honours a file selection the same way the parser does, so it
// must be offered the picker — matching how the browser collector gets its profile
// picker. Selecting only the collector used to skip straight past the picker.
func TestEventLogPickerOfferedToCollectorAndParser(t *testing.T) {
	for _, name := range []string{"eventlog", "eventlog_parser"} {
		t.Run(name, func(t *testing.T) {
			m := menuWithModule(t, name)
			if !m.needsEventLogSelection() {
				t.Fatal("needsEventLogSelection() = false, want true")
			}
			entered, _ := m.updateCollectors(tea.KeyMsg{Type: tea.KeyEnter})
			if got := entered.(menuModel).phase; got != phaseLoadingEventLogs {
				t.Errorf("phase after enter = %d, want phaseLoadingEventLogs", got)
			}
		})
	}
}

func TestBrowserPickerUnaffected(t *testing.T) {
	m := menuWithModule(t, "browser")
	if !m.needsBrowserProfiles() {
		t.Error("needsBrowserProfiles() = false, want true")
	}
	if m.needsEventLogSelection() {
		t.Error("needsEventLogSelection() = true for a browser-only selection")
	}
}

// Picking files must actually narrow what the collector reads, not just draw a list.
func TestEventLogSelectionReachesCollector(t *testing.T) {
	evtxDir := t.TempDir()
	names := []string{"Security.evtx", "System.evtx", "Application.evtx"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(evtxDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := menuWithModule(t, "eventlog")
	entered, _ := m.updateCollectors(tea.KeyMsg{Type: tea.KeyEnter})

	logs := make([]eventlogpkg.EventLogFile, 0, len(names))
	for _, name := range names {
		logs = append(logs, eventlogpkg.EventLogFile{Name: name})
	}
	loaded, _ := entered.(menuModel).Update(eventLogsLoadedMsg{logs: logs})

	m = loaded.(menuModel)
	m.eventLogCursor = 1 // System.evtx
	picked, _ := m.updateEventLogs(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	m = picked.(menuModel)
	m.completed = true

	done, result, cancelled, err := InteractiveMenuFinishedWithConfig(m)
	if err != nil || !done || cancelled {
		t.Fatalf("InteractiveMenuFinishedWithConfig() = done %v, cancelled %v, err %v", done, cancelled, err)
	}
	if len(result.Modules) != 1 || result.Modules[0].Name() != "eventlog" {
		t.Fatalf("modules = %v, want just the eventlog collector", result.Modules)
	}

	resolved, err := eventlogpkg.ResolveSelectedOrAllLogs(evtxDir)
	if err != nil {
		t.Fatalf("ResolveSelectedOrAllLogs() error = %v", err)
	}
	if !slices.Equal(resolved, []string{"System.evtx"}) {
		t.Errorf("collector would read %v, want only [System.evtx]", resolved)
	}
}
