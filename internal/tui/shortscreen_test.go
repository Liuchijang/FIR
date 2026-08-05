package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	_ "github.com/Liuchijang/FIR/internal/analyzers"
	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/output"
	"github.com/Liuchijang/FIR/internal/resource"
)

// eventLogSelectionAt drives the menu to the EVTX picker with count discovered files.
func eventLogSelectionAt(t *testing.T, count, width, height int) menuModel {
	t.Helper()

	model := NewInteractiveMenuTeaModelWithConfig(".", resource.DefaultConfig())
	sized, _ := model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m := sized.(menuModel)

	found := false
	for i, opt := range m.modules {
		if opt.module.Name() == "eventlog_parser" {
			m.collectorCursor, found = i, true
			break
		}
	}
	if !found {
		t.Fatal("eventlog_parser is not registered")
	}

	selected, _ := m.updateCollectors(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	entered, _ := selected.(menuModel).updateCollectors(tea.KeyMsg{Type: tea.KeyEnter})

	logs := make([]eventlogpkg.EventLogFile, count)
	for i := range logs {
		logs[i] = eventlogpkg.EventLogFile{Name: "Log" + string(rune('A'+i%26)) + ".evtx"}
	}
	loaded, _ := entered.(menuModel).Update(eventLogsLoadedMsg{logs: logs})

	got := loaded.(menuModel)
	if got.phase != phaseEventLogs {
		t.Fatalf("phase = %d, want phaseEventLogs", got.phase)
	}
	return got
}

// A short terminal used to spend every body row on the banner, the phase title and
// the status line, leaving no selectable row — the EVTX list looked like it offered
// nothing to pick.
func TestEventLogListAlwaysOffersARow(t *testing.T) {
	for _, height := range []int{8, 10, 12, 14, 16, 18, 20, 24, 30, 50} {
		for _, width := range []int{40, 80, 100, 160} {
			view := eventLogSelectionAt(t, 382, width, height).View()
			if !strings.Contains(view, "[ ]") {
				t.Errorf("%dx%d: no selectable row rendered:\n%s", width, height, view)
			}
		}
	}
}

func TestEventLogSelectionTogglesOnShortScreen(t *testing.T) {
	m := eventLogSelectionAt(t, 382, 100, 12)

	toggled, _ := m.updateEventLogs(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	m = toggled.(menuModel)
	if got := len(m.eventLogResults()); got != 1 {
		t.Fatalf("after space: %d files selected, want 1 (status %q)", got, m.status)
	}
	if !strings.Contains(m.View(), "[x]") {
		t.Error("the selected row is not marked [x]")
	}

	all, _ := m.updateEventLogs(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if got := len(all.(menuModel).eventLogResults()); got != 382 {
		t.Errorf("after 'a': %d files selected, want 382", got)
	}
}

// The collection screen shares the same chrome, so it must also keep module rows.
func TestProgressKeepsRowsOnShortScreen(t *testing.T) {
	var mods []module.Module
	for _, mode := range module.Modes() {
		mods = append(mods, module.GetByMode(mode)...)
	}

	for _, height := range []int{8, 10, 12, 16, 24, 40} {
		sized, _ := NewCollectionProgressModel(mods, 8).Update(tea.WindowSizeMsg{Width: 100, Height: height})
		running := sized.(CollectionProgressModel)
		if view := running.View(); !strings.Contains(view, "WAITING") {
			t.Errorf("height %d: no module rows rendered:\n%s", height, view)
		}

		done, _ := running.Update(CollectionFinishedMsg{
			Report: output.NewSummaryReport("out", time.Unix(0, 0).UTC(), 0, 0, 8, nil),
		})
		if view := done.View(); !strings.Contains(view, "|") {
			t.Errorf("height %d: summary table missing:\n%s", height, view)
		}
	}
}
