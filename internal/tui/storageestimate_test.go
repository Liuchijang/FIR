package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	browserpkg "github.com/Liuchijang/FIR/internal/collectors/browser"
	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/resource"
)

func rawFor(t *testing.T, name string) int64 {
	t.Helper()
	mod, err := module.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return resource.EstimateStorage(".", []module.Module{mod}, true).EstimatedRawBytes
}

// The estimate used to report a flat per-module figure, so picking one small EVTX
// file still claimed the whole winevt\Logs directory.
func TestEventLogEstimateFollowsSelection(t *testing.T) {
	logs, err := eventlogpkg.DiscoverAvailableLogs()
	if err != nil || len(logs) < 2 {
		t.Skipf("need at least 2 discoverable EVTX files, got %d (err %v)", len(logs), err)
	}
	t.Cleanup(func() { eventlogpkg.ConfigureSelectedLogs(nil) })

	eventlogpkg.ConfigureSelectedLogs(nil)
	all := rawFor(t, "eventlog")

	eventlogpkg.ConfigureSelectedLogs([]string{logs[0].Name})
	one := rawFor(t, "eventlog")

	if one >= all {
		t.Errorf("one file estimates %s, all files estimate %s — selection is being ignored",
			resource.FormatBytes(one), resource.FormatBytes(all))
	}
	if one <= 0 {
		t.Errorf("one file estimates %s, want a positive size", resource.FormatBytes(one))
	}
}

func TestBrowserEstimateFollowsSelection(t *testing.T) {
	profiles, err := browserpkg.DiscoverProfiles()
	if err != nil || len(profiles) < 2 {
		t.Skipf("need at least 2 discoverable browser profiles, got %d (err %v)", len(profiles), err)
	}
	t.Cleanup(func() { browserpkg.ConfigureProfiles(nil) })

	browserpkg.ConfigureProfiles(nil)
	all := rawFor(t, "browser")

	// Only assert a strict drop when more than one profile actually holds bytes,
	// so the test does not depend on this machine's browser history.
	nonEmpty := 0
	for _, profile := range profiles {
		browserpkg.ConfigureProfiles([]string{profile.Path})
		if rawFor(t, "browser") > 0 {
			nonEmpty++
		}
	}

	browserpkg.ConfigureProfiles([]string{profiles[0].Path})
	one := rawFor(t, "browser")

	if one > all {
		t.Errorf("one profile estimates %s, more than all profiles at %s",
			resource.FormatBytes(one), resource.FormatBytes(all))
	}
	if nonEmpty >= 2 && one >= all {
		t.Errorf("one profile estimates %s and all %d profiles estimate %s - selection is being ignored",
			resource.FormatBytes(one), len(profiles), resource.FormatBytes(all))
	}
}

// A 1GiB floor on the safety margin made every small selection read as
// "Required 1.0 GiB", which looks like a broken estimate.
func TestSmallSelectionDoesNotRequireAGigabyte(t *testing.T) {
	logs, err := eventlogpkg.DiscoverAvailableLogs()
	if err != nil || len(logs) == 0 {
		t.Skip("no discoverable EVTX files")
	}
	t.Cleanup(func() { eventlogpkg.ConfigureSelectedLogs(nil) })

	eventlogpkg.ConfigureSelectedLogs([]string{logs[0].Name})
	mod, err := module.Get("eventlog")
	if err != nil {
		t.Fatal(err)
	}
	estimate := resource.EstimateStorage(".", []module.Module{mod}, true)

	const oneGiB = 1024 * 1024 * 1024
	if estimate.EstimatedRawBytes < oneGiB && estimate.RequiredBytes >= oneGiB {
		t.Errorf("raw %s but required %s — the margin floor dominates the estimate",
			resource.FormatBytes(estimate.EstimatedRawBytes), resource.FormatBytes(estimate.RequiredBytes))
	}
}

// The estimate shown on the run config screen must reflect the picks made in the
// TUI. The selection used to be pushed to the collector packages only once the menu
// finished, so the run config always showed the figure for collecting everything.
// Both paths below end on the run config screen; only the number of picked files
// differs, so the two estimates must differ too.
func runConfigRawForEventLogs(t *testing.T, pickAll bool, total int) int64 {
	t.Helper()

	logs, err := eventlogpkg.DiscoverAvailableLogs()
	if err != nil {
		t.Fatal(err)
	}
	logs = logs[:min(total, len(logs))]

	// The eventlog collector, not the parser: an analyzer writes a small CSV rather
	// than copying the logs, so it is estimated flat by design.
	base := menuWithModule(t, "eventlog")
	entered, _ := base.updateCollectors(tea.KeyMsg{Type: tea.KeyEnter})
	loaded, _ := entered.(menuModel).Update(eventLogsLoadedMsg{logs: logs})

	m := loaded.(menuModel)
	if m.phase != phaseEventLogs {
		t.Fatalf("phase = %d, want phaseEventLogs", m.phase)
	}

	key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}
	if !pickAll {
		m.eventLogCursor = 0
		key = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}

	picked, _ := m.updateEventLogs(key)
	confirmed, _ := picked.(menuModel).updateEventLogs(tea.KeyMsg{Type: tea.KeyEnter})

	got := confirmed.(menuModel)
	if got.phase != phaseRunConfig {
		t.Fatalf("phase = %d, want phaseRunConfig", got.phase)
	}
	return got.storageEstimate.EstimatedRawBytes
}

func TestRunConfigEstimateReflectsEventLogPicks(t *testing.T) {
	logs, err := eventlogpkg.DiscoverAvailableLogs()
	if err != nil || len(logs) < 2 {
		t.Skipf("need at least 2 discoverable EVTX files, got %d (err %v)", len(logs), err)
	}
	t.Cleanup(func() { eventlogpkg.ConfigureSelectedLogs(nil) })

	all := runConfigRawForEventLogs(t, true, len(logs))
	one := runConfigRawForEventLogs(t, false, len(logs))

	if one >= all {
		t.Errorf("run config shows %s for one file and %s for all - the picks are ignored",
			resource.FormatBytes(one), resource.FormatBytes(all))
	}
	if one <= 0 {
		t.Errorf("run config shows %s for one file, want a positive size", resource.FormatBytes(one))
	}
}

func runConfigRawForProfiles(t *testing.T, pickAll bool, profiles []browserpkg.BrowserProfile) int64 {
	t.Helper()

	m := menuWithModule(t, "browser")
	entered, _ := m.updateCollectors(tea.KeyMsg{Type: tea.KeyEnter})
	loaded, _ := entered.(menuModel).Update(profilesLoadedMsg{profiles: profiles})

	m = loaded.(menuModel)
	if m.phase != phaseProfiles {
		t.Fatalf("phase = %d, want phaseProfiles", m.phase)
	}

	key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}
	if !pickAll {
		m.profileCursor = 0
		key = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	}
	picked, _ := m.updateProfiles(key)
	done, _ := picked.(menuModel).updateProfiles(tea.KeyMsg{Type: tea.KeyEnter})

	got := done.(menuModel)
	if got.phase != phaseRunConfig {
		t.Fatalf("phase = %d, want phaseRunConfig", got.phase)
	}
	return got.storageEstimate.EstimatedRawBytes
}

func TestRunConfigEstimateReflectsBrowserPicks(t *testing.T) {
	profiles, err := browserpkg.DiscoverProfiles()
	if err != nil || len(profiles) < 2 {
		t.Skipf("need at least 2 discoverable browser profiles, got %d (err %v)", len(profiles), err)
	}
	t.Cleanup(func() { browserpkg.ConfigureProfiles(nil) })

	all := runConfigRawForProfiles(t, true, profiles)
	one := runConfigRawForProfiles(t, false, profiles)

	if one >= all {
		t.Errorf("run config shows %s for one profile and %s for all - the picks are ignored",
			resource.FormatBytes(one), resource.FormatBytes(all))
	}
}
