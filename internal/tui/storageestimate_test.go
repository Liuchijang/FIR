package tui

import (
	"testing"

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
