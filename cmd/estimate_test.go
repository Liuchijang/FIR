package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/resource"
)

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rawBytes(t *testing.T, name string) int64 {
	t.Helper()
	mod, err := module.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return resource.EstimateStorage(".", []module.Module{mod}, false).EstimatedRawBytes
}

// Collectors that can see their own artifacts must estimate from them, not from a
// flat per-module constant. SystemRoot is redirected so the sizes are exact
// regardless of what this machine holds or whether the test is elevated.
func TestCollectorsEstimateFromRealArtifacts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("SystemRoot", root)

	const kb = 1024
	writeFile(t, filepath.Join(root, "AppCompat", "Programs", "Amcache.hve"), 300*kb)
	writeFile(t, filepath.Join(root, "AppCompat", "Programs", "Amcache.hve.LOG1"), 100*kb)
	writeFile(t, filepath.Join(root, "Prefetch", "NOTEPAD.EXE-1234.pf"), 40*kb)
	writeFile(t, filepath.Join(root, "Prefetch", "CMD.EXE-5678.pf"), 60*kb)
	writeFile(t, filepath.Join(root, "System32", "wbem", "Repository", "OBJECTS.DATA"), 700*kb)
	writeFile(t, filepath.Join(root, "System32", "sru", "SRUDB.dat"), 500*kb)
	writeFile(t, filepath.Join(root, "System32", "config", "SYSTEM"), 800*kb)
	writeFile(t, filepath.Join(root, "System32", "config", "SOFTWARE"), 900*kb)

	tests := []struct {
		module string
		want   int64
	}{
		{"amcache", 400 * kb},
		{"prefetch", 100 * kb},
		{"wmi", 700 * kb},
		{"srum", 500 * kb},
	}
	for _, tc := range tests {
		t.Run(tc.module, func(t *testing.T) {
			if got := rawBytes(t, tc.module); got != tc.want {
				t.Errorf("estimated %s, want %s", resource.FormatBytes(got), resource.FormatBytes(tc.want))
			}
		})
	}

	// The registry collector also covers per-user hives, and it finds those profile
	// directories through HKLM\...\ProfileList rather than under SystemRoot, so the
	// total legitimately exceeds the fake hives written above. Assert it measured
	// them and is not simply returning the flat constant.
	t.Run("registry", func(t *testing.T) {
		const flatGuess = 512 * 1024 * kb
		got := rawBytes(t, "registry")
		if got < 1700*kb {
			t.Errorf("estimated %s, want at least the 1.7 MiB of system hives present", resource.FormatBytes(got))
		}
		if got == flatGuess {
			t.Errorf("estimated exactly the flat guess %s, so nothing was measured", resource.FormatBytes(got))
		}
	})
}

// With no artifacts to measure, each collector must fall back to its flat estimate
// rather than reporting zero and claiming a run needs no space.
func TestEstimateFallsBackWhenNothingReadable(t *testing.T) {
	t.Setenv("SystemRoot", t.TempDir())

	for _, name := range []string{"amcache", "prefetch", "wmi", "srum", "registry", "eventlog"} {
		t.Run(name, func(t *testing.T) {
			if got := rawBytes(t, name); got <= 0 {
				t.Errorf("estimated %d bytes, want a positive fallback", got)
			}
		})
	}
}
