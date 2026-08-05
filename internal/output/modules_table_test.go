package output

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Liuchijang/FIR/internal/module"
)

var ansi = regexp.MustCompile("\x1b" + `\[[0-9;]*m`)

func sampleResults() []module.Result {
	return []module.Result{
		{Category: "eventlog", CollectorName: "eventlog_parser", Success: true, Duration: 73 * time.Second,
			FilesCollected: []module.FileInfo{{Size: 3 * 1024 * 1024}}},
		{Category: "ntfs", CollectorName: "mft", Error: "access denied", Duration: 2 * time.Second},
		{Category: "system", CollectorName: "srum", Success: true, Skipped: true},
	}
}

// Every layout must produce rows exactly as wide as its border, at every width.
func TestModulesTableAlignsAtAllWidths(t *testing.T) {
	for width := 12; width <= 160; width++ {
		out := renderTerminalModulesTable(sampleResults(), width)
		lines := strings.Split(out, "\n")
		want := len(ansi.ReplaceAllString(lines[0], ""))
		for i, line := range lines {
			if got := len(ansi.ReplaceAllString(line, "")); got != want {
				t.Fatalf("width=%d line %d: width %d != %d\n%s", width, i, got, want, out)
			}
		}
	}
}

// The flex column must absorb leftover width without pushing the table past it.
func TestModulesTableRespectsRequestedWidth(t *testing.T) {
	for width := 24; width <= 160; width++ {
		out := renderTerminalModulesTable(sampleResults(), width)
		first := ansi.ReplaceAllString(strings.Split(out, "\n")[0], "")
		if len(first) > width {
			t.Errorf("width=%d: table is %d wide, exceeds the budget", width, len(first))
		}
	}
}

func TestModulesTableKeepsStatusAndNames(t *testing.T) {
	out := ansi.ReplaceAllString(renderTerminalModulesTable(sampleResults(), 120), "")
	for _, want := range []string{"eventlog_parser", "SUCCESS", "mft", "FAILED", "srum", "SKIPPED", "access denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("wide table missing %q:\n%s", want, out)
		}
	}
}
