package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventlogpkg "github.com/Liuchijang/FIR/internal/collectors/eventlog"
	"github.com/Liuchijang/FIR/internal/module"
)

const evtxHeader = `"SourceFile","LogName","ProviderName","Id","Level","TimeCreated","RecordId","ProcessId","ThreadId","MachineName","UserId","Message"`

// exportEVTX writes a small .evtx into dir using the given XPath filter, skipping the
// test when the host cannot export event logs.
func exportEVTX(t *testing.T, dir, name, query string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	cmd := exec.Command("wevtutil", "epl", "Application", path, "/q:"+query, "/ow:true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("wevtutil epl failed (%v): %s", err, out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("wevtutil produced no file: %v", err)
	}
	return path
}

func runEventLogParser(t *testing.T, evtxDir string, files []string) (string, []byte) {
	t.Helper()

	out := filepath.Dir(evtxDir)
	eventlogpkg.ConfigureSelectedLogs(files)
	t.Cleanup(func() { eventlogpkg.ConfigureSelectedLogs(nil) })

	mod, err := module.Get("eventlog_parser")
	if err != nil {
		t.Fatal(err)
	}
	analyzer, ok := mod.(module.RequestAnalyzer)
	if !ok {
		t.Fatalf("unexpected module type %T", mod)
	}

	result := analyzer.AnalyzeWithRequest(context.Background(), module.AnalyzeRequest{
		OutputDir: out,
		StartedAt: time.Now(),
	})

	body, err := os.ReadFile(filepath.Join(out, "Analyzer", "eventlog_parser", "eventlog_records.csv"))
	if err != nil {
		body = nil
	}
	return result.Error, body
}

func newEvtxDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "eventlog")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The CSV is consumed by downstream tooling, so its exact shape is a contract: a
// UTF-8 BOM, CRLF line endings, the fixed 12-column header, and every field quoted.
func TestEventLogParserOutputFormat(t *testing.T) {
	dir := newEvtxDir(t)
	exportEVTX(t, dir, "sample.evtx", "*[System[(EventRecordID>0)]]")

	errMsg, body := runEventLogParser(t, dir, []string{"sample.evtx"})
	if errMsg != "" {
		t.Fatalf("parser reported %q", errMsg)
	}
	if len(body) == 0 {
		t.Fatal("parser produced no CSV")
	}

	if !bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
		t.Error("CSV is missing the UTF-8 BOM")
	}
	text := string(body[3:])
	if !strings.Contains(text, "\r\n") {
		t.Error("CSV does not use CRLF line endings")
	}

	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\r\n")
	if lines[0] != evtxHeader {
		t.Errorf("header = %s\nwant       %s", lines[0], evtxHeader)
	}
	if len(lines) < 2 {
		t.Fatal("CSV has a header but no rows")
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, `"`) || !strings.HasSuffix(line, `"`) {
			t.Errorf("line %d is not fully quoted: %s", i, line)
			break
		}
		if got := strings.Count(line, `","`); got != 11 {
			t.Errorf("line %d has %d field separators, want 11: %s", i, got, line)
			break
		}
	}
}

// A log that yields no events left Export-Csv with a BOM-only file and a successful
// result. Downstream code tolerates that, so the faster writer must reproduce it
// rather than erroring or emitting a header-only CSV.
func TestEventLogParserZeroEventsKeepsBOMOnlyFile(t *testing.T) {
	dir := newEvtxDir(t)
	exportEVTX(t, dir, "empty.evtx", "*[System[(EventRecordID=999999999)]]")

	errMsg, body := runEventLogParser(t, dir, []string{"empty.evtx"})
	if errMsg != "" {
		t.Errorf("parser reported %q, want success", errMsg)
	}
	if !bytes.Equal(body, []byte{0xEF, 0xBB, 0xBF}) {
		t.Errorf("CSV is %d bytes (%q), want just the 3-byte BOM", len(body), body)
	}
}

// newestRecordID returns an EventRecordID that exists in the Application log, so a
// query can select exactly one event.
func newestRecordID(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-WinEvent -LogName Application -MaxEvents 1).RecordId").Output()
	if err != nil {
		t.Skipf("cannot read the Application log: %v", err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		t.Skip("the Application log reported no records")
	}
	return id
}

// A single-event file must not be dropped, and a file listed but absent must not
// abort the run.
func TestEventLogParserSingleEventAndMissingFile(t *testing.T) {
	dir := newEvtxDir(t)
	exportEVTX(t, dir, "one.evtx", "*[System[(EventRecordID="+newestRecordID(t)+")]]")

	errMsg, body := runEventLogParser(t, dir, []string{"one.evtx", "absent.evtx"})
	if errMsg != "" {
		t.Fatalf("parser reported %q", errMsg)
	}
	lines := strings.Split(strings.TrimRight(string(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})), "\r\n"), "\r\n")
	if len(lines) != 2 {
		t.Errorf("got %d lines, want a header plus exactly one row:\n%s", len(lines), body)
	}
}
