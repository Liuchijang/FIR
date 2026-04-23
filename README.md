# FIR - Freedom Incident Response

A production-grade Windows DFIR (Digital Forensics & Incident Response) artifact collection tool written in Go. Designed for first-response triage scenarios with a focus on minimal system impact, forensic integrity, and extensibility.

## Features

- **Dual CLI Modes**: Bubble Tea interactive flow or flag-driven batch collection
- **Built-in Modules**: Collector modules for Browser, Event Logs, Execution, Live Response, Memory, NTFS, Registry, and System artifacts, plus analyzer modules for parsed triage output
- **Forensic Safety**: Read-only access, SHA-256 integrity hashing, no artifact modification
- **Windows Privilege Handling**: Auto-detects admin status and enables backup, restore, security, and debug privileges when available
- **Native Windows Collection**: Uses backup semantics, registry hive save APIs, and raw NTFS access where needed
- **Concurrent Collection**: Configurable parallelism with per-module timeouts
- **Structured Output**: Organized collection output with summary reports and structured logs
- **Extensible Modules**: Add collection or analyzer modules behind a shared module contract with minimal integration work

## Build

```powershell
# Build the binary
go build -ldflags "-s -w" -o fir.exe .

# Or with version info
go build -ldflags "-s -w -X github.com/Liuchijang/FIR/internal/output.Version=1.2.0" -o fir.exe .
```

**Requirements**: Go 1.21+ and Windows target platform.

## Usage

### Interactive Mode (default)

```powershell
# Run as Administrator for full access
.\fir.exe
```

This launches a Bubble Tea interface where you can:
- Browse and toggle modules in a keyboard-driven menu
- Show a spinner while browser profiles are being discovered
- Watch modules move through waiting, running, success, and failed states during execution

After collection finishes, FIR prints a run summary table and writes the same report to `summary.txt`.

### Flag Mode

```powershell
# Collect specific artifacts
.\fir.exe collect --artifact registry,eventlog,prefetch

# Collect by category
.\fir.exe collect --artifact ntfs,execution

# Collect everything
.\fir.exe collect --artifact all

# Custom output directory and timeout
.\fir.exe collect --artifact registry,eventlog --output C:\triage --timeout 10m

# Verbose mode with higher concurrency
.\fir.exe collect --artifact all --output E:\evidence -v --concurrency 4
```

### Available Artifacts

| Name | Category | Description |
|---|---|---|
| `browser` | `browser` | Collects browser forensic artifacts from detected Chrome, Edge, Brave, Vivaldi, Firefox, Opera, and Opera GX profiles |
| `eventlog` | `eventlog` | Collects Windows Event Log files (`.evtx`) with forensic priority ordering |
| `amcache` | `execution` | Collects `Amcache.hve` plus `Amcache.hve.LOG1/.LOG2` via native file access with hive-save and raw-volume fallback |
| `prefetch` | `execution` | Collects Windows Prefetch files (`.pf`) from `C:\Windows\Prefetch` |
| `autoruns` | `live` | Generates live autoruns-style triage CSV for services, Run keys, startup folders, and scheduled tasks |
| `process_explorer` | `live` | Generates live process, module, and network triage CSV from the running system |
| `ram` | `memory` | Acquires physical memory using `winpmem` |
| `mft` | `ntfs` | Collects the `$MFT` (Master File Table) via raw disk access |
| `secure_sds` | `ntfs` | Best-effort collection of the `$Secure:$SDS` stream via raw NTFS record parsing |
| `usnjrnl` | `ntfs` | Collects the `$UsnJrnl:$J` USN Change Journal via FSCTL |
| `registry` | `registry` | Collects primary registry hives plus `.LOG1/.LOG2` via backup semantics with hive-save fallback |
| `srum` | `system` | Collects the SRUM database (`SRUDB.dat`) via native Windows file access |
| `wmi` | `system` | Collects WMI repository files (`OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`) |

### Available Analyzer Modules

| Name | Category | Description |
|---|---|---|
| `amcache_parser` | `execution` | Parse Amcache |
| `browser_history_parser` | `browser` | Parse browser history from collected browser profiles |
| `eventlog_parser` | `eventlog` | Parse EVTX logs |
| `mft_parser` | `ntfs` | Parse `$MFT` to full CSV |
| `prefetch_parser` | `execution` | Parse Prefetch |
| `recentdocs_parser` | `registry` | Parse RecentDocs |
| `runmru_parser` | `registry` | Parse RunMRU |
| `secure_sds_parser` | `ntfs` | Parse Secure SDS |
| `shimcache_parser` | `registry` | Parse ShimCache |
| `userassist_parser` | `registry` | Parse UserAssist |
| `usnjrnl_parser` | `ntfs` | Parse USN, enrich with MFT if selected |
| `wmi_parser` | `system` | Parse WMI |

**Category shortcuts**: Use `browser`, `eventlog`, `execution`, `live`, `memory`, `ntfs`, `registry`, `system`, or `all`.

## CLI Output Example

Interactive mode now shows a Bubble Tea screen for selection, live execution status, and a final summary report. A typical run looks like this:

```text
+--------------------------------------------------------------+
|  |-----||   O    |----\\                                     |
|  |    --| |----| |   x  <|'                                  |
|  |__|--'  |____| |__|\\__/                                   |
|  FIR v1.0.0                                                  |
|  Freedom Incident Response                                   |
+--------------------------------------------------------------+

Collecting Artifacts

[OK] SUCCESS [eventlog] eventlog           files=397  size=323.9 MiB  duration=3.4s
[OK] SUCCESS [execution] prefetch          files=271  size=7.4 MiB    duration=8s
[-] FAILED  [memory] ram                   duration=32ms  error=winpmem not found
| RUNNING   [live] process_explorer

Collection Summary

+------------+-------------------+----------+-------+-----------+----------+
| Category   | Module            | Status   | Files | Size      | Duration |
+------------+-------------------+----------+-------+-----------+----------+
| eventlog   | eventlog          | SUCCESS  | 397   | 323.9 MiB | 3.4s     |
| execution  | prefetch          | SUCCESS  | 271   | 7.4 MiB   | 8s       |
| memory     | ram               | FAILED   | 0     | 0 B       | 32ms     |
+------------+-------------------+----------+-------+-----------+----------+

Failure Details
! [memory] ram duration=32ms
  error: winpmem not found: winpmem executable not found
```

## RAM Acquisition (winpmem)

FIR does **not** bundle winpmem due to licensing. Place `winpmem_mini_x64.exe` in:
- Same directory as `fir.exe` (recommended)
- Current working directory
- System PATH

If winpmem is not found, the RAM collector will fail gracefully with a clear error message.

## Package Layout

The project now follows the runtime flow more directly:

```text
cmd/
  root.go
  collect.go
  interactive_progress.go

internal/
  module/        shared module contract + registry
  collectors/    artifact acquisition modules grouped by category
  analyzers/     parsed / enriched output modules
  tui/           Bubble Tea menu + shared terminal UI helpers
  acquisition/   low-level Windows and NTFS access helpers
  output/        summary + metadata rendering
  logging/       session logging
  console/       console/window handling
  utils/         remaining generic helpers
```

This keeps the practical path easy to follow:
`main -> cmd -> module registry -> collectors/analyzers -> output/logging`

## Requirements

- **OS**: Windows 10/11, Server 2016+
- **Privileges**: Administrator (right-click -> Run as Administrator)
- **Go**: 1.21+ (for building from source)

## License

This tool is intended for authorized forensic investigation and incident response only.
