# FIR - Freedom Incident Response

A production-grade Windows DFIR (Digital Forensics & Incident Response) artifact collection tool written in Go. Designed for first-response triage scenarios with a focus on minimal system impact, forensic integrity, and extensibility.

## Features

- **Dual CLI Modes**: Bubble Tea interactive flow or flag-driven batch collection
- **Built-in Collectors**: Browser, Event Logs, Execution, Live Response, Memory, NTFS, Registry, and System artifacts
- **Forensic Safety**: Read-only access, SHA-256 integrity hashing, no artifact modification
- **Windows Privilege Handling**: Auto-detects admin status, enables SeBackupPrivilege and SeDebugPrivilege
- **Locked File Support**: VSS shadow copies, `reg save`, `esentutl` fallbacks for locked files
- **Concurrent Collection**: Configurable parallelism with per-collector timeouts
- **Structured Output**: Organized collection output with summary reports and structured logs
- **Extensible Collectors**: Add collectors by implementing a single interface with minimal integration work

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
- Browse and toggle collectors in a keyboard-driven menu
- Show a spinner while Chromium profiles are being discovered
- Watch collectors move through waiting, running, success, and failed states during execution

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
| `browser_chromium` | `browser` | Collects Chromium browser forensic artifacts from selected Chrome, Edge, Brave, or Vivaldi profiles |
| `eventlog` | `eventlog` | Collects Windows Event Log files (`.evtx`) with forensic priority ordering |
| `amcache` | `execution` | Collects `Amcache.hve` from `C:\Windows\AppCompat\Programs` |
| `prefetch` | `execution` | Collects Windows Prefetch files (`.pf`) from `C:\Windows\Prefetch` |
| `autoruns` | `live` | Collects live autoruns-style persistence data for services, Run keys, startup folders, and scheduled tasks into CSV |
| `process_explorer` | `live` | Collects live process inventory, command lines, loaded DLL modules, and network connections into CSV |
| `ram` | `memory` | Acquires physical memory using `winpmem` |
| `mft` | `ntfs` | Collects the `$MFT` (Master File Table) via raw disk access |
| `secure_sds` | `ntfs` | Collects the `$Secure:$SDS` stream via VSS snapshot access |
| `usnjrnl` | `ntfs` | Collects the `$UsnJrnl:$J` USN Change Journal via FSCTL |
| `registry` | `registry` | Collects SYSTEM, SOFTWARE, SAM, SECURITY, `NTUSER.DAT`, and `UsrClass.dat` hives |
| `srum` | `system` | Collects the SRUM database (`SRUDB.dat`) |
| `wmi` | `system` | Collects WMI repository files (`OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`) |

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

## Requirements

- **OS**: Windows 10/11, Server 2016+
- **Privileges**: Administrator (right-click -> Run as Administrator)
- **Go**: 1.21+ (for building from source)

## License

This tool is intended for authorized forensic investigation and incident response only.
