# FIR — First Incident Response

A production-grade Windows DFIR (Digital Forensics & Incident Response) artifact collection tool written in Go. Designed for first-response triage scenarios with a focus on minimal system impact, forensic integrity, and extensibility.

## Features

- **Dual CLI Modes**: Interactive menu-driven selection or flag-driven batch collection
- **10 Built-in Collectors**: Memory, NTFS, Registry, Event Logs, Execution Artifacts, System Activity
- **Forensic Safety**: Read-only access, SHA-256 integrity hashing, no artifact modification
- **Windows Privilege Handling**: Auto-detects admin status, enables SeBackupPrivilege/SeDebugPrivilege
- **Locked File Support**: VSS shadow copies, `reg save`, `esentutl` fallbacks for locked files
- **Concurrent Collection**: Configurable parallelism with per-collector timeouts
- **Structured Output**: Organized directory tree with JSON metadata and structured logs
- **Extensible Architecture**: Add collectors by implementing a single interface — no core changes needed

## Build

```powershell
# Build the binary
go build -ldflags "-s -w" -o fir.exe .

# Or with version info
go build -ldflags "-s -w -X github.com/fir/fir/internal/output.Version=1.2.0" -o fir.exe .
```

**Requirements**: Go 1.21+ and Windows target platform.

## Usage

### Interactive Mode (default)

```powershell
# Run as Administrator for full access
.\fir.exe
```

This launches a menu-driven interface where you can:
- Browse collectors by category
- Select by number, name, or category
- Confirm before collection starts

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
| `ram` | 🔴 Memory | Physical memory acquisition via winpmem |
| `mft` | 🟠 NTFS | $MFT (Master File Table) via raw disk access |
| `usnjrnl` | 🟠 NTFS | $UsnJrnl:$J (USN Change Journal) via FSCTL |
| `secure_sds` | 🟠 NTFS | $Secure:$SDS (Security Descriptors) via VSS |
| `registry` | 🔵 Registry | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat |
| `eventlog` | 🟢 Event Logs | All .evtx files with forensic priority ordering |
| `prefetch` | 🟡 Execution | Windows Prefetch files (.pf) |
| `amcache` | 🟡 Execution | Amcache.hve |
| `wmi` | 🟣 System | WMI repository (OBJECTS.DATA, INDEX.BTR, MAPPING*.MAP) |
| `srum` | 🟣 System | SRUM database (SRUDB.dat) |

**Category shortcuts**: Use `memory`, `ntfs`, `registry`, `eventlog`, `execution`, `system`, or `all`.

## Output Structure

```
DESKTOP-ABC123_20260416_143210/
├── memory/
│   └── memory.raw
├── ntfs/
│   ├── $MFT
│   ├── $UsnJrnl_J
│   └── $Secure_SDS
├── registry/
│   ├── SYSTEM
│   ├── SOFTWARE
│   ├── SAM
│   ├── SECURITY
│   ├── DEFAULT
│   └── users/
│       ├── JohnDoe/
│       │   ├── NTUSER.DAT
│       │   └── UsrClass.dat
│       └── Admin/
│           ├── NTUSER.DAT
│           └── UsrClass.dat
├── eventlog/
│   ├── Security.evtx
│   ├── System.evtx
│   ├── Application.evtx
│   └── ... (all .evtx files)
├── execution/
│   ├── prefetch/
│   │   ├── CHROME.EXE-ABC12345.pf
│   │   └── ...
│   └── Amcache.hve
├── system/
│   ├── wmi/
│   │   ├── OBJECTS.DATA
│   │   ├── INDEX.BTR
│   │   └── MAPPING*.MAP
│   └── SRUDB.dat
├── logs/
│   └── collector.log
└── metadata.json
```

## metadata.json

```json
{
  "hostname": "DESKTOP-ABC123",
  "timestamp": "2026-04-16T14:32:10+07:00",
  "timestamp_utc": "2026-04-16T07:32:10Z",
  "os": "windows",
  "architecture": "amd64",
  "artifacts_collected": ["registry", "eventlog", "prefetch"],
  "collector_version": "1.0.0",
  "total_duration": "12.345s",
  "results": [
    {
      "collector_name": "registry",
      "category": "registry",
      "files_collected": [
        {"path": "SYSTEM", "sha256": "a1b2c3...", "size": 16777216}
      ],
      "duration_seconds": 3.21,
      "success": true
    }
  ]
}
```

## CLI Output Example

```
  ╔═══════════════════════════════════════╗
  ║   FIR — First Incident Response      ║
  ║   Windows DFIR Artifact Collector     ║
  ║   Version 1.0.0                       ║
  ╚═══════════════════════════════════════╝

[+] Output directory: C:\triage\DESKTOP-ABC123_20260416_143210
[+] Collectors to run: 3
[+] Collecting: registry
[✓] Done: registry (6 hives) ... (3.2s)
[+] Collecting: eventlog
[✓] Done: eventlog (12 files) ... (2.3s)
[+] Collecting: prefetch
[✓] Done: prefetch (45 files) ... (1.1s)

[+] Collection completed in 6.6s
[✓] Results: 3 succeeded, 0 failed
[+] Output: C:\triage\DESKTOP-ABC123_20260416_143210
```

## Architecture

### Collector Interface

All collectors implement this interface:

```go
type Collector interface {
    Name() string
    Category() string
    Description() string
    Collect(ctx context.Context, outputDir string) error
}
```

### Adding a New Collector

1. Create a new file in the appropriate package (e.g., `internal/newcategory/mycollector.go`)
2. Implement the `Collector` interface
3. Self-register in `init()`:

```go
package newcategory

import "github.com/fir/fir/internal/collector"

func init() {
    collector.Register(&myCollector{})
}

type myCollector struct{}

func (c *myCollector) Name() string        { return "mycollector" }
func (c *myCollector) Category() string    { return "newcategory" }
func (c *myCollector) Description() string { return "Collects something useful" }

func (c *myCollector) Collect(ctx context.Context, outputDir string) error {
    // Your collection logic here.
    return nil
}
```

4. Add a blank import in `cmd/root.go`:
```go
_ "github.com/fir/fir/internal/newcategory"
```

**No changes to core orchestration logic required.**

### Project Structure

```
├── main.go                         # Entry point
├── cmd/
│   ├── root.go                     # Root command, interactive mode, preflight
│   └── collect.go                  # Flag-driven collection, orchestration
├── internal/
│   ├── collector/                  # Core interface + registry
│   ├── cli/                        # Interactive menu
│   ├── acquisition/                # Raw disk + VSS helpers
│   ├── output/                     # Directory management + metadata
│   ├── logging/                    # Dual-output logger
│   ├── utils/                      # Privileges, file copy, hashing
│   ├── memory/                     # RAM collector
│   ├── ntfs/                       # MFT, USN Journal, Secure SDS
│   ├── registry/                   # Registry hive collector
│   ├── eventlog/                   # Event log collector
│   ├── execution/                  # Prefetch, Amcache
│   └── system/                     # WMI, SRUM
```

## RAM Acquisition (winpmem)

FIR does **not** bundle winpmem due to licensing. Place `winpmem_mini_x64.exe` in:
- Same directory as `fir.exe` (recommended)
- Current working directory
- System PATH

If winpmem is not found, the RAM collector will fail gracefully with a clear error message.

## Requirements

- **OS**: Windows 10/11, Server 2016+
- **Privileges**: Administrator (right-click → Run as Administrator)
- **Go**: 1.21+ (for building from source)

## License

This tool is intended for authorized forensic investigation and incident response only.
