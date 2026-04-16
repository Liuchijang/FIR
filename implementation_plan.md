# FIR — Windows DFIR First-Response Artifact Collector

## Goal

Build a production-grade, modular Windows artifact collection tool in Go for first-response DFIR scenarios. The tool must collect volatile and non-volatile forensic artifacts with minimal system impact, never modify originals, and provide both interactive and flag-driven CLI modes.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---|---|---|
| CLI framework | `cobra` | Industry standard for Go CLIs, supports subcommands + flags natively |
| Interactive menus | `survey/v2` (AlecAivazis) | Lightweight, checkbox/select prompts — avoids heavy Bubble Tea for a non-TUI tool |
| Colored output | `fatih/color` | Zero-dependency, simple colored printing |
| Spinner/progress | `briandowns/spinner` | 90+ spinner styles, minimal overhead |
| Logging | `log/slog` (stdlib) | Structured JSON logging, no external dependency |
| Hashing | `crypto/sha256` (stdlib) | SHA-256 for integrity verification |
| Windows APIs | `golang.org/x/sys/windows` | Privilege management, raw handle access |
| Raw disk / NTFS | Direct `CreateFile` on `\\.\C:` | Sector-aligned reads for MFT/$UsnJrnl/$Secure |
| VSS | `vssadmin` / WMI via `exec.Command` | Shadow copy creation for locked file access |
| RAM | External `winpmem` integration | Industry-standard memory acquisition |

---

## Project Structure

```
d:\Code\FIR\
├── main.go                          # Entry point
├── go.mod
├── go.sum
├── README.md
│
├── cmd/                             # Cobra commands
│   ├── root.go                      # Root command, global flags
│   └── collect.go                   # `collect` subcommand (flag mode)
│
└── internal/
    ├── collector/                   # Core collector framework
    │   ├── collector.go             # Collector interface + types
    │   └── registry.go              # Dynamic collector registry
    │
    ├── memory/                      # 🔴 RAM collector
    │   └── memory.go                # winpmem integration
    │
    ├── ntfs/                        # 🟠 NTFS artifact collectors
    │   ├── mft.go                   # $MFT collector
    │   ├── usnjrnl.go               # $UsnJrnl:$J collector
    │   └── secure.go                # $Secure:$SDS collector
    │
    ├── registry/                    # 🔵 Registry hive collectors
    │   └── registry.go              # All hives (SYSTEM, SAM, etc.)
    │
    ├── eventlog/                    # 🟢 Event log collector
    │   └── eventlog.go              # .evtx file collection
    │
    ├── execution/                   # 🟡 Execution artifact collectors
    │   ├── prefetch.go              # Prefetch files
    │   └── amcache.go               # Amcache.hve
    │
    ├── system/                      # 🟣 System activity collectors
    │   ├── wmi.go                   # WMI repository
    │   └── srum.go                  # SRUM database
    │
    ├── cli/                         # CLI UX layer
    │   └── interactive.go           # Interactive menu mode
    │
    ├── acquisition/                 # Low-level acquisition helpers
    │   ├── rawdisk.go               # Raw disk handle + sector-aligned reads
    │   └── shadowcopy.go            # VSS shadow copy create/delete
    │
    ├── output/                      # Output management
    │   ├── writer.go                # Directory creation, file writing
    │   └── metadata.go              # metadata.json generation
    │
    ├── logging/                     # Logging infrastructure
    │   └── logger.go                # slog-based file + console logger
    │
    └── utils/                       # Shared utilities
        ├── privilege.go             # SeBackupPrivilege, SeDebugPrivilege
        ├── filecopy.go              # Safe file copy with hashing
        └── hash.go                  # SHA-256 file hashing
```

---

## Proposed Changes

### Core Framework

#### [NEW] [main.go](file:///d:/Code/FIR/main.go)
- Thin entry point: calls `cmd.Execute()`

#### [NEW] [go.mod](file:///d:/Code/FIR/go.mod)  
- Module: `github.com/fir/fir`
- Dependencies: `cobra`, `survey/v2`, `fatih/color`, `briandowns/spinner`, `golang.org/x/sys`

---

### CLI Layer (`cmd/`)

#### [NEW] [root.go](file:///d:/Code/FIR/cmd/root.go)
- Root command with `--output` and `--verbose` persistent flags
- Default action: launch interactive mode
- Version flag: `--version`
- Pre-run: admin check + privilege escalation

#### [NEW] [collect.go](file:///d:/Code/FIR/cmd/collect.go)
- `collect` subcommand for flag-driven mode
- `--artifact` flag: comma-separated list (`ram,mft,registry,eventlog,execution,system`)
- `--output` flag: output base directory (default: current dir)
- `--timeout` flag: per-collector timeout (default: 5m)
- `--concurrency` flag: max parallel collectors (default: 2)
- Orchestration logic: resolve collectors → create output dir → run collectors → write metadata

---

### Collector Framework (`internal/collector/`)

#### [NEW] [collector.go](file:///d:/Code/FIR/internal/collector/collector.go)
```go
type Collector interface {
    Name() string
    Category() string
    Description() string
    Collect(ctx context.Context, outputDir string) error
}

type Result struct {
    CollectorName string
    Category      string
    FilesCollected []FileInfo
    Duration      time.Duration
    Error         error
}

type FileInfo struct {
    Path   string `json:"path"`
    SHA256 string `json:"sha256"`
    Size   int64  `json:"size"`
}
```

#### [NEW] [registry.go](file:///d:/Code/FIR/internal/collector/registry.go)
- Global `Registry` with thread-safe `Register()` and `Get()` methods
- `GetByCategory(category)` to filter collectors
- `GetByName(name)` for specific collector lookup
- `All()` returns sorted list of all registered collectors
- Each collector package uses `func init()` to self-register

---

### Memory Collector (`internal/memory/`)

#### [NEW] [memory.go](file:///d:/Code/FIR/internal/memory/memory.go)
- Searches for `winpmem` in: same directory as exe, PATH, user-specified path
- Executes: `winpmem_mini_x64.exe <output>/memory.raw`
- Falls back to `winpmem_mini_x86.exe` on 32-bit
- Validates exit code, hashes output
- Self-registers in `init()`

---

### NTFS Collectors (`internal/ntfs/`)

#### [NEW] [mft.go](file:///d:/Code/FIR/internal/ntfs/mft.go)
- Opens `\\.\C:` raw volume handle with `CreateFile`
- Reads MFT via `FSCTL_GET_NTFS_VOLUME_DATA` to locate MFT start
- Sector-aligned reads to copy full $MFT
- Falls back to VSS shadow copy if raw access fails
- Self-registers in `init()`

#### [NEW] [usnjrnl.go](file:///d:/Code/FIR/internal/ntfs/usnjrnl.go)
- Uses `FSCTL_READ_USN_JOURNAL` to read $UsnJrnl:$J
- Streams journal entries to output file
- Self-registers in `init()`

#### [NEW] [secure.go](file:///d:/Code/FIR/internal/ntfs/secure.go)
- Reads `$Secure:$SDS` via raw disk or VSS
- Self-registers in `init()`

---

### Registry Collectors (`internal/registry/`)

#### [NEW] [registry.go](file:///d:/Code/FIR/internal/registry/registry.go)
- Collects system hives: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` from `C:\Windows\System32\config\`
- Collects user hives: `NTUSER.DAT`, `UsrClass.dat` from each `C:\Users\*\` profile
- Uses `RegSaveKeyEx` API for live hives (preferred — clean, consistent)
- Falls back to VSS shadow copy for locked files
- Hashes all collected files
- Self-registers in `init()`

---

### Event Log Collector (`internal/eventlog/`)

#### [NEW] [eventlog.go](file:///d:/Code/FIR/internal/eventlog/eventlog.go)
- Enumerates all `.evtx` files from `C:\Windows\System32\winevt\Logs\`
- Copies each file (via VSS if locked)
- Prioritizes: Security, System, Application, PowerShell, Sysmon
- Self-registers in `init()`

---

### Execution Artifact Collectors (`internal/execution/`)

#### [NEW] [prefetch.go](file:///d:/Code/FIR/internal/execution/prefetch.go)
- Copies all `.pf` files from `C:\Windows\Prefetch\`
- Requires admin (path is ACL-protected)
- Self-registers in `init()`

#### [NEW] [amcache.go](file:///d:/Code/FIR/internal/execution/amcache.go)
- Copies `C:\Windows\AppCompat\Programs\Amcache.hve`
- Uses VSS if file is locked
- Self-registers in `init()`

---

### System Activity Collectors (`internal/system/`)

#### [NEW] [wmi.go](file:///d:/Code/FIR/internal/system/wmi.go)
- Copies WMI repository from `C:\Windows\System32\wbem\Repository\`
- Includes: `OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`
- Self-registers in `init()`

#### [NEW] [srum.go](file:///d:/Code/FIR/internal/system/srum.go)
- Copies SRUM database from `C:\Windows\System32\sru\SRUDB.dat`
- Uses VSS if locked (commonly locked by `svchost`)
- Self-registers in `init()`

---

### Acquisition Helpers (`internal/acquisition/`)

#### [NEW] [rawdisk.go](file:///d:/Code/FIR/internal/acquisition/rawdisk.go)
- `OpenRawVolume(drive string) (*RawVolume, error)` — opens `\\.\X:` handle
- Sector-aligned `ReadAt()` implementation
- `GetNTFSVolumeData()` — FSCTL for MFT location/size
- Buffer pooling for efficient I/O

#### [NEW] [shadowcopy.go](file:///d:/Code/FIR/internal/acquisition/shadowcopy.go)
- `CreateShadowCopy(volume string) (shadowPath string, cleanup func(), error)`
- Uses `vssadmin create shadow /for=C:`
- Parses output for shadow device path
- `cleanup()` deletes the shadow copy after use
- Timeout protection

---

### Output Layer (`internal/output/`)

#### [NEW] [writer.go](file:///d:/Code/FIR/internal/output/writer.go)
- `NewOutputManager(baseDir string) *OutputManager`
- Creates `<Hostname>_<YYYYMMDD_HHMMSS>/` directory structure
- Creates category subdirectories on demand
- `GetCategoryDir(category string) string`
- Thread-safe directory creation

#### [NEW] [metadata.go](file:///d:/Code/FIR/internal/output/metadata.go)
- Generates `metadata.json` with:
  - hostname, timestamp, OS version
  - list of artifacts collected
  - per-file hashes and sizes
  - collector version, duration
  - errors encountered

---

### Logging (`internal/logging/`)

#### [NEW] [logger.go](file:///d:/Code/FIR/internal/logging/logger.go)
- Dual-output logger:
  - **Console**: colored progress messages only (`[+]`, `[-]`, `[!]`)
  - **File**: full structured JSON logs to `logs/collector.log`
- `Info()`, `Error()`, `Success()`, `Progress()` methods
- Timestamps on all entries
- Elapsed time tracking per collector

---

### Utilities (`internal/utils/`)

#### [NEW] [privilege.go](file:///d:/Code/FIR/internal/utils/privilege.go)
- `IsAdmin() bool` — checks if running elevated
- `EnablePrivilege(name string) error` — enables `SeBackupPrivilege`, `SeDebugPrivilege`
- Uses `OpenProcessToken` → `LookupPrivilegeValue` → `AdjustTokenPrivileges`

#### [NEW] [filecopy.go](file:///d:/Code/FIR/internal/utils/filecopy.go)
- `SafeCopyFile(src, dst string) (FileInfo, error)` — copies file with simultaneous SHA-256
- Uses `FILE_FLAG_BACKUP_SEMANTICS` for locked file access
- Buffered I/O with 64KB chunks

#### [NEW] [hash.go](file:///d:/Code/FIR/internal/utils/hash.go)
- `HashFile(path string) (string, error)` — returns hex SHA-256
- `HashReader(r io.Reader) (string, error)`

---

### Documentation

#### [NEW] [README.md](file:///d:/Code/FIR/README.md)
- Project overview, build instructions
- CLI usage examples (both modes)
- Sample output structure
- Architecture diagram

---

## User Review Required

> [!IMPORTANT]
> **CLI Framework Choice**: Using `cobra` for commands + `survey/v2` for interactive menus. This gives us professional flag parsing AND interactive prompts without the complexity of a full TUI framework like Bubble Tea. The tool is a CLI utility, not a dashboard.

> [!IMPORTANT]
> **VSS Strategy**: Using `vssadmin` via `exec.Command` rather than COM interop. This is simpler, well-tested in DFIR tools, and avoids CGO. The trade-off is a subprocess spawn, but it's a one-time operation.

> [!WARNING]
> **RAM Acquisition**: Requires `winpmem` to be present alongside the executable or in PATH. The tool will NOT bundle winpmem (licensing). If winpmem is missing, the memory collector will skip gracefully with a warning.

> [!IMPORTANT]
> **Raw NTFS Access**: For $MFT, we'll use `FSCTL_GET_NTFS_VOLUME_DATA` + raw reads. For $UsnJrnl, we'll use `FSCTL_READ_USN_JOURNAL`. For locked registry/evtx files, we'll prefer `RegSaveKeyEx` (registry) or VSS fallback (everything else).

---

## Build & Execution Plan

### Phase 1 — Foundation (files: 8)
1. `go.mod`, `main.go`
2. `internal/collector/collector.go`, `internal/collector/registry.go`
3. `internal/logging/logger.go`
4. `internal/utils/privilege.go`, `internal/utils/filecopy.go`, `internal/utils/hash.go`

### Phase 2 — Output & Acquisition (files: 4)
5. `internal/output/writer.go`, `internal/output/metadata.go`
6. `internal/acquisition/rawdisk.go`, `internal/acquisition/shadowcopy.go`

### Phase 3 — Collectors (files: 9)
7. `internal/registry/registry.go`
8. `internal/eventlog/eventlog.go`
9. `internal/execution/prefetch.go`, `internal/execution/amcache.go`
10. `internal/system/wmi.go`, `internal/system/srum.go`
11. `internal/ntfs/mft.go`, `internal/ntfs/usnjrnl.go`, `internal/ntfs/secure.go`
12. `internal/memory/memory.go`

### Phase 4 — CLI (files: 3)
13. `cmd/root.go`, `cmd/collect.go`
14. `internal/cli/interactive.go`

### Phase 5 — Polish (files: 1)
15. `README.md`

---

## Verification Plan

### Automated Tests
```powershell
# Build
go build -o fir.exe .

# Help output
.\fir.exe --help
.\fir.exe collect --help

# Flag mode (safe artifacts only — no RAM)
.\fir.exe collect --artifact registry,eventlog,prefetch --output C:\triage

# Verify output structure
dir C:\triage\<hostname>_*\
type C:\triage\<hostname>_*\metadata.json
```

### Manual Verification
- Confirm output directory naming: `<Hostname>_<YYYYMMDD_HHMMSS>`
- Verify metadata.json contains correct fields and hashes
- Verify registry hives are valid (can be opened in Registry Explorer)
- Verify .evtx files are valid (can be opened in Event Viewer)
- Confirm collector.log contains structured entries
- Confirm CLI output shows only progress, no raw data
