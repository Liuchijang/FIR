# FIR - Freedom Incident Response

FIR is a Windows DFIR artifact collection tool written in Go for fast triage, responder-friendly workflows, and low-friction extension. It supports both an interactive terminal UI and a flag-driven CLI so the same binary works for hands-on response and repeatable scripted collection.

## Highlights

- Interactive Bubble Tea workflow for module selection, browser profile review, EVTX targeting, and live progress tracking
- Flag-driven collection mode for automation and repeatable runs
- Built-in collectors and analyzers across `browser`, `eventlog`, `execution`, `live`, `memory`, `ntfs`, `registry`, and `system`
- Forensic-minded collection with SHA-256 hashing, structured output, and minimal artifact modification
- Native Windows handling for privileges, raw NTFS access, registry hives, and backup semantics where needed
- Concurrent execution with configurable per-module timeout and concurrency limits

## Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges for full collection coverage
- Go 1.21+ if building from source

## Build

```powershell
# Basic build
go build -ldflags "-s -w" -o fir.exe .

# Build with version metadata
go build -ldflags "-s -w -X github.com/Liuchijang/FIR/internal/output.Version=1.2.0" -o fir.exe .
```

## Quick Start

### Interactive mode

```powershell
.\fir.exe
```

Interactive mode is the default entry point. FIR opens a full-screen terminal UI where you can:

- Choose collector and analyzer modules from grouped lists
- Review browser profiles only when a browser module is selected
- Review EVTX targets only when the EVTX parser is selected
- Expand or collapse footer help with `?`
- Watch live module progress with waiting, running, success, and failed states
- Review a rendered terminal summary when the run completes

### Flag mode

```powershell
# Specific modules
.\fir.exe collect --artifact registry,eventlog,prefetch

# By category
.\fir.exe collect --artifact ntfs,execution

# Everything
.\fir.exe collect --artifact all

# Custom output directory and timeout
.\fir.exe collect --artifact registry,eventlog --output C:\triage --timeout 10m

# Verbose run with higher concurrency
.\fir.exe collect --artifact all --output E:\evidence --concurrency 4 -v
```

## Interactive UI Samples

These examples are illustrative terminal snapshots of the current UI flow.

### Module selection

```text
+------------------------------------------------------------------------------+
|  |-----||   O    |----\\                                                    |
|  |    --| |----| |   x  <|'                                                 |
|  |__|--'  |____| |__|\\__/                                                  |
|                                                                            |
|  FIR v1.2.0                                                                |
|  Freedom Incident Response                                                 |
|  Interactive module launcher                                               |
|                                                                            |
|                            Interactive Flow                                |
|                            Choose modules                                  |
|                            Review browser profiles                         |
|                            Run collection                                  |
+------------------------------------------------------------------------------+

Module Selection
3 modules selected.

Collector
  [x] [browser] browser                 -- Collects browser forensic artifacts...
> [x] [eventlog] eventlog               -- Collects Windows Event Log files...
  [ ] [execution] prefetch              -- Collects Windows Prefetch files...
  [ ] [execution] amcache               -- Collects Amcache.hve and logs...

Analyzer
  [ ] [browser] browser_history_parser  -- Parse browser history...
  [ ] [eventlog] eventlog_parser        -- Parse EVTX logs...

------------------------------------------------------------------------------
up/k move | pgdn page down | space toggle | ? toggle help | q quit
```

### Live collection progress

```text
+------------------------------------------------------------------------------+
|  |-----||   O    |----\\                                                    |
|  |    --| |----| |   x  <|'                                                 |
|  |__|--'  |____| |__|\\__/                                                  |
|                                                                            |
|  FIR v1.2.0                                                                |
|  Freedom Incident Response                                                 |
|  Interactive collection runner                                             |
|                                                                            |
|                              Collection                                    |
|                       * Running: 1 | Waiting: 3                            |
|                         Finished: 2/6 | Concurrency: 2                     |
|                       Monitor module progress                              |
+------------------------------------------------------------------------------+

Collecting Artifacts

[OK] SUCCESS  [eventlog]  eventlog            files=397  size=323.9 MiB  duration=3.4s
[OK] SUCCESS  [execution] prefetch            files=271  size=7.4 MiB    duration=8.0s
[-] FAILED   [memory]    ram                 duration=32ms  error=winpmem not found
| RUNNING    [live]      process_explorer
... WAITING  [registry]  registry
... WAITING  [system]    wmi

------------------------------------------------------------------------------
Live progress is streamed from running modules. 6 collectors loaded with
concurrency=2.
up/k scroll up | pgdn page down | ? toggle help | ctrl+c abort
```

After the run finishes, FIR writes a session summary to `summary.txt` and metadata to `metadata.json` in the generated output directory.

## Available Artifact Modules

| Name | Category | Description |
|---|---|---|
| `browser` | `browser` | Collect browser forensic artifacts from detected Chrome, Edge, Brave, Vivaldi, Firefox, Opera, and Opera GX profiles |
| `eventlog` | `eventlog` | Collect Windows Event Log files (`.evtx`) with forensic-priority ordering |
| `amcache` | `execution` | Collect `Amcache.hve` plus `Amcache.hve.LOG1/.LOG2` via native file access with hive-save and raw-volume fallback |
| `prefetch` | `execution` | Collect Windows Prefetch files (`.pf`) from `C:\Windows\Prefetch` |
| `autoruns` | `live` | Generate live autoruns-style triage CSV for services, Run keys, startup folders, and scheduled tasks |
| `process_explorer` | `live` | Generate live process, module, and network triage CSV from the running system |
| `ram` | `memory` | Acquire physical memory using `winpmem` |
| `mft` | `ntfs` | Collect the `$MFT` (Master File Table) via raw disk access |
| `secure_sds` | `ntfs` | Best-effort collection of the `$Secure:$SDS` stream via raw NTFS record parsing |
| `usnjrnl` | `ntfs` | Collect the `$UsnJrnl:$J` USN Change Journal via FSCTL |
| `registry` | `registry` | Collect primary registry hives plus `.LOG1/.LOG2` via backup semantics with hive-save fallback |
| `srum` | `system` | Collect the SRUM database (`SRUDB.dat`) via native Windows file access |
| `wmi` | `system` | Collect WMI repository files such as `OBJECTS.DATA`, `INDEX.BTR`, and `MAPPING*.MAP` |

## Available Analyzer Modules

| Name | Category | Description |
|---|---|---|
| `amcache_parser` | `execution` | Parse Amcache |
| `browser_history_parser` | `browser` | Parse browser history from collected browser profiles |
| `eventlog_parser` | `eventlog` | Parse EVTX logs |
| `mft_parser` | `ntfs` | Parse `$MFT` to CSV |
| `prefetch_parser` | `execution` | Parse Prefetch |
| `recentdocs_parser` | `registry` | Parse RecentDocs |
| `runmru_parser` | `registry` | Parse RunMRU |
| `secure_sds_parser` | `ntfs` | Parse Secure SDS |
| `shimcache_parser` | `registry` | Parse ShimCache |
| `userassist_parser` | `registry` | Parse UserAssist |
| `usnjrnl_parser` | `ntfs` | Parse USN and enrich with MFT data when selected |
| `wmi_parser` | `system` | Parse WMI |

Category shortcuts supported by `--artifact`:

- `all`
- `browser`
- `eventlog`
- `execution`
- `live`
- `memory`
- `ntfs`
- `registry`
- `system`

## Output Layout

Each run creates a session directory under the selected output root. FIR writes:

- Collected artifacts into category/module folders
- `collector.log` for the session log
- `metadata.json` for machine-readable run metadata
- `summary.txt` for the final run summary

A typical layout looks like this:

```text
triage/
  FIR_20260423_104512/
    collector.log
    metadata.json
    summary.txt
    browser/
    eventlog/
    execution/
    live/
    memory/
    ntfs/
    registry/
    system/
    Analyzer/
```

## RAM Acquisition

FIR does not bundle `winpmem` due to licensing. Place `winpmem_mini_x64.exe` in one of these locations:

- The same directory as `fir.exe`
- The current working directory
- A directory listed in `PATH`

If `winpmem` is missing, the RAM module fails cleanly and the error is shown in both the terminal UI and the run summary.

## Project Layout

```text
cmd/
  root.go
  collect.go
  interactive_progress.go

internal/
  acquisition/   low-level Windows and NTFS access helpers
  analyzers/     parsed and enriched output modules
  collectors/    artifact acquisition modules grouped by category
  console/       console and window handling
  logging/       session logging
  module/        shared module contract and registry
  output/        summary and metadata rendering
  tui/           Bubble Tea menu and terminal UI helpers
  utils/         generic helpers
```

Runtime flow:

```text
main -> cmd -> module registry -> collectors/analyzers -> output/logging
```

## Operational Notes

- Run as Administrator for best coverage, especially for raw NTFS, registry, memory, and protected system files.
- Collector modules run before analyzer modules in the same session.
- Timeouts are applied per module via `--timeout`.
- Parallelism is controlled with `--concurrency`.

## License

This project is intended for authorized forensic investigation and incident response only.
