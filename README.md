# Tyto

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/Liuchijang/Tyto?style=for-the-badge)](https://github.com/Liuchijang/Tyto/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Liuchijang/Tyto?style=for-the-badge)](https://github.com/Liuchijang/Tyto/network)
[![GitHub issues](https://img.shields.io/github/issues/Liuchijang/Tyto?style=for-the-badge)](https://github.com/Liuchijang/Tyto/issues)
[![GitHub license](https://img.shields.io/github/license/Liuchijang/Tyto?style=for-the-badge)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)

**A Windows DFIR artifact collection and triage tool written in Go.**

*Named for* Tyto alba, *the barn owl: quiet on the wire, everything on the record.*

</div>

![Tyto interactive collection progress](docs/assets/tyto-interactive-progress.png)

## Overview

Tyto collects Windows forensic artifacts from a running machine, parses them into
CSV, and packages the run with a SHA-256 per file. Collection happens on the
affected host; `tyto analyze --input` parses that run later on the investigator's
machine, with no access to the live system.

## Features

- **Three ways to run** — interactive TUI, `tyto collect` for automation, `tyto analyze` for a run collected earlier.
- **Collect here, analyze there** — `analyze --input` re-hashes every artifact against the source manifest, never falls back to the live host, and names the output after the subject rather than the machine parsing it.
- **Native acquisition** — backup semantics, registry hive save APIs, and raw NTFS reads of `$MFT`, `$UsnJrnl:$J` and `$Secure:$SDS` from every fixed drive. A locked file gets three escalating attempts.
- **Parses what it collects** — 15 collectors and 18 analyzers over NTFS, event logs, execution artifacts, jump lists, shell links, the registry, WMI, SRUM and browsers. See [Available Modules](#available-modules).
- **Reads evidence without changing it** — event logs are parsed from a staged copy, because opening a dirty `.evtx` makes Windows rewrite it. Registry hives are parsed from the file, not mounted.
- **Nothing is lost quietly** — a partial result warns instead of hiding what came through, a file that copies as all zeroes is flagged, and a record that will not parse still gets a row saying why.
- **One timestamp rule** — every timestamp column is RFC3339 in UTC and holds the artifact's own instant; a value that cannot be resolved leaves the cell empty.
- **No worker knob** — workers are derived from the storage topology per phase, and CPU and disk caps go through a Job Object so child processes are covered too.
- **Hashed on the way out** — artifacts are SHA-256'd as they are written, the ZIP included.
- **Cross-checked against JLECmd** — 27 of 35 shared fields identical across 2,133 jump list entries.

Tyto does not decrypt browser secrets: cookie values and saved passwords are exported as hex beside the scheme that wrapped them, and the encrypted stores are collected intact.

## Tech Stack

**Language**

![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?style=for-the-badge&logo=go&logoColor=white)

**CLI and TUI**

![Cobra](https://img.shields.io/badge/Cobra-CLI-6415ff?style=for-the-badge)
![Bubble Tea](https://img.shields.io/badge/Bubble_Tea-TUI-FF75B7?style=for-the-badge)
![Lip Gloss](https://img.shields.io/badge/Lip_Gloss-Terminal_UI-7D56F4?style=for-the-badge)

**Windows and Storage**

![x/sys](https://img.shields.io/badge/golang.org%2Fx%2Fsys-Windows_APIs-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![SQLite](https://img.shields.io/badge/modernc.org%2Fsqlite-Embedded_SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![go-ese](https://img.shields.io/badge/go--ese-ESE%2FJET_Blue-4B8BBE?style=for-the-badge)

`modernc.org/sqlite` reads browser databases and `www.velocidex.com/golang/go-ese` reads the SRUM database's ESE format. Both are pure Go, so a release build stays a single static `tyto.exe` with no runtime dependencies.

## Quick Start

### Prerequisites

- **Operating system**: Windows 10/11 or Windows Server 2016+
- **Privileges**: Administrator for anything that acquires artifacts — interactive mode and `tyto collect` exit immediately with an error if not run elevated. `tyto analyze` is the exception and runs as a normal user, because it reads files the operator already holds
- **Go**: 1.26+ for building from source

### Installation

1. Clone the repository:

```powershell
git clone https://github.com/Liuchijang/Tyto.git
cd Tyto
```

2. Build the executable:

```powershell
go build -trimpath -buildvcs=false -ldflags "-s -w" -o tyto.exe .
```

## Usage

There are three ways to run Tyto, and they differ in **where an analyzer reads
its sample from**. That is the part worth getting right: it decides which machine
the CSVs describe.

| How it is run | Analyzers read from | Administrator |
|---|---|---|
| `collect --artifact <category> --analyze` | the artifacts this run just collected | required |
| `analyze` with no `--input` | the live machine | required |
| `analyze --input <run\|zip>` | only the input, never the live machine | not required |

There is no fallback between them. An analyzer that should read a collected
artifact and cannot reports `SKIPPED` or `FAILED` rather than quietly answering
from somewhere else, so a CSV never describes a source other than the one
`manifest.json` names.

### Interactive

Run Tyto without a subcommand:

```powershell
.\tyto.exe
```

Interactive mode lets you select modules, review runtime configuration, watch live module status, and view the final collection summary.

### tyto collect

Acquires artifacts from the machine it runs on. Collector modules only by default
— analyzers (`*_parser`) are skipped even if a category or `all` would otherwise
include them, and `--analyze` opts into them. `autoruns` and `process_explorer`
are collectors, so they run without it.

```powershell
.\tyto.exe collect --artifact registry,eventlog,prefetch     # by module name
.\tyto.exe collect --artifact ntfs,execution                 # by category
.\tyto.exe collect --artifact all                            # everything
.\tyto.exe collect --artifact ntfs --analyze                 # collect, then parse what was collected
.\tyto.exe collect --artifact registry --output C:\triage --timeout 10m
.\tyto.exe collect --artifact all --output E:\evidence --cpu-limit 60 --disk-io 80MB
.\tyto.exe collect --artifact ntfs --no-compress
```

**`--analyze` follows categories, not module names.** `--artifact ntfs --analyze`
adds `mft_parser`, `usnjrnl_parser` and `secure_sds_parser` because `ntfs` is a
category; `--artifact mft --analyze` adds nothing at all, because `mft` names one
module and that module is a collector. The flag is silently a no-op there. Use a
category name, or list the parsers explicitly:

```powershell
.\tyto.exe collect --artifact mft,mft_parser --analyze
```

| Flag | Description |
|---|---|
| `-a, --artifact` | Comma-separated modules or categories, or `list` to print every module with its description. Required |
| `--analyze` | Also run the analyzers for the selected categories. Off by default |
| `-o, --output` | Base directory the run directory is created in. Defaults to `.` |
| `-t, --timeout` | Timeout per module; `0` (the default) disables it |
| `--cpu-limit` | CPU cap for Tyto and every process it spawns, via a Windows Job Object. Defaults to 60, clamped to 10–80 |
| `--disk-io` | Disk bandwidth cap for Tyto and every process it spawns, e.g. `80MB`. No cap by default |
| `--compress` / `--no-compress` | Zip the run directory when finished. **On** by default |
| `-v, --verbose` | Verbose/debug output |

### tyto analyze

Runs analyzer modules. `--input` decides which machine they describe, and that is
the only difference between the two ways to call it.

```powershell
# Offline: parse a run collected earlier, on the investigator's machine.
.\tyto.exe analyze --input D:\evidence\HOST_20260812_134006.zip        # a compressed run, what collect leaves by default
.\tyto.exe analyze --input D:\evidence\HOST_20260812_134006 -o D:\cases\1234
.\tyto.exe analyze --input HOST_20260812_134006.zip --artifact ntfs,eventlog

# Live: no --input, so the analyzers read this machine. Requires Administrator.
.\tyto.exe analyze --artifact shimcache_parser,prefetch_parser
.\tyto.exe analyze --artifact wmi_parser                               # carve the live OBJECTS.DATA, plus a CIM query
```

| Flag | Description |
|---|---|
| `-i, --input` | The run directory or `.zip` to analyze. Omit it to analyze the live machine instead |
| `-a, --artifact` | Comma-separated analyzers or categories, or `list` to print every module with its description. Defaults to `all` |
| `--keep-extracted` | Keep the directory an input archive was extracted into, instead of removing it when the run ends |
| `-o, --output` | Base directory the analysis run directory is created in. Defaults to `.` |
| `-t, --timeout` | Timeout per analyzer; `0` (the default) disables it |
| `--cpu-limit` | CPU cap for Tyto and every process it spawns, via a Windows Job Object. Defaults to 60, clamped to 10–80 |
| `--disk-io` | Disk bandwidth cap for Tyto and every process it spawns, e.g. `80MB`. No cap by default |
| `--compress` | Zip the analysis output when finished. **Off** by default, unlike collection — the output is CSV an analyst opens straight away |
| `-v, --verbose` | Verbose/debug output |

There is no `--no-compress` here; compression is already off unless `--compress`
asks for it.

## Available Modules

### Collectors

| Name | Category | Description |
|---|---|---|
| `browser` | `browser` | Collects browser artifacts from Chromium and Firefox profiles: history, cookies, credential stores, bookmarks, preferences, session files, the flat LevelDB stores (Local Storage, Session Storage, Platform Notifications, Service Worker, Sync Data), and extension manifests without the extension payloads. `IndexedDB` and the HTTP cache are left out — hundreds of megabytes per profile for artifacts nothing here parses yet |
| `eventlog` | `eventlog` | Collects Windows Event Log files (`.evtx`) |
| `amcache` | `execution` | Collects `Amcache.hve` and transaction logs |
| `prefetch` | `execution` | Collects Windows Prefetch files (`.pf`) |
| `jumplist` | `execution` | Collects jump lists per user profile: both `AutomaticDestinations` and `CustomDestinations`, including the `.temp` files Windows leaves behind mid-write — on one measured host those held 155 embedded links against 120 in the finished files |
| `recentfiles` | `execution` | Collects the shell links a user leaves when opening a document, from **two** folders: `Windows\Recent` and `Office\Recent`. Office keeps its own MRU, and only that copy survives a user clearing the shell's list |
| `ram` | `memory` | Acquires physical memory using `winpmem` |
| `mft` | `ntfs` | Collects the `$MFT` via raw disk access, from every fixed drive |
| `secure_sds` | `ntfs` | Collects the `$Secure:$SDS` stream, from every fixed drive |
| `usnjrnl` | `ntfs` | Collects the `$UsnJrnl:$J` USN Change Journal, from every fixed drive |
| `autoruns` | `live` | Captures autostart configuration from the running system: services, run keys per machine and per user SID, scheduled tasks with their actions and triggers, and every startup folder. **Live state, not an artifact** |
| `process_explorer` | `live` | Captures running processes with command lines and owners, every loaded module, and TCP/UDP connections joined to the owning process. Falls back to `netstat -ano` where the `Get-Net*` cmdlets are unavailable. **Live state, not an artifact** |
| `registry` | `registry` | Collects primary registry hives and transaction logs (excludes `SECURITY`, which requires `SYSTEM`, not just Administrator) |
| `srum` | `system` | Collects the SRUM database (`SRUDB.dat`) |
| `wmi` | `system` | Collects WMI repository files |

### Analyzers

Most analyzers read an artifact, so they work against a collected run or the live
machine, so every one of them is available to `analyze --input`.

`autoruns` and `process_explorer` are **collectors**, listed above. They acquire
state that exists only while the machine is running, and the runner finishes every
collector before it starts any analyzer — so as analyzers they captured the most
volatile data in a run only after every artifact had been copied, a memory image
included. Use `collect` for them, not `analyze`.

| Name | Category | Description |
|---|---|---|
| `amcache_parser` | `execution` | Parses Amcache artifacts |
| `browser_history_parser` | `browser` | Parses visits and downloads from Chromium `History` and Firefox `places.sqlite`. Downloads carry the redirect chain and the decoded Safe Browsing verdict |
| `browser_cookies_parser` | `browser` | Parses cookie metadata — host, path, creation, expiry, last access, `Secure`/`HttpOnly`/`SameSite` — from every cookie store a profile has |
| `browser_credentials_parser` | `browser` | Parses saved-login metadata and autofill from `Login Data`, `Web Data`, `logins.json` and `formhistory.sqlite`. Separate from the other browser analyzers so a triage can skip the most sensitive artifacts |
| `browser_profile_parser` | `browser` | Parses bookmarks with folder paths, installed extensions with their permissions and content scripts, selected profile settings, omnibox shortcuts, media history and DIPS bounce records |
| `eventlog_parser` | `eventlog` | Parses EVTX logs |
| `jumplist_parser` | `execution` | Parses jump lists: the DestList of each automatic file and the LNK bodies both kinds wrap. Reports what was opened, in what order, on which machine, from which volume, and the target's own size, timestamps and `$MFT` position. Three CSVs: a row per file (including the empty ones), a row per DestList entry, and a row per link in a custom destinations file |
| `mft_parser` | `ntfs` | Parses `$MFT` into CSV, streaming one row per record with resolved full paths |
| `prefetch_parser` | `execution` | Parses Prefetch records, decompressing the Windows 10/11 container first. Reports up to **eight execution timestamps** per program with the run count, the volumes it touched with their serials and creation times, and every file and directory the traced runs loaded. Versions 17 through 31 (XP to Windows 11). Four CSVs: per-record summary, a run-time timeline, volumes, and path references |
| `recentdocs_parser` | `registry` | Parses RecentDocs entries |
| `recentfiles_parser` | `execution` | Parses Recent and Office Recent shell links. Carries the link file's own creation and modification times — the first and last time that document was opened — alongside everything the link records about the target, including the serial and label of a volume that has since been unplugged |
| `runmru_parser` | `registry` | Parses RunMRU entries |
| `secure_sds_parser` | `ntfs` | Parses Secure SDS data |
| `shimcache_parser` | `registry` | Parses ShimCache |
| `srum_parser` | `system` | Parses the SRUM database into one CSV per provider table, resolving application and user IDs through `SruDbIdMapTable`, network adapter types out of the interface LUID, and Wi-Fi profile names from the `SOFTWARE` hive |
| `userassist_parser` | `registry` | Parses UserAssist |
| `usnjrnl_parser` | `ntfs` | Parses USN records, joining in each record's `$MFT` name, path and timestamps when `mft` or `mft_parser` is part of the run |
| `wmi_parser` | `system` | Reports WMI event-subscription persistence from two sources. It carves `__FilterToConsumerBinding`, `__EventFilter` and the consumer records out of `OBJECTS.DATA` — the run's collected copy, or the live host's file — which is what makes it work offline and what lets it recover subscriptions already deleted from the repository. When analyzing the live machine it additionally queries `root\subscription` for the authoritative current view plus the namespace tree. The two sets of CSVs keep separate names because they are separate evidence |

### Category Shortcuts

Use `browser`, `eventlog`, `execution`, `live`, `memory`, `ntfs`, `registry`,
`system`, or `all`. A category name selects every module in it, collectors and
analyzers alike. `live` is the one exception in practice: it now holds only
collectors, so `collect --artifact live` runs both of them and
`analyze --artifact live` has nothing to run.

Both lists above are also available from the binary, generated from the module
registry rather than transcribed — `tyto collect --help` prints each category with
the modules in it, and `--artifact list` prints every module with its description.

## Timestamps

**Every timestamp column in every CSV is RFC3339 in UTC, and the value is the
artifact's own.** Nothing is re-based on the way out: a FILETIME, a WebKit
microsecond count and a PE `TimeDateStamp` are already UTC where they are stored,
so the instant in the CSV is the instant in the artifact. Most column names carry
a `UTC` suffix to say so.

Two properties worth knowing before comparing Tyto's output against another tool:

- **A timestamp column holds an instant or it is empty** — never the raw integer,
  never `N/A`. Importers bind such a column to a date type and reject the *whole
  file* over one cell that will not convert, so a value Tyto cannot resolve costs
  one blank cell rather than the artifact.
- **Sub-second precision survives.** The layout is RFC3339 *Nano*: a FILETIME
  carries 100ns and a USN journal records many events inside one second. A whole
  second renders with no fraction, so both forms parse as plain RFC3339.

| Module | Timestamp columns | What the artifact stores |
|---|---|---|
| `mft_parser` | `SI_CreatedUTC`, `SI_ModifiedUTC`, `SI_MFTModifiedUTC`, `SI_AccessedUTC`, and the four `FN_*UTC` equivalents | FILETIME — 100ns ticks since 1601-01-01 UTC |
| `usnjrnl_parser` | `TimestampUTC`, plus the `$MFT` times joined in when `mft`/`mft_parser` is in the run | FILETIME |
| `secure_sds_parser` | none — `$Secure:$SDS` carries no timestamps | — |
| `prefetch_parser` | `LastRunUTC`, `PreviousRun1..7UTC`, `RunUTC`, `VolumeCreatedUTC` | FILETIME, read from **inside the record**. That is the point: the execution times are in the file's bytes, so a collected copy carries them intact. The `.pf` file's own filesystem timestamps are not reported: everything they carried is inside the record |
| `jumplist_parser` | `LastModifiedUTC` | FILETIME in the DestList entry — when that item was last opened |
| | `DroidCreatedUTC`, `TrackerCreatedUTC` | The timestamp inside a version 1 UUID, counted in 100ns from **1582-10-15**. It dates the identifier, not the file — it has been observed tracking the machine's boot time — which is why neither column is named after a creation |
| `recentfiles_parser` | `LinkCreatedUTC`, `LinkModifiedUTC` | The `.lnk` file's own timestamps: the first and last time the document was opened. See *An artifact's own timestamps* below |
| both, from the embedded link | `TargetCreatedUTC`, `TargetModifiedUTC`, `TargetAccessedUTC` | FILETIME in the link header, describing the **target** as it was when the link was last written |
| `eventlog_parser` | `TimeCreatedUTC` | EVTX record `SystemTime` (FILETIME), rendered through .NET's round-trip `"o"` format under the invariant culture so the column never depends on the operator's regional settings |
| `amcache_parser` | `KeyLastWriteTimestamp`, `FileKeyLastWriteTimestamp` | Hive key last-write FILETIME |
| | `DriverTimeStamp` | A `REG_DWORD` holding the driver's PE `TimeDateStamp` — Unix epoch **seconds**, not a FILETIME |
| | `DriverVerDate`, `Date`, `DriverLastWriteTime`, `LinkDate` | Text values inside the hive — see the caveat below |
| `shimcache_parser` | `LastModifiedUTC`, `LastUpdateUTC` | FILETIME inside the cache entry |
| `userassist_parser` | `LastExecutedUTC`, `KeyLastWriteTimestamp` | FILETIME in the value blob and on the hive key. `FocusTimeMS` beside them is a **duration** in milliseconds, not an instant |
| `recentdocs_parser`, `runmru_parser` | `KeyLastWriteTimestamp` | Hive key last-write FILETIME |
| `srum_parser` | per provider table — `ConnectStartTime`, `*TimeStamp`, … | FILETIME for most columns and an ESE `DateTime` for others; both are accepted. `ConnectedTime` is a **duration** in seconds and is added to the row's start time rather than printed |
| `browser_*_parser`, Chromium | `VisitTimeUTC`, `LastVisitUTC`, `CreationUTC`, `ExpiresUTC`, `DateAddedUTC`, … | Microseconds since **1601-01-01** (the WebKit epoch) |
| `browser_*_parser`, Firefox | the same columns | Microseconds since **1970-01-01** — except `logins.json`, which uses **milliseconds** |
| `browser_profile_parser` | the Media History columns | Unix epoch **seconds** |
| `autoruns`, `process_explorer` (collectors) | `LastRunTimeUTC`, `NextRunTimeUTC`, `LastWriteTimeUTC`, `CreationDateUTC`, `CreationTimeUTC` | A .NET `DateTime` in **local** time, converted by `ConvertTo-TytoUtc`. Along with `eventlog_parser` these are the only paths that convert rather than re-render, because .NET hands the script local time |
| `wmi_parser` | none | The object store keeps no creation time for a subscription and the CIM query selects no date-bearing property, so no column is named after one |


### An artifact's own timestamps

Copying a file does not preserve its timestamps, so a collected artifact carries
the moment Tyto wrote it rather than the moment the subject's machine did. For
most artifacts that costs nothing — the evidence is inside the file. For a Recent
folder's `.lnk` it is the evidence: the link is created the first time a document
is opened and rewritten every time after.

So the collector records the source's own creation and modification times as it
copies, and `manifest.json` carries them per file:

```json
{
  "path": "users\\alice\\Recent\\report.docx.lnk",
  "sha256": "…",
  "size": 1234,
  "source_created": "2026-03-31T09:05:01.8065995Z",
  "source_modified": "2026-09-03T06:47:06.0013361Z"
}
```

An analyzer reads them back from that record offline, and stats the file directly
when it is reading the live host — both render identically, so a row does not say
which mode produced it. The access time is deliberately not recorded: Windows
updates it inconsistently and disables it outright for many operations.

The copy itself still does not preserve times, and that is deliberate. Collected
files carrying *collection* times is what made it possible to prove that a parser
was rewriting artifacts after the collector had hashed them, by showing the two
mtime windows did not overlap.

## RAM Acquisition

Tyto does not bundle `winpmem`. To enable RAM acquisition, place `winpmem_mini_x64.exe` in one of these locations:

- Same directory as `tyto.exe`
- Current working directory
- System `PATH`

If `winpmem` is not found, the RAM module fails gracefully and records the error in the run summary.

## Security and Legal Notice

Tyto is intended for authorized forensic investigation and incident response only. Run it only on systems where you have explicit permission to collect artifacts.

## Contributing

1. Fork the repository.
2. Create a feature or fix branch.
3. Keep changes focused and aligned with the module structure.
4. Update documentation when behavior changes.
5. Submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Support

- Issues: [GitHub Issues](https://github.com/Liuchijang/Tyto/issues)
- Repository: [Liuchijang/Tyto](https://github.com/Liuchijang/Tyto)

---

<div align="center">

**Star this repository if Tyto is useful for your incident response workflow.**

Made by [Liuchijang](https://github.com/Liuchijang)

</div>
