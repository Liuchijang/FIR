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

Tyto is a Windows first-response triage tool: it collects forensic artifacts, parses them into CSV, and packages the run with integrity metadata. Collectors and analyzers sit behind a shared module contract, and one engine drives both an interactive terminal UI and a flag-driven CLI.

## Features

- **Two modes**: an interactive Bubble Tea workflow, or `tyto collect` for automation. Collectors run alone by default; `--analyze` adds the matching parsers.
- **Native Windows acquisition**: backup semantics, registry hive save APIs, and raw NTFS reads — `$MFT`, `$UsnJrnl:$J` and `$Secure:$SDS` from every fixed drive, not just `C:`. Requires Administrator, and enables the backup, restore, security and debug privileges at startup.
- **Parses what it collects**: `$MFT`, the USN journal, `$Secure:$SDS`, EVTX, Amcache, Prefetch, ShimCache, UserAssist, RecentDocs, RunMRU, WMI, the SRUM database, and browser history, downloads, cookies, saved-login metadata, autofill, bookmarks, extensions and profile settings. Every timestamp column in every CSV uses one RFC3339 UTC layout, so the halves of an output directory join on time without reformatting.
- **Self-tuning concurrency**: no worker knob. Tyto surveys the drives a run reads and writes, then picks a worker count per phase — collection backs off on spinning media, analysis scales with free RAM. The numbers and the reasoning land in `manifest.json`.
- **Caps that reach child processes**: CPU and disk limits go through a Windows Job Object, so `winpmem` and the PowerShell-hosted analyzers are covered rather than quietly exempt. Disk throttling is opt-in.
- **Partial-failure tolerant**: a module fails only if it collected nothing; partial errors surface as warnings instead of hiding the artifacts that did come through.
- **Hashed on the way out**: every artifact is SHA-256'd as it is written rather than read back afterwards, including the ZIP itself. `manifest.json` records a digest per file, and browser artifacts are qualified by user, browser and profile so an entry names exactly one file.
- **Structured output**: `manifest.json`, `summary.txt`, `collector.log`, a storage estimate before the run, and an optional ZIP with a `.sha256` sidecar.

Tyto does not decrypt browser secrets. Cookie values and saved passwords are exported as hex beside a column naming the scheme that wrapped them, because Chrome 127+ App-Bound Encryption is tied to the machine that created it and is worth telling apart from the older DPAPI-keyed form before anyone spends time on recovery. The encrypted stores themselves are collected intact.

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
- **Privileges**: Administrator is required — Tyto exits immediately with an error if not run elevated
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

`-trimpath` keeps the build machine's directory layout out of the binary,
`-buildvcs=false` keeps the commit hash out of it, and `-ldflags "-s -w"` drops
the symbol table and DWARF data. Together they take the binary from 13.9 MB to
**9.4 MB**, a third smaller, and stop it carrying anything about where it was
built. Drop all three while developing — `go build -o tyto.exe .` is faster and
keeps stack traces readable.

3. Check it runs:

```powershell
.\tyto.exe --version
# tyto version 1.3
```

There is nothing to install alongside it. Every dependency is pure Go, so the
result is one static executable — the only optional external file is `winpmem`
for RAM acquisition (see below).

The application icon needs no build step either: the Go linker picks up any
`*.syso` next to the main package, and `tyto_windows_amd64.syso` is committed.

To change the icon, redraw `tyto.png` and regenerate both files:

```powershell
go run ./tools/mkico -in tyto.png -out tyto.ico -sheet preview.png
go run github.com/akavel/rsrc@latest -ico tyto.ico -arch amd64 -o tyto_windows_amd64.syso
```

`mkico` crops the drawing to a centred square and area-averages it down to the
nine sizes Windows chooses between, keeping the source's transparency. `-sheet`
writes a preview over a light and a dark surface, which is worth looking at: the
owl is a black silhouette, so on a dark-mode taskbar its body merges into the
background and the small sizes read as two floating eyes. `-bg RRGGBB` flats it
onto a colour if that is ever unwanted. `rsrc` runs via `go run pkg@version`, so
neither tool is a module dependency.

## Usage

### Interactive Mode

Run Tyto without a subcommand:

```powershell
.\tyto.exe
```

Interactive mode lets you select modules, review runtime configuration, watch live module status, and view the final collection summary.

### Flag Mode

`tyto collect` runs collector modules only by default — analyzers (`*_parser`, `autoruns`, `process_explorer`, etc.) are skipped even if a category or `all` would otherwise include them.

Collect specific artifacts:

```powershell
.\tyto.exe collect --artifact registry,eventlog,prefetch
```

Collect by category:

```powershell
.\tyto.exe collect --artifact ntfs,execution
```

Collect everything:

```powershell
.\tyto.exe collect --artifact all
```

Collect and then run the matching analyzers:

```powershell
.\tyto.exe collect --artifact eventlog --analyze
```

Use a custom output directory and timeout:

```powershell
.\tyto.exe collect --artifact registry,eventlog --output C:\triage --timeout 10m
```

Run with resource controls:

```powershell
.\tyto.exe collect --artifact all --output E:\evidence --cpu-limit 60 --disk-io 80MB
```

Disable compression:

```powershell
.\tyto.exe collect --artifact ntfs --no-compress
```

### Common Flags

| Flag | Description |
|---|---|
| `-o, --output` | Base output directory for collected artifacts |
| `-v, --verbose` | Enable verbose/debug output |
| `-a, --artifact` | Comma-separated list of artifacts or categories |
| `--analyze` | Also run the analyzer modules for the selected artifacts/categories (default: collect only) |
| `-t, --timeout` | Optional timeout per module; `0` disables timeout |
| `--cpu-limit` | CPU limit percentage, applied to Tyto and every process it spawns via a Windows Job Object |
| `--disk-io` | Cap disk bandwidth for Tyto and every process it spawns, for example `80MB`. No cap by default |
| `--compress` | Compress run directory after collection; enabled by default |
| `--no-compress` | Disable run directory compression |

## Available Modules

### Collectors

| Name | Category | Description |
|---|---|---|
| `browser` | `browser` | Collects browser artifacts from Chromium and Firefox profiles: history, cookies, credential stores, bookmarks, preferences, session files, the flat LevelDB stores (Local Storage, Session Storage, Platform Notifications, Service Worker, Sync Data), and extension manifests without the extension payloads. `IndexedDB` and the HTTP cache are left out — hundreds of megabytes per profile for artifacts nothing here parses yet |
| `eventlog` | `eventlog` | Collects Windows Event Log files (`.evtx`) |
| `amcache` | `execution` | Collects `Amcache.hve` and transaction logs |
| `prefetch` | `execution` | Collects Windows Prefetch files (`.pf`) |
| `ram` | `memory` | Acquires physical memory using `winpmem` |
| `mft` | `ntfs` | Collects the `$MFT` via raw disk access, from every fixed drive |
| `secure_sds` | `ntfs` | Collects the `$Secure:$SDS` stream, from every fixed drive |
| `usnjrnl` | `ntfs` | Collects the `$UsnJrnl:$J` USN Change Journal, from every fixed drive |
| `registry` | `registry` | Collects primary registry hives and transaction logs (excludes `SECURITY`, which requires `SYSTEM`, not just Administrator) |
| `srum` | `system` | Collects the SRUM database (`SRUDB.dat`) |
| `wmi` | `system` | Collects WMI repository files |

### Analyzers

| Name | Category | Description |
|---|---|---|
| `autoruns` | `live` | Generates live autoruns-style triage CSV |
| `process_explorer` | `live` | Generates live process, module, and network triage CSV |
| `amcache_parser` | `execution` | Parses Amcache artifacts |
| `browser_history_parser` | `browser` | Parses visits and downloads from Chromium `History` and Firefox `places.sqlite`. Downloads carry the redirect chain and the decoded Safe Browsing verdict |
| `browser_cookies_parser` | `browser` | Parses cookie metadata — host, path, creation, expiry, last access, `Secure`/`HttpOnly`/`SameSite` — from every cookie store a profile has |
| `browser_credentials_parser` | `browser` | Parses saved-login metadata and autofill from `Login Data`, `Web Data`, `logins.json` and `formhistory.sqlite`. Separate from the other browser analyzers so a triage can skip the most sensitive artifacts |
| `browser_profile_parser` | `browser` | Parses bookmarks with folder paths, installed extensions with their permissions and content scripts, selected profile settings, omnibox shortcuts, media history and DIPS bounce records |
| `eventlog_parser` | `eventlog` | Parses EVTX logs |
| `mft_parser` | `ntfs` | Parses `$MFT` into CSV, streaming one row per record with resolved full paths |
| `prefetch_parser` | `execution` | Parses Prefetch artifacts |
| `recentdocs_parser` | `registry` | Parses RecentDocs entries |
| `runmru_parser` | `registry` | Parses RunMRU entries |
| `secure_sds_parser` | `ntfs` | Parses Secure SDS data |
| `shimcache_parser` | `registry` | Parses ShimCache |
| `srum_parser` | `system` | Parses the SRUM database into one CSV per provider table, resolving application and user IDs through `SruDbIdMapTable`, network adapter types out of the interface LUID, and Wi-Fi profile names from the `SOFTWARE` hive |
| `userassist_parser` | `registry` | Parses UserAssist |
| `usnjrnl_parser` | `ntfs` | Parses USN records and enriches with MFT when available |
| `wmi_parser` | `system` | Parses WMI artifacts |

### Category Shortcuts

Use `browser`, `eventlog`, `execution`, `live`, `memory`, `ntfs`, `registry`, `system`, or `all`.

## Output

A run creates a timestamped directory. Collectors write under a directory named
for their artifact; every analyzer writes under `Analyzer/<module>/`:

```text
HOSTNAME_YYYYMMDD_HHMMSS/
  collector.log
  manifest.json
  summary.txt
  browser/<user>/<browser>/<profile>/
  eventlog/
  execution/                   Amcache.hve and its transaction logs
  execution/prefetch/
  memory/                      only until the image is moved out, see below
  ntfs/                        $MFT, $UsnJrnl:$J and $Secure:$SDS, one per drive
  registry/
  registry/users/<user>/        NTUSER.DAT and UsrClass.dat
  system/                      SRUDB.dat
  system/wmi/
  Analyzer/mft_parser/
  Analyzer/usnjrnl_parser/
  Analyzer/srum_parser/
  Analyzer/browser_history_parser/
  ...                          one directory per analyzer that produced output
```

The run directory is created fresh every time: if a directory of that name
already exists, Tyto takes the next free name rather than writing into it, because
the run ends by archiving that path and then deleting it.

When compression is enabled, Tyto writes:

```text
HOSTNAME_YYYYMMDD_HHMMSS.zip
HOSTNAME_YYYYMMDD_HHMMSS.zip.sha256
```

A collected memory image is delivered **next to** the archive rather than inside it:

```text
HOSTNAME_YYYYMMDD_HHMMSS_memory.raw
```

A RAM dump is high-entropy and barely compresses, while zipping it would need a second full-size copy on disk at the same time — on a 32GB host, the difference between needing ~38GB free and ~69GB. The interactive run config says so before the run starts, and `manifest.json` lists the file under `uncompressed_files`.

`manifest.json` is the source of truth for run configuration, storage estimates, module results, hashes, and output metadata.

## RAM Acquisition

Tyto does not bundle `winpmem`. To enable RAM acquisition, place `winpmem_mini_x64.exe` in one of these locations:

- Same directory as `tyto.exe`
- Current working directory
- System `PATH`

If `winpmem` is not found, the RAM module fails gracefully and records the error in the run summary.

## Project Structure

```text
Tyto/
  cmd/                 Cobra commands and runtime option parsing
  internal/
    acquisition/       Low-level Windows and raw disk acquisition helpers
    analyzers/         Parsed and enriched output modules
    artifact/          Artifact layout helpers
    collection/        Module resolution, runner, and executor
    collectors/        Artifact acquisition modules grouped by category
    console/           Console/window handling
    logging/           Session logger
    module/            Shared collector/analyzer module contracts and registry
    ntfs/              Record primitives shared by the raw-volume reader and the parsers
    output/            Manifest, archive, summary, and output writer
    platform/          Host/platform helpers
    resource/          Resource config, estimates, and disk checks
    tui/               Bubble Tea interactive UI
    utils/             Windows privilege, hashing, and file helpers
  main.go              Application entry point
  go.mod               Go module definition
  go.sum               Go dependency checksums
```

Runtime flow:

```text
main -> cmd -> module registry -> collection runner -> collectors/analyzers -> output/logging
```

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
