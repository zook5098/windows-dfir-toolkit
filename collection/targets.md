# KAPE Targets & Modules for IR Triage

This documents the curated `!Targets` and `!Modules` used by
[run_kape.ps1](run_kape.ps1) for a standard IR triage collection. The goal is
broad enough coverage to build a useful super-timeline (execution,
persistence, file activity, auth) without pulling a full disk image.

## Targets (what gets collected)

| Target | Why |
|---|---|
| `RegistryHives` | SYSTEM, SOFTWARE, SAM, NTUSER.DAT, USRCLASS.DAT — persistence keys, execution history, user activity |
| `EventLogs` | Security, System, PowerShell Operational, Sysmon (if present) — auth events, service creation, script block logging |
| `FileSystem` | Pulls `$MFT` / `$J` (USN Journal) — file creation/modification/deletion, timestomp detection |
| `Prefetch` | `C:\Windows\Prefetch` — program execution, run count, first/last run |
| `ScheduledTasks` | `C:\Windows\System32\Tasks` — persistence via scheduled tasks |
| `Amcache` | `Amcache.hve` — execution evidence that survives binary deletion |
| `LNKFilesAndFolders` | User `.lnk` shortcuts and jump lists — file/folder interaction, useful for insider or lateral-movement cases |

## Modules (what parses the collected data)

Each module is an EZ Tools binary KAPE invokes automatically against the
matching target output, writing normalized CSV into the module destination
folder.

| Module | Parses | Feeds normalize_kape.py as |
|---|---|---|
| `MFTECmd` | `$MFT`, `$J` (from `FileSystem`) | `mft` |
| `PECmd` | Prefetch `.pf` files | `prefetch` |
| `AppCompatCacheParser` | Shimcache (SYSTEM hive, from `RegistryHives`) | `shimcache` |
| `RECmd_DFIRBatch` | Registry hives via RECmd's `DFIRBatch.reb` batch (Run keys, Services, UserAssist, ASEPs, etc., from `RegistryHives`) | `registry` |
| `EvtxECmd` | EVTX event logs (from `EventLogs`) | `event_log` |
| `LECmd` | `.lnk` files (from `LNKFilesAndFolders`) | `lnk` |

## Invocation

`run_kape.ps1` runs targets and modules in a single KAPE invocation —
modules process straight out of the target destination, so there's no
separate second pass:

```powershell
kape.exe --tsource <SourceDrive> --tdest <TargetDestination> `
  --target RegistryHives,EventLogs,FileSystem,Prefetch,ScheduledTasks,Amcache,LNKFilesAndFolders `
  --mdest <ModuleDestination> `
  --module MFTECmd,PECmd,AppCompatCacheParser,RECmd_DFIRBatch,EvtxECmd,LECmd `
  --mflush
```

Module names are matched against your installed KAPE's actual `.mkape` catalog
(`Modules\EZTools\...\*.mkape`, `Modules\Compound\*.mkape`) — they don't
always match the underlying EZ Tools binary name. `RECmd` itself, for
example, isn't a module; the closest match for a single comprehensive
registry batch is `RECmd_DFIRBatch` (older KAPE versions shipped the same
idea as `Kroll_Batch.reb` under a plain `RECmd` module — the batch file and
module name were both renamed upstream). If a module gets skipped with
"Module `<name>` not found," confirm the real name with `kape.exe --mlist`
or by checking your `Modules` folder before assuming the target itself
failed to collect.

Both the target list and module list are overridable via `run_kape.ps1
-Targets` / `-Modules` for scoped, one-off collections (e.g. registry-only).

## Curated set vs. a KAPE compound target

`run_kape.ps1` can run in one of two target modes:

- **Curated (default)** — the scoped 7-target set above, chosen to feed the
  primary artifact types `parsers/normalize_kape.py` knows how to normalize.
  Fast and predictable output size: CSVs produced by the listed modules end
  up in the timeline, while unsupported output remains in the collection for
  manual review. In particular, `ScheduledTasks` is collected as raw evidence
  but does not yet have a configured module or normalizer.
- **KAPE compound target** (`-CompoundTarget <name>`) — hands off target
  selection to one of KAPE's own built-in `!`-prefixed presets instead,
  e.g. `-CompoundTarget SANS_Triage` (equivalent to `--target
  !SANS_Triage`). Compound targets bundle many more individual targets
  than this repo's curated set — broader coverage, but slower collection
  and more raw output that `normalize_kape.py` won't recognize (it skips
  any CSV whose header schema it doesn't match, so unmapped modules'
  output is simply left as raw KAPE/EZ Tools CSVs alongside the
  timeline rather than causing an error).

Popular built-in compound targets (exact set depends on your installed
KAPE version — run `kape.exe --tlist` to see what's actually available):

| Compound target | What it is |
|---|---|
| `!SANS_Triage` | SANS' community-maintained broad triage collection |
| `!BasicCollection` | KAPE's own general-purpose baseline collection |

`-Modules` still applies on top of a compound target — it doesn't need to
change, since modules only process the artifact types they match.

Use the curated set for fast, scoped IR triage where you already know
what you're looking for; reach for a compound target when you want KAPE's
broader standard preset instead, e.g. an unfamiliar host or a second pass.

## Adding a target or module

1. Confirm the KAPE target/module name via `kape.exe --tlist` / `--mlist`.
2. Add it to the default list in [run_kape.ps1](run_kape.ps1) (or pass it
   ad hoc via `-Targets` / `-Modules`).
3. Add a row to the tables above explaining what it collects and why it's
   relevant to triage.
4. If it's a new module, add a case to `parsers/normalize_kape.py` mapping
   its CSV output to the common schema.
