# Windows DFIR Toolkit

Automated collection, parsing, and timelining of Windows host artifacts for rapid incident response triage. Built to compress the "acquire → parse → timeline" phase of an investigation from hours to minutes on a live or imaged host.

Windows-specific by design — this toolkit is built around KAPE, which only runs on Windows. Linux and Mac counterparts (built around UAC and Aftermath, respectively) are planned as separate sibling repos rather than folded into this one, since each platform's collection tooling and output format is different enough to warrant its own pipeline.

## Why this exists

During an active incident, analysts lose time hand-running a dozen tools (KAPE, RegRipper, Eric Zimmerman's tools, log parsers) and manually stitching output into a coherent timeline. This toolkit wraps that workflow into a single pipeline: point it at a host or image, get a normalized, sortable super-timeline plus a triage summary highlighting the artifacts most relevant to common intrusion patterns (persistence, lateral movement, execution, credential access).

Collection is handled by [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) itself (a curated Target/Module set — see [collection/targets.md](collection/targets.md)), rather than custom-built collectors/parsers. This toolkit's own code starts one step later: normalizing KAPE's EZ Tools CSV output and building the timeline.

## Architecture

```
collection/   -> run_kape.ps1 wraps KAPE with a curated Target/Module set for IR triage
                 targets.md documents which KAPE Targets/Modules are used and why
parsers/      -> normalize_kape.py reads KAPE's EZ Tools output CSVs (MFTECmd, PECmd,
                 AppCompatCacheParser, RECmd, EvtxECmd, LECmd, ...) and normalizes them
                 into a common schema
timeline/     -> build_timeline.py merges normalized records, tags rows with ATT&CK
                 techniques per docs/attack_mapping.yaml, and outputs a sorted timeline
                 build_db.py exports that timeline into exactly two output files:
                 timeline.db and a self-contained index.html dashboard (sql.js and its
                 WASM binary are inlined into it, so nothing else needs to travel with it)
                 viewer/ is the index.html template + vendored sql.js (SQLite-in-WASM)
                 that build_db.py renders from -- the dashboard runs real indexed SQL
                 queries against the .db client-side, so review scales to however
                 large a real timeline gets, up to a practical browser memory ceiling
                 serve_db.py is an alternative for timeline.db files past that ceiling:
                 a small local server (Python stdlib only) that queries the .db directly
                 off disk with no size limit, paired with server_viewer/'s dashboard
samples/      -> timeline.csv + dashboard/ show what a built timeline and its
                 exported dashboard look like end to end
docs/         -> methodology notes, ATT&CK mapping
```

## Artifacts covered (v1 scope)

| Artifact | Source | What it reveals |
|---|---|---|
| Prefetch | `C:\Windows\Prefetch` | Program execution, run count, first/last run |
| Windows Event Logs | Security, System, PowerShell, Sysmon | Auth events, service creation, script block logging |
| MFT | `$MFT` | File creation/modification/deletion, timestomping detection |
| Registry (Run keys, Services, UserAssist) | NTUSER.DAT, SYSTEM, SOFTWARE hives | Persistence, program execution history |
| Amcache / Shimcache | AmCache.hve, SYSTEM hive | Execution evidence even after deletion |
| Scheduled Tasks | `C:\Windows\System32\Tasks` | Persistence |

## Pipeline

1. **Collect** — `collection/run_kape.ps1` invokes KAPE (assumed installed and on PATH) against a live host or mounted image, collecting the Targets in `collection/targets.md` and running the matching EZ Tools Modules against them in a single pass.
2. **Normalize** — `parsers/normalize_kape.py` reads every module's CSV output and normalizes it into a common schema: `timestamp, host, artifact_type, action, detail, source_file`.
3. **Timeline** — `timeline/build_timeline.py` merges all normalized records, sorts by timestamp, and tags entries with likely ATT&CK techniques based on pattern rules in `docs/attack_mapping.yaml`.
4. **Review** — `timeline/build_db.py` exports the timeline CSV into a SQLite database and renders a matching `index.html` dashboard — sql.js (SQLite compiled to WebAssembly) is inlined directly into that HTML, so the two output files (`timeline.db` + `index.html`) are all that's needed, no server required and no separate files to keep track of. The dashboard (search, artifact-type filters, ATT&CK-tagged-only toggle, click-to-sort columns, pagination) runs real SQL queries against the `.db` client-side, and only the current page of results is ever loaded into the browser, so it scales to real timelines with hundreds of thousands of rows. See [Dashboard notes](#dashboard-notes) below for a practical size ceiling and `timeline/serve_db.py`, the alternative for databases past it. Or import the CSV into Timesketch directly.

## Quick start

**Prerequisites:**

- **Windows** — `run_kape.ps1` and KAPE itself are Windows-only. (The Python normalize/timeline/export steps are plain CSV/SQLite processing and will run on any OS once you have KAPE's output — but collection itself needs Windows.)
- **PowerShell** — Windows PowerShell 5.1+ or PowerShell 7+ (`pwsh`), to run `run_kape.ps1`.
- **Administrator privileges** — KAPE requires an elevated shell to collect from a live host; it exits immediately without one.
- **[KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)** — installed separately (free registration with Kroll required) and on `PATH`, or pass `-KapePath` to `run_kape.ps1`. Run KAPE's own updater (`Get-KAPEUpdate.ps1`, or gkape's "Update" button) at least once so its bundled EZ Tools binaries (MFTECmd, PECmd, etc.) and Target/Module definitions are actually present — a fresh KAPE download doesn't always have everything on first extract.
- **Python 3.8+** and `pip`, for the normalize/timeline/export steps.
- A source to collect from — the live machine itself (`-SourceDrive C:`), a mounted image, or a remote/UNC path KAPE can read.

```powershell
git clone https://github.com/zook5098/windows-dfir-toolkit
cd windows-dfir-toolkit
pip install -r requirements.txt

# Collect with KAPE (targets + modules in one pass)
# -CaseName should identify the subject system/case, not your own analysis machine
.\collection\run_kape.ps1 -SourceDrive C: -TargetDestination D:\triage\raw -ModuleDestination D:\triage\parsed -CaseName CASE-2026-014

# ...or collect with a KAPE built-in compound target instead of the curated set
.\collection\run_kape.ps1 -SourceDrive C: -TargetDestination D:\triage\raw -ModuleDestination D:\triage\parsed -CaseName CASE-2026-014 -CompoundTarget SANS_Triage

# Full usage, no need to open this README or targets.md
.\collection\run_kape.ps1 --help

# Normalize KAPE's module (EZ Tools) CSV output
python parsers/normalize_kape.py --input D:\triage\parsed\<run_folder> --output ./case001/normalized.csv --host HOSTNAME

# Build the tagged, sorted timeline
python timeline/build_timeline.py --input ./case001/normalized.csv --output ./case001/timeline.csv

# Export to a SQLite database + copy the dashboard alongside it
python timeline/build_db.py --input ./case001/timeline.csv --output ./case001/dashboard --title "CASE001"
```

Open `./case001/dashboard/index.html` directly (double-click) and use the file picker or drag-and-drop to load `timeline.db` from the same folder — or serve the folder over `http://` (e.g. `python -m http.server` from inside it) to have it auto-load `timeline.db` with no manual step. Both work; serving just skips the one click. (Browsers block a page from `fetch()`-ing local files under `file://`, which is why double-clicking can't auto-load — but everything else, including the SQLite engine itself, works identically either way.)

See [samples/timeline.csv](samples/timeline.csv) for what `build_timeline.py` output looks like, and [samples/dashboard/](samples/dashboard/) for a ready-to-open example dashboard (search, filters, ATT&CK tagging) without running the pipeline yourself.

### Dashboard notes

- **Opening directly (double-click) fully works** — sql.js's SQLite/WebAssembly engine is inlined into `index.html` itself specifically so it never needs to fetch anything to start, which sidesteps a real Chromium restriction (`file://` pages can't `fetch()` even their own bundled `.wasm` file).
- **Practical size ceiling**: the dashboard loads the whole `.db` into browser memory (indexed SQL queries run against it client-side, but the file itself is read in full). In testing, the browser's own file-reading APIs throw past roughly 1.5GB read as a single chunk — worked around here by reading large files in slices — and allocating one contiguous in-memory buffer above roughly 2GB fails outright regardless. Past that, the dashboard shows a clear error naming `serve_db.py` rather than hanging or failing silently.

**For a `timeline.db` too large for that ceiling**, use the server-backed dashboard instead:

```powershell
python timeline/serve_db.py --db ./case001/dashboard/timeline.db
```

This queries the `.db` directly off disk with Python's stdlib `sqlite3` — no size ceiling at all, since it's never loaded into memory as a whole. Verified end-to-end against a synthetic 3.27GB / 5-million-row database (matching real-world scale): sub-100ms responses for filtering, sorting, and pagination throughout. Free-text search is the one tradeoff — with no index to use (`LIKE` with a leading wildcard can't use one), it's a full table scan, which took ~13 seconds at that scale in testing. That's slow but *correct* — it was a deliberate choice over faster indexed alternatives like SQLite FTS5, whose tokenized matching could silently miss a substring match a forensic search needs to catch. Narrowing by artifact-type filter first (fast, indexed) before searching free text will speed this up. `serve_db.py` binds to `127.0.0.1` only (not the network) and opens the database read-only, so it can never modify evidence.

## Roadmap

- [x] KAPE-based collection wrapper (`collection/run_kape.ps1`)
- [x] KAPE/EZ Tools CSV normalizer (`parsers/normalize_kape.py`)
- [x] Timeline merge + ATT&CK tagging (`timeline/build_timeline.py`)
- [x] Emit all MFTECmd timestamp events (created/modified/accessed/record-change)
- [x] Per-MFT-entry timestomp detection heuristic (SI vs FN, tags `T1070.006` via `mft_timestamp_anomaly`)
- [x] SQLite-backed timeline dashboard (`timeline/build_db.py` + `timeline/viewer/` — search, artifact filters, ATT&CK-tagged-only toggle, sortable columns, pagination; replaced an earlier single-file HTML viewer that embedded every row as inline JSON, which ran real collections out of browser memory)
- [x] Server-backed dashboard for databases too large for the browser to load whole (`timeline/serve_db.py` + `timeline/server_viewer/` — same UI, queries SQLite directly off disk via a local Python stdlib server, no size ceiling; verified against a synthetic 3.27GB/5M-row database)
- [ ] Timesketch export format
- [ ] Sample malicious dataset + walkthrough (docs/case_walkthrough.md)

## Design principles

- **Minimal footprint on live systems** — KAPE runs read-only against the source; no writes to the host beyond the configured output destinations.
- **Chain of custody friendly** — KAPE logs what it collected and when; keep target/module output folders as the evidence record.
- **Analyst-first output** — the timeline is designed to be read by a human under time pressure, not just machine-parsed.

## Status

Early build — collection, normalization, and timeline stages are scaffolded. See Roadmap above for current coverage.

## License

[MIT](LICENSE). Third-party components vendored for offline use are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
