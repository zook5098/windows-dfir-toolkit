"""
normalize_kape.py

Reads the CSV output KAPE's bundled EZ Tools modules write into a module
destination folder (MFTECmd, PECmd, AppCompatCacheParser, RECmd, EvtxECmd,
LECmd — see collection/targets.md) and normalizes every row into the
toolkit's common schema:
    timestamp, host, artifact_type, action, detail, source_file

Tool CSVs are identified by header signature rather than filename, since
KAPE/EZ Tools naming conventions vary by version and module deployment
layout. Add a new tool by adding a signature + row parser and registering
it in TOOL_PARSERS.

Usage:
    python normalize_kape.py --input <module_dest_dir> --output normalized.csv --host HOSTNAME
"""

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path


NORMALIZED_FIELDS = ["timestamp", "host", "artifact_type", "action", "detail", "source_file"]

# $STANDARD_INFORMATION (0x10) vs $FILE_NAME (0x30) timestamp pairs MFTECmd
# emits per $MFT entry, and the action each SI timestamp normalizes to.
MFT_TIMESTAMP_CATEGORIES = [
    ("Created", "file_created"),
    ("LastModified", "file_modified"),
    ("LastAccess", "file_accessed"),
    ("LastRecordChange", "file_record_changed"),
]

# SI is user/API-visible (what `dir`, Explorer, and most timestomping tools
# read and write); FN is set by the filesystem at creation/rename and is
# rarely touched by anti-forensic tooling. If SI claims to predate FN by
# more than this tolerance, the SI timestamp was likely backdated.
TIMESTOMP_TOLERANCE_SECONDS = 1


def _get(row, *names, default=""):
    """Return the first present, non-empty value among candidate column names."""
    for name in names:
        value = row.get(name)
        if value:
            return value
    return default


def _parse_mft_timestamp(value):
    """Parse an MFTECmd timestamp string (e.g. '2024-05-01 12:00:00.1234567').

    MFTECmd emits sub-microsecond fractional precision; truncate to the 6
    digits Python's %f supports. Returns None if unparseable.
    """
    if not value:
        return None
    value = value.strip().rstrip("Z").replace("T", " ")
    if "." in value:
        base, frac = value.split(".", 1)
        value = f"{base}.{(frac + '000000')[:6]}"
        fmt = "%Y-%m-%d %H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%d %H:%M:%S"
    try:
        return datetime.strptime(value, fmt)
    except ValueError:
        return None


def _is_timestomp_anomaly(si_value, fn_value):
    """Heuristic only — SI predating FN is suggestive, not conclusive, of timestomping."""
    si_dt = _parse_mft_timestamp(si_value)
    fn_dt = _parse_mft_timestamp(fn_value)
    if si_dt is None or fn_dt is None:
        return False
    return (fn_dt - si_dt).total_seconds() > TIMESTOMP_TOLERANCE_SECONDS


def parse_mftecmd_row(row):
    """MFTECmd $MFT CSV -> file system timeline rows (up to 4 per $MFT entry).

    Emits one row per populated $STANDARD_INFORMATION (0x10) timestamp —
    created/modified/accessed/record-changed — and flags SI-vs-FN (0x30)
    anomalies inline via the `mft_timestamp_anomaly` marker that
    docs/attack_mapping.yaml's T1070.006 rule matches on.
    """
    path = "\\".join(p for p in (_get(row, "ParentPath"), _get(row, "FileName")) if p)
    size = _get(row, "FileSize", default="?")

    records = []
    for category, action in MFT_TIMESTAMP_CATEGORIES:
        si_ts = _get(row, f"{category}0x10")
        if not si_ts:
            continue
        fn_ts = _get(row, f"{category}0x30")
        detail = f"{path} (size={size})"
        if _is_timestomp_anomaly(si_ts, fn_ts):
            detail += f" [mft_timestamp_anomaly: SI={si_ts} FN={fn_ts}]"
        records.append({"timestamp": si_ts, "artifact_type": "mft", "action": action, "detail": detail})
    return records


def parse_pecmd_row(row):
    """PECmd Prefetch CSV -> program execution rows."""
    timestamp = _get(row, "LastRun")
    if not timestamp:
        return []
    exe = _get(row, "ExecutableName", default="UNKNOWN")
    run_count = _get(row, "RunCount", default="?")
    detail = f"{exe} (run_count={run_count})"
    return [{"timestamp": timestamp, "artifact_type": "prefetch", "action": "process_execution", "detail": detail}]


def parse_shimcache_row(row):
    """AppCompatCacheParser (Shimcache) CSV -> execution-evidence rows."""
    timestamp = _get(row, "LastModifiedTimeUTC", "LastModified")
    if not timestamp:
        return []
    path = _get(row, "Path", default="UNKNOWN")
    executed = _get(row, "Executed")
    action = "shimcache_executed" if executed and executed.lower() in ("true", "1") else "shimcache_entry"
    return [{"timestamp": timestamp, "artifact_type": "shimcache", "action": action, "detail": path}]


def parse_recmd_row(row):
    """RECmd batch (Kroll_Batch.reb) CSV -> registry rows."""
    timestamp = _get(row, "LastWriteTimestamp")
    if not timestamp:
        return []
    key_path = _get(row, "KeyPath")
    value_name = _get(row, "ValueName")
    value_data = _get(row, "ValueData")
    action = _get(row, "Description", "Category", default="registry_value")
    detail = f"{key_path}\\{value_name} = {value_data}" if value_name else key_path
    return [{"timestamp": timestamp, "artifact_type": "registry", "action": action, "detail": detail}]


def parse_evtxecmd_row(row):
    """EvtxECmd CSV -> event log rows."""
    timestamp = _get(row, "TimeCreated")
    if not timestamp:
        return []
    event_id = _get(row, "EventId", default="?")
    channel = _get(row, "Channel", default="")
    action = f"event_id_{event_id}"
    detail = _get(row, "MapDescription", "Payload", default=f"{channel} EventID {event_id}")
    return [{"timestamp": timestamp, "artifact_type": "event_log", "action": action, "detail": detail}]


def parse_lecmd_row(row):
    """LECmd .lnk CSV -> link-file rows (target file interaction)."""
    timestamp = _get(row, "TargetModified", "TargetAccessed", "TargetCreated")
    if not timestamp:
        return []
    target = _get(row, "LocalPath", "TargetIDAbsolutePath", default="UNKNOWN")
    args = _get(row, "Arguments")
    detail = f"{target} {args}".strip()
    return [{"timestamp": timestamp, "artifact_type": "lnk", "action": "lnk_target_access", "detail": detail}]


# (required header columns to identify the tool, row parser). Order matters:
# checked top to bottom, first full match wins.
TOOL_PARSERS = [
    ({"EntryNumber", "ParentPath", "Created0x10"}, parse_mftecmd_row),
    ({"ExecutableName", "RunCount", "LastRun"}, parse_pecmd_row),
    ({"CacheEntryPosition", "Path", "LastModifiedTimeUTC"}, parse_shimcache_row),
    ({"KeyPath", "ValueName", "LastWriteTimestamp"}, parse_recmd_row),
    ({"EventId", "Channel", "TimeCreated"}, parse_evtxecmd_row),
    ({"TargetCreated", "LocalPath", "Arguments"}, parse_lecmd_row),
]


def detect_parser(fieldnames):
    columns = set(fieldnames or [])
    for signature, row_parser in TOOL_PARSERS:
        if signature.issubset(columns):
            return row_parser
    return None


def normalize_file(csv_path, host):
    with open(csv_path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        row_parser = detect_parser(reader.fieldnames)
        if row_parser is None:
            print(f"[skip] unrecognized CSV schema: {csv_path}", file=sys.stderr)
            return []

        normalized = []
        for row in reader:
            for record in row_parser(row):
                record["host"] = host
                record["source_file"] = str(csv_path)
                normalized.append(record)
        return normalized


def main():
    parser = argparse.ArgumentParser(description="Normalize KAPE/EZ Tools module CSVs into the common schema.")
    parser.add_argument("--input", required=True, help="Directory containing KAPE module (EZ Tools) CSV output")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--host", required=True, help="Hostname to tag records with")
    args = parser.parse_args()

    input_dir = Path(args.input)
    csv_files = sorted(input_dir.rglob("*.csv"))
    if not csv_files:
        print(f"No CSV files found under {input_dir}", file=sys.stderr)

    rows = []
    for csv_path in csv_files:
        rows.extend(normalize_file(csv_path, args.host))

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NORMALIZED_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} normalized rows from {len(csv_files)} CSV files to {args.output}")


if __name__ == "__main__":
    main()
