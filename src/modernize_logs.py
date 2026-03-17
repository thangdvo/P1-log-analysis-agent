"""
modernize_logs.py

Converts legacy syslog timestamps (e.g. "Nov 30 06:39:00") to ISO 8601
(e.g. "2024-11-30T06:39:00+00:00") for every line in data/auth.log.

Assumptions:
- All logs are from 2024 (confirmed by SecRepo dataset provenance)
- Server timezone is UTC (confirmed by hostname ip-172-31-27-153, AWS us-east-1)
- Input format: <Mon> <DD> <HH:MM:SS> <host> <rest...>

Output: data/auth_modern.log  (same lines, only timestamp field replaced)
"""

import re
from datetime import datetime, timezone
from pathlib import Path

# Legacy syslog timestamp: "Nov 30 06:39:00"
LEGACY_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})"
)

YEAR = 2024  # All logs are from 2024


def modernize_line(line: str) -> str:
    """Replace the leading syslog timestamp with an ISO 8601 timestamp."""
    m = LEGACY_TS_RE.match(line)
    if not m:
        return line  # pass through unchanged (e.g. continuation lines)

    month_str, day_str, time_str = m.group(1), m.group(2), m.group(3)

    # Parse into a UTC-aware datetime
    dt = datetime.strptime(
        f"{YEAR} {month_str} {day_str} {time_str}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)

    iso_ts = dt.isoformat()  # e.g. "2024-11-30T06:39:00+00:00"
    remainder = line[m.end():]  # everything after the old timestamp

    return iso_ts + remainder


def main():
    project_root = Path(__file__).parent.parent
    input_path = project_root / "data" / "auth.log"
    output_path = project_root / "data" / "auth_modern.log"

    lines_processed = 0
    lines_skipped = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as infile, \
         output_path.open("w", encoding="utf-8") as outfile:

        for line in infile:
            modern = modernize_line(line.rstrip("\n"))
            outfile.write(modern + "\n")

            if LEGACY_TS_RE.match(line):
                lines_processed += 1
            else:
                lines_skipped += 1

    print(f"Done. {lines_processed:,} lines converted, {lines_skipped} skipped.")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
