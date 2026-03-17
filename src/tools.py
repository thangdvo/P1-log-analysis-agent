"""
tools.py

Four agent tools for querying auth_modern.log.
Each tool returns structured data (dicts / lists of dicts) so the agent
can format or reason over the results without re-parsing.

Log line format (after modernize_logs.py):
    2024-11-30T08:42:04+00:00 ip-172-31-27-153 sshd[22182]: Invalid user admin from 187.12.249.74

Key event patterns observed in this dataset:
    - "Invalid user <user> from <IP>"              → failed auth, bad username
    - "input_userauth_request: invalid user <user>" → paired with above
    - "Too many authentication failures for <user>" → brute-force cutoff
    - "Received disconnect from <IP>"               → connection teardown
    - "Connection closed by <IP>"                   → connection teardown
    - "Did not receive identification string from <IP>" → scanner/probe
    - "fatal: Read from socket failed"              → abrupt disconnect
    - "pam_unix(cron:session)"                      → cron noise (not SSH attacks)
"""

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

DEFAULT_LOG = Path(__file__).parent.parent / "data" / "auth_modern.log"

# Matches the ISO 8601 timestamp at the start of every modernized line
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00)")

# Extracts IP addresses that appear after "from " in sshd lines
_IP_FROM_RE = re.compile(r"\bfrom ([\d]{1,3}(?:\.[\d]{1,3}){3})\b")

# "Invalid user <username> from <IP>"
_INVALID_USER_RE = re.compile(r"Invalid user (\S+) from ([\d.]+)")

# "Too many authentication failures for <username>"
_TOO_MANY_RE = re.compile(r"Too many authentication failures for (\S+)")


def _iter_lines(log_file: Path):
    """Yield stripped lines from the log file."""
    with log_file.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line.rstrip("\n")


def _parse_ts(line: str) -> datetime | None:
    """Return a UTC-aware datetime from the line's leading timestamp, or None."""
    m = _TS_RE.match(line)
    if not m:
        return None
    return datetime.fromisoformat(m.group(1))


# ---------------------------------------------------------------------------
# Tool 1 — search_logs
# ---------------------------------------------------------------------------

def search_logs(
    query: str,
    log_file: Path = DEFAULT_LOG,
    max_results: int = 200,
) -> dict:
    """
    Search log lines for a keyword, IP address, or username.

    Args:
        query:       Case-insensitive search string (e.g. "187.12.249.74",
                     "Invalid user", "admin").
        log_file:    Path to the modernized log file.
        max_results: Cap on returned matches (avoids drowning the agent).

    Returns:
        {
            "query":        str,
            "total_matches": int,
            "returned":     int,
            "matches":      [{"timestamp": str, "line": str}, ...]
        }
    """
    log_file = Path(log_file)
    query_lower = query.lower()
    matches = []
    total = 0

    for line in _iter_lines(log_file):
        if query_lower in line.lower():
            total += 1
            if len(matches) < max_results:
                ts = _parse_ts(line)
                matches.append({
                    "timestamp": ts.isoformat() if ts else "",
                    "line": line,
                })

    return {
        "query": query,
        "total_matches": total,
        "returned": len(matches),
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# Tool 2 — count_events
# ---------------------------------------------------------------------------

# Supported event_type aliases -> substring patterns to search for in lines
_EVENT_PATTERNS: dict[str, list[str]] = {
    "invalid_user":       ["Invalid user"],
    "failed_login":       ["Invalid user", "Too many authentication failures"],
    "brute_force_cutoff": ["Too many authentication failures"],
    "disconnect":         ["Received disconnect", "Connection closed"],
    "probe":              ["Did not receive identification string"],
    "cron":               ["pam_unix(cron:session)"],
    "all_ssh":            ["sshd["],
    "fatal":              ["fatal:"],
}


def count_events(
    event_type: str,
    log_file: Path = DEFAULT_LOG,
) -> dict:
    """
    Count log lines that match a named event category.

    Supported event_type values:
        invalid_user, failed_login, brute_force_cutoff,
        disconnect, probe, cron, all_ssh, fatal

    Returns:
        {
            "event_type":  str,
            "count":       int,
            "patterns":    [str, ...]   # patterns that were searched
        }
    """
    log_file = Path(log_file)
    event_type_lower = event_type.lower().replace(" ", "_")

    if event_type_lower not in _EVENT_PATTERNS:
        return {
            "event_type": event_type,
            "error": f"Unknown event type. Choose from: {sorted(_EVENT_PATTERNS)}",
            "count": 0,
            "patterns": [],
        }

    patterns = _EVENT_PATTERNS[event_type_lower]
    count = 0

    for line in _iter_lines(log_file):
        if any(p in line for p in patterns):
            count += 1

    return {
        "event_type": event_type_lower,
        "count": count,
        "patterns": patterns,
    }


# ---------------------------------------------------------------------------
# Tool 3 — detect_brute_force
# ---------------------------------------------------------------------------

def detect_brute_force(
    log_file: Path = DEFAULT_LOG,
    threshold: int = 5,
) -> dict:
    """
    Identify IPs that made more than `threshold` failed/hostile attempts.

    "Hostile attempt" is defined as any line containing:
        - "Invalid user"        (bad username -> clearly attacking)
        - "Too many authentication failures" (SSH cut them off mid-burst)
        - "Did not receive identification string" (scanner probing port)

    These are the three clearest attack signals in this dataset (no
    "Failed password" events exist because the server rejects at pre-auth).

    Returns:
        {
            "threshold":   int,
            "total_ips":   int,
            "attackers":   [
                {
                    "ip":              str,
                    "attempts":        int,
                    "first_seen":      str (ISO 8601),
                    "last_seen":       str (ISO 8601),
                    "targeted_users":  [str, ...],
                    "attack_window_minutes": float,
                },
                ...                      # ranked by attempts desc
            ]
        }
    """
    log_file = Path(log_file)

    HOSTILE_PATTERNS = [
        "Invalid user",
        "Too many authentication failures",
        "Did not receive identification string",
    ]

    ip_attempts: Counter = Counter()
    ip_first_seen: dict[str, datetime] = {}
    ip_last_seen: dict[str, datetime] = {}
    ip_users: dict[str, set] = defaultdict(set)

    for line in _iter_lines(log_file):
        if not any(p in line for p in HOSTILE_PATTERNS):
            continue

        ip_m = _IP_FROM_RE.search(line)
        if not ip_m:
            continue
        ip = ip_m.group(1)

        ts = _parse_ts(line)
        ip_attempts[ip] += 1

        if ts:
            if ip not in ip_first_seen or ts < ip_first_seen[ip]:
                ip_first_seen[ip] = ts
            if ip not in ip_last_seen or ts > ip_last_seen[ip]:
                ip_last_seen[ip] = ts

        u_m = _INVALID_USER_RE.search(line)
        if u_m:
            ip_users[ip].add(u_m.group(1))

    attackers = []
    for ip, attempts in ip_attempts.most_common():
        if attempts < threshold:
            break

        first = ip_first_seen.get(ip)
        last = ip_last_seen.get(ip)
        window = (
            round((last - first).total_seconds() / 60, 1)
            if first and last and last != first
            else 0.0
        )

        attackers.append({
            "ip": ip,
            "attempts": attempts,
            "first_seen": first.isoformat() if first else "",
            "last_seen": last.isoformat() if last else "",
            "targeted_users": sorted(ip_users[ip]),
            "attack_window_minutes": window,
        })

    return {
        "threshold": threshold,
        "total_ips": len(attackers),
        "attackers": attackers,
    }


# ---------------------------------------------------------------------------
# Tool 4 — correlate_events
# ---------------------------------------------------------------------------

def correlate_events(
    ip: str,
    log_file: Path = DEFAULT_LOG,
) -> dict:
    """
    Return every log event for a given IP, in chronological order.

    Useful for reconstructing the full timeline of a single attacker:
    when they arrived, what usernames they tried, how the server responded.

    Returns:
        {
            "ip":           str,
            "total_events": int,
            "first_seen":   str (ISO 8601),
            "last_seen":    str (ISO 8601),
            "summary": {
                "invalid_user_attempts": int,
                "brute_force_cutoffs":   int,
                "disconnects":           int,
                "probes":                int,
                "targeted_users":        [str, ...],
            },
            "timeline": [
                {"timestamp": str, "event": str},
                ...
            ]
        }
    """
    log_file = Path(log_file)

    timeline = []
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    invalid_user_count = 0
    brute_force_count = 0
    disconnect_count = 0
    probe_count = 0
    targeted_users: set[str] = set()

    for line in _iter_lines(log_file):
        if ip not in line:
            continue

        ts = _parse_ts(line)

        if ts:
            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

        if "Invalid user" in line:
            invalid_user_count += 1
            u_m = _INVALID_USER_RE.search(line)
            if u_m:
                targeted_users.add(u_m.group(1))
        elif "Too many authentication failures" in line:
            brute_force_count += 1
        elif "Received disconnect" in line or "Connection closed" in line:
            disconnect_count += 1
        elif "Did not receive identification string" in line:
            probe_count += 1

        ts_prefix = _TS_RE.match(line)
        event_text = line[ts_prefix.end():].strip() if ts_prefix else line

        timeline.append({
            "timestamp": ts.isoformat() if ts else "",
            "event": event_text,
        })

    return {
        "ip": ip,
        "total_events": len(timeline),
        "first_seen": first_seen.isoformat() if first_seen else "",
        "last_seen": last_seen.isoformat() if last_seen else "",
        "summary": {
            "invalid_user_attempts": invalid_user_count,
            "brute_force_cutoffs": brute_force_count,
            "disconnects": disconnect_count,
            "probes": probe_count,
            "targeted_users": sorted(targeted_users),
        },
        "timeline": timeline,
    }
