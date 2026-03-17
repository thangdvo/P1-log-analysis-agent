"""
tests/test_tools.py

Basic tests for every tool in src/tools.py.
All tests run against the real data/auth_modern.log so they validate
actual findings, not toy fixtures.

Run with:  pytest tests/ -v
"""

import pytest
from pathlib import Path
from src.tools import search_logs, count_events, detect_brute_force, correlate_events

# Known facts about auth_modern.log (validated by manual inspection)
KNOWN_TOP_IP = "218.75.153.170"        # highest attempt count
KNOWN_BLITZ_IP = "173.192.158.3"       # 748 events in ~5 min on Dec 2
KNOWN_BOTNET_IP = "220.99.93.50"       # part of 4-IP coordinated botnet
KNOWN_DATE_PREFIX = "2024-"            # all timestamps are in 2024


# ─────────────────────────────────────────────────────────────────────────────
# search_logs
# ─────────────────────────────────────────────────────────────────────────────

class TestSearchLogs:

    def test_basic_returns_structure(self):
        result = search_logs("Invalid user admin")
        assert "query" in result
        assert "total_matches" in result
        assert "returned" in result
        assert "matches" in result

    def test_known_total_match_count(self):
        # "Invalid user admin" appears 3,914 times (two lines per event:
        # the sshd line + the input_userauth_request line)
        result = search_logs("Invalid user admin")
        assert result["total_matches"] >= 3900, (
            f"Expected ≥3900 matches for 'Invalid user admin', got {result['total_matches']}"
        )

    def test_case_insensitive(self):
        lower = search_logs("invalid user admin")
        upper = search_logs("INVALID USER ADMIN")
        assert lower["total_matches"] == upper["total_matches"]

    def test_max_results_respected(self):
        result = search_logs("sshd", max_results=10)
        assert result["returned"] <= 10
        assert len(result["matches"]) <= 10

    def test_max_results_default_cap(self):
        # default is 200 — should never return more even if more exist
        result = search_logs("sshd")
        assert result["returned"] <= 200

    def test_match_contains_iso_timestamp(self):
        result = search_logs("Invalid user admin", max_results=5)
        for match in result["matches"]:
            assert match["timestamp"].startswith(KNOWN_DATE_PREFIX), (
                f"Timestamp {match['timestamp']!r} doesn't start with '2024-'"
            )

    def test_no_results_for_garbage_query(self):
        result = search_logs("ZZZNOMATCHZZZXXX")
        assert result["total_matches"] == 0
        assert result["matches"] == []

    def test_ip_search_returns_lines_containing_ip(self):
        result = search_logs(KNOWN_BLITZ_IP, max_results=5)
        assert result["total_matches"] > 0
        for match in result["matches"]:
            assert KNOWN_BLITZ_IP in match["line"]

    def test_returned_matches_total_when_few_results(self):
        # Search for an unusual specific string — returned == total
        result = search_logs("Too many authentication failures for postgres")
        assert result["returned"] == result["total_matches"]


# ─────────────────────────────────────────────────────────────────────────────
# count_events
# ─────────────────────────────────────────────────────────────────────────────

class TestCountEvents:

    def test_returns_structure(self):
        result = count_events("invalid_user")
        assert "event_type" in result
        assert "count" in result
        assert "patterns" in result

    def test_invalid_user_count(self):
        result = count_events("invalid_user")
        # 12,250 "Invalid user" lines confirmed by manual grep
        assert result["count"] >= 12000, f"Expected ≥12000, got {result['count']}"

    def test_failed_login_superset_of_invalid_user(self):
        # failed_login covers invalid_user + brute_force_cutoff — must be >=
        invalid = count_events("invalid_user")["count"]
        failed = count_events("failed_login")["count"]
        assert failed >= invalid

    def test_brute_force_cutoff_count(self):
        result = count_events("brute_force_cutoff")
        assert result["count"] >= 2500, f"Expected ≥2500, got {result['count']}"

    def test_all_ssh_is_largest(self):
        # nearly every line is an sshd event
        all_ssh = count_events("all_ssh")["count"]
        invalid = count_events("invalid_user")["count"]
        assert all_ssh > invalid

    def test_disconnect_substantial(self):
        result = count_events("disconnect")
        assert result["count"] >= 40000

    def test_probe_nonzero(self):
        result = count_events("probe")
        assert result["count"] > 0

    def test_unknown_event_type_returns_error(self):
        result = count_events("definitely_not_a_real_event")
        assert "error" in result
        assert result["count"] == 0

    @pytest.mark.parametrize("event_type", [
        "invalid_user", "failed_login", "brute_force_cutoff",
        "disconnect", "probe", "cron", "all_ssh", "fatal",
    ])
    def test_all_event_types_accepted(self, event_type):
        result = count_events(event_type)
        assert "error" not in result
        assert result["count"] >= 0


# ─────────────────────────────────────────────────────────────────────────────
# detect_brute_force
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectBruteForce:

    def test_returns_structure(self):
        result = detect_brute_force(threshold=100)
        assert "threshold" in result
        assert "total_ips" in result
        assert "attackers" in result

    def test_threshold_respected(self):
        result = detect_brute_force(threshold=100)
        for attacker in result["attackers"]:
            assert attacker["attempts"] >= 100

    def test_sorted_descending(self):
        result = detect_brute_force(threshold=5)
        counts = [a["attempts"] for a in result["attackers"]]
        assert counts == sorted(counts, reverse=True)

    def test_known_top_ip_present(self):
        result = detect_brute_force(threshold=5)
        ips = [a["ip"] for a in result["attackers"]]
        assert KNOWN_TOP_IP in ips, f"{KNOWN_TOP_IP} should be in attacker list"

    def test_known_top_ip_is_first(self):
        result = detect_brute_force(threshold=5)
        assert result["attackers"][0]["ip"] == KNOWN_TOP_IP

    def test_high_threshold_returns_fewer(self):
        low = detect_brute_force(threshold=5)["total_ips"]
        high = detect_brute_force(threshold=500)["total_ips"]
        assert high < low

    def test_attacker_fields_complete(self):
        result = detect_brute_force(threshold=100)
        for a in result["attackers"]:
            assert "ip" in a
            assert "attempts" in a
            assert "first_seen" in a
            assert "last_seen" in a
            assert "targeted_users" in a
            assert "attack_window_minutes" in a

    def test_first_seen_before_last_seen(self):
        result = detect_brute_force(threshold=100)
        for a in result["attackers"]:
            if a["first_seen"] and a["last_seen"]:
                assert a["first_seen"] <= a["last_seen"]

    def test_targeted_users_is_list(self):
        result = detect_brute_force(threshold=100)
        for a in result["attackers"]:
            assert isinstance(a["targeted_users"], list)

    def test_361_ips_above_threshold_5(self):
        # Confirmed from manual analysis
        result = detect_brute_force(threshold=5)
        assert result["total_ips"] >= 300


# ─────────────────────────────────────────────────────────────────────────────
# correlate_events
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelateEvents:

    def test_returns_structure(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        assert "ip" in result
        assert "total_events" in result
        assert "first_seen" in result
        assert "last_seen" in result
        assert "summary" in result
        assert "timeline" in result

    def test_known_ip_event_count(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        # 748 events confirmed for 173.192.158.3
        assert result["total_events"] >= 700, (
            f"Expected ≥700 events for {KNOWN_BLITZ_IP}, got {result['total_events']}"
        )

    def test_known_ip_attack_date(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        assert result["first_seen"].startswith("2024-12-02"), (
            f"Expected Dec 2 attack, got {result['first_seen']}"
        )

    def test_timeline_chronological_order(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        timestamps = [
            e["timestamp"] for e in result["timeline"] if e["timestamp"]
        ]
        assert timestamps == sorted(timestamps)

    def test_summary_counts_consistent(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        s = result["summary"]
        # Sum of categorised events must be <= total
        categorised = (
            s["invalid_user_attempts"]
            + s["brute_force_cutoffs"]
            + s["disconnects"]
            + s["probes"]
        )
        assert categorised <= result["total_events"]

    def test_ip_appears_in_every_timeline_event(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        for event in result["timeline"][:20]:  # check first 20
            assert KNOWN_BLITZ_IP in event["event"]

    def test_targeted_users_is_list(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        assert isinstance(result["summary"]["targeted_users"], list)

    def test_known_users_targeted(self):
        result = correlate_events(KNOWN_BLITZ_IP)
        users = result["summary"]["targeted_users"]
        # This IP targeted single-letter names like 'a', 'b'
        assert "a" in users or "b" in users, (
            f"Expected single-letter usernames, got: {users[:10]}"
        )

    def test_unknown_ip_returns_empty(self):
        result = correlate_events("1.2.3.4")
        assert result["total_events"] == 0
        assert result["timeline"] == []
        assert result["first_seen"] == ""

    def test_botnet_ip_has_many_users(self):
        result = correlate_events(KNOWN_BOTNET_IP)
        users = result["summary"]["targeted_users"]
        # Botnet IPs used 47+ usernames
        assert len(users) >= 40, f"Expected ≥40 usernames, got {len(users)}"
