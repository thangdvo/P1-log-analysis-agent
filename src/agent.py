"""
agent.py

Two modes:

1. Q&A agent (ask / --demo / interactive REPL)
   Answers natural language questions about auth_modern.log.

2. Autonomous investigator (run_investigation / --investigate)
   Given a high-level goal, autonomously decides what to investigate,
   calls tools in sequence, reasons over results (ReAct pattern), and
   produces a structured incident report — no human prompting mid-run.

Usage:
    python src/agent.py                          # interactive REPL
    python src/agent.py "Was there a brute force attack?"  # single question
    python src/agent.py --demo                   # run all four demo questions
    python src/agent.py --investigate            # autonomous incident investigation

ReAct loop (run_investigation):
    GOAL
     ↓
    Reason → Act (tool call) → Observe (result) → Reason → ...
     ↓
    submit_report (structured incident report)
"""

import json
import os
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
import anthropic

# Ensure project root is on sys.path so "from src.tools import ..." works
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load .env from project root (picks up ANTHROPIC_API_KEY if not already set)
load_dotenv(PROJECT_ROOT / ".env")

from src.tools import (
    search_logs,
    count_events,
    detect_brute_force,
    correlate_events,
    DEFAULT_LOG,
)

# ---------------------------------------------------------------------------
# Anthropic client
# ---------------------------------------------------------------------------

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from environment
MODEL = "claude-opus-4-6"

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are a cloud security analyst specializing in SSH log analysis. You have
access to tools that query a real auth.log file from an AWS EC2 honeypot server
(ip-172-31-27-153) running from Nov 30 to Dec 31, 2024 UTC. The log has 86,839
entries capturing active brute-force campaigns and credential scanning.

DATASET FACTS:
- No "Failed password" events exist — the server rejects attackers at pre-auth.
- Key attack signals: "Invalid user" (bad username), "Too many authentication
  failures" (SSH cut them off mid-burst), "Did not receive identification string"
  (port scanners).
- The top attacker IP sent over 11,000 hostile events.

TOOL GUIDANCE:
- For "which IPs had most failed logins" or "brute force" questions:
  use detect_brute_force — it ranks IPs by hostile attempts.
- For "which usernames are targeted" questions: call detect_brute_force and
  inspect the targeted_users field across the top attackers. Or call
  search_logs("Invalid user <name>") to check a specific username.
- For activity from a specific IP: use correlate_events.
- For keyword/phrase searches or counts: use search_logs or count_events.
- Feel free to call multiple tools when needed to give a thorough answer.

Answer in clear, concise plain English. Lead with the most important finding.
When relevant, cite specific IPs, counts, and timestamps from the data.
""".strip()

# ---------------------------------------------------------------------------
# Tool definitions — JSON schema for the Anthropic API
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "name": "search_logs",
        "description": (
            "Search auth_modern.log lines for a keyword, IP address, or username. "
            "Returns matching lines with timestamps. Case-insensitive. "
            "Use this to find specific events or to spot-check patterns."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search string, e.g. '187.12.249.74', 'Invalid user admin', "
                        "'Too many authentication failures'."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum lines to return (default 200, max 1000).",
                    "default": 200,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "count_events",
        "description": (
            "Count log lines that match a named event category. "
            "Supported values: invalid_user, failed_login, brute_force_cutoff, "
            "disconnect, probe, cron, all_ssh, fatal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event_type": {
                    "type": "string",
                    "description": (
                        "Event category name. One of: invalid_user, failed_login, "
                        "brute_force_cutoff, disconnect, probe, cron, all_ssh, fatal."
                    ),
                    "enum": [
                        "invalid_user",
                        "failed_login",
                        "brute_force_cutoff",
                        "disconnect",
                        "probe",
                        "cron",
                        "all_ssh",
                        "fatal",
                    ],
                }
            },
            "required": ["event_type"],
        },
    },
    {
        "name": "detect_brute_force",
        "description": (
            "Identify IPs with more than `threshold` hostile attempts, ranked by "
            "attempt count. Returns first/last seen timestamps, attack window in "
            "minutes, and usernames each IP targeted. Best tool for 'which IPs "
            "attacked?' and 'was there a brute force?' questions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "threshold": {
                    "type": "integer",
                    "description": "Minimum hostile attempts to be included (default 5).",
                    "default": 5,
                }
            },
            "required": [],
        },
    },
    {
        "name": "correlate_events",
        "description": (
            "Return every log event for a specific IP address in chronological "
            "order, plus a summary (invalid-user attempts, disconnects, "
            "brute-force cutoffs, targeted usernames). Use this to reconstruct "
            "the full timeline of a single attacker."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IPv4 address to look up, e.g. '173.192.158.3'.",
                }
            },
            "required": ["ip"],
        },
    },
]

# ---------------------------------------------------------------------------
# Tool execution — maps API tool names to Python functions
# ---------------------------------------------------------------------------


def _clip_timeline(timeline: list[dict], head: int = 20, tail: int = 5) -> list[dict]:
    """Return head+tail of a potentially huge timeline, with a gap marker."""
    if len(timeline) <= head + tail:
        return timeline
    gap = len(timeline) - head - tail
    return (
        timeline[:head]
        + [{"timestamp": "...", "event": f"... {gap} events omitted ..."}]
        + timeline[-tail:]
    )


def execute_tool(name: str, tool_input: dict) -> str:
    """
    Run the named tool and return a JSON string suitable for Claude to read.
    Large results are clipped to keep the context window manageable.
    """
    try:
        if name == "search_logs":
            result = search_logs(
                query=tool_input["query"],
                max_results=min(int(tool_input.get("max_results", 200)), 1000),
            )
            # Clip matches — Claude only needs a sample + the total count
            if len(result["matches"]) > 30:
                result = dict(result)
                result["matches"] = result["matches"][:30]
                result["note"] = (
                    f"Showing first 30 of {result['total_matches']:,} matches. "
                    "Call again with a more specific query to drill down."
                )

        elif name == "count_events":
            result = count_events(event_type=tool_input["event_type"])

        elif name == "detect_brute_force":
            result = detect_brute_force(
                threshold=int(tool_input.get("threshold", 5))
            )
            # Keep top 20 attackers; Claude doesn't need all 361
            if len(result["attackers"]) > 20:
                result = dict(result)
                result["attackers"] = result["attackers"][:20]
                result["note"] = (
                    f"Showing top 20 of {result['total_ips']} IPs above threshold."
                )

        elif name == "correlate_events":
            result = correlate_events(ip=tool_input["ip"])
            # Keep summary intact; clip the timeline
            if len(result.get("timeline", [])) > 25:
                result = dict(result)
                result["timeline"] = _clip_timeline(result["timeline"])
                result["timeline_note"] = (
                    f"Timeline clipped to 25 representative events "
                    f"(total: {result['total_events']})."
                )

        else:
            return json.dumps({"error": f"Unknown tool: {name}"})

        return json.dumps(result, default=str)

    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Agent — streaming agentic loop
# ---------------------------------------------------------------------------


def ask(question: str, verbose: bool = False) -> str:
    """
    Send a natural language question to the agent and return the final answer.

    Streams Claude's text output to stdout in real time.
    Handles multi-step tool calls automatically.
    """
    messages: list[dict] = [{"role": "user", "content": question}]

    while True:
        # Stream the response so the user sees text as it's generated
        with client.messages.stream(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        ) as stream:
            # Print text tokens in real time
            for text_chunk in stream.text_stream:
                print(text_chunk, end="", flush=True)

            response = stream.get_final_message()

        # ── Finished (no tool calls) ────────────────────────────────────────
        if response.stop_reason == "end_turn":
            print()  # newline after streamed output
            return next(
                (b.text for b in response.content if b.type == "text"), ""
            )

        # ── Tool use ─────────────────────────────────────────────────────────
        if response.stop_reason == "tool_use":
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

            if verbose:
                for tb in tool_use_blocks:
                    print(
                        f"\n[tool] {tb.name}({json.dumps(tb.input, separators=(',', ':'))})"
                    )

            # Append Claude's response (including tool_use blocks) to history
            messages.append({"role": "assistant", "content": response.content})

            # Execute every tool Claude requested, collect results
            tool_results = []
            for tb in tool_use_blocks:
                result_str = execute_tool(tb.name, tb.input)
                if verbose:
                    preview = result_str[:200] + ("..." if len(result_str) > 200 else "")
                    print(f"[result] {preview}")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tb.id,
                    "content": result_str,
                })

            # Feed results back to Claude as a user message
            messages.append({"role": "user", "content": tool_results})
            # Loop again — Claude will now synthesize the tool results
            continue

        # Unexpected stop reason — treat as done
        print()
        return next((b.text for b in response.content if b.type == "text"), "")


# ---------------------------------------------------------------------------
# Autonomous investigator — system prompt, submit_report tool, ReAct loop
# ---------------------------------------------------------------------------

INVESTIGATION_SYSTEM_PROMPT = """
You are an autonomous cloud security analyst conducting a solo incident investigation.
You have been given a high-level goal. No human will assist or answer questions.
You must investigate, reason, and conclude entirely on your own.

DATASET: Real auth.log from AWS EC2 honeypot (ip-172-31-27-153), Nov 30 – Dec 31 2024,
86,839 events. The server rejects all attackers at pre-auth — so there are no
"Failed password" events. Attack signals are:
  - "Invalid user"                        → bad username, attacker definitely hostile
  - "Too many authentication failures"   → SSH cut them off mid-burst
  - "Did not receive identification str" → port scanner / probe

INVESTIGATION PROTOCOL — ReAct (Reason → Act → Observe → Repeat):

Before EVERY tool call, narrate your reasoning: what you know so far, what gap
you're filling, and why this tool answers it. After seeing results, narrate what
you learned and what that implies. This narration IS your reasoning trace.

MANDATORY INVESTIGATION SEQUENCE — do not skip steps:

  STEP 1 — TRIAGE
    Call count_events for at least: invalid_user, brute_force_cutoff, all_ssh.
    Reason: establishes scale and confirms attack signals are present.

  STEP 2 — THREAT DETECTION
    Call detect_brute_force(threshold=5) to rank all attacking IPs.
    Reason: identifies the actors, their intensity, and time windows.

  STEP 3 — DEEP DIVE (repeat for top 3 IPs by threat profile)
    Call correlate_events for each. Choose IPs that represent different
    attack patterns (e.g., the highest-volume, the fastest, the most persistent).
    Reason: reconstructs attacker intent, technique, and targeting.

  STEP 4 — PATTERN ANALYSIS (optional but encouraged)
    Call search_logs for specific patterns that confirm or refute hypotheses
    (e.g., coordinated wordlists, specific username campaigns).

  STEP 5 — CONCLUDE
    Only after completing steps 1–3, call submit_report with your findings.

SEVERITY RUBRIC:
  Critical → active, ongoing attack OR evidence of successful authentication
  High     → confirmed brute-force campaign from multiple IPs, no breach
  Medium   → isolated scanning activity, low volume
  Low      → only automated probes, no credential attempts

IMPORTANT:
- Never call submit_report as your first action.
- Never ask the user a question — you have all the tools you need.
- If a tool returns an error, note it and continue with other tools.
- Be specific: cite IPs, counts, timestamps, and usernames from actual results.
""".strip()

# submit_report is a special tool — calling it ends the investigation loop
# and produces the final structured incident report.
SUBMIT_REPORT_TOOL: dict = {
    "name": "submit_report",
    "description": (
        "Submit the completed incident report to end the investigation. "
        "Call this ONLY after completing the mandatory investigation sequence "
        "(triage counts → brute force detection → at least 3 IP correlations). "
        "All fields in the report must be grounded in tool results you observed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["Low", "Medium", "High", "Critical"],
                "description": "Overall incident severity.",
            },
            "confidence": {
                "type": "string",
                "enum": ["Low", "Medium", "High"],
                "description": "Confidence in the severity assessment.",
            },
            "incident_type": {
                "type": "string",
                "description": "Short label, e.g. 'Multi-Vector SSH Brute Force Campaign'.",
            },
            "incident_confirmed": {
                "type": "boolean",
                "description": "True if a real attack is confirmed (not just noise).",
            },
            "attack_ongoing": {
                "type": "boolean",
                "description": "True if the attack was still active at the end of the log.",
            },
            "attack_succeeded": {
                "type": "boolean",
                "description": "True if any attacker appears to have authenticated successfully.",
            },
            "summary": {
                "type": "string",
                "description": "2-4 sentence executive summary of the incident.",
            },
            "log_period": {
                "type": "string",
                "description": "Date range of the log, e.g. '2024-11-30 to 2024-12-31'.",
            },
            "total_events_analyzed": {
                "type": "integer",
                "description": "Total log lines analyzed.",
            },
            "top_attacking_ips": {
                "type": "array",
                "description": "Top attacking IPs, each with metadata.",
                "items": {
                    "type": "object",
                    "properties": {
                        "ip":           {"type": "string"},
                        "attempts":     {"type": "integer"},
                        "first_seen":   {"type": "string"},
                        "last_seen":    {"type": "string"},
                        "behavior":     {"type": "string"},
                        "threat_level": {"type": "string"},
                    },
                    "required": ["ip", "attempts", "behavior", "threat_level"],
                },
            },
            "top_targeted_usernames": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Usernames most frequently targeted across all attackers.",
            },
            "attack_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Distinct attack patterns observed (e.g. coordinated botnet, slow-and-low).",
            },
            "iocs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Indicators of Compromise — attacker IP addresses.",
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Prioritized, specific remediation actions.",
            },
            "investigation_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "What the agent investigated, in order.",
            },
        },
        "required": [
            "severity", "confidence", "incident_type", "incident_confirmed",
            "attack_ongoing", "attack_succeeded", "summary",
            "top_attacking_ips", "top_targeted_usernames", "attack_patterns",
            "iocs", "recommended_actions", "investigation_steps",
        ],
    },
}

INVESTIGATION_TOOLS = TOOLS + [SUBMIT_REPORT_TOOL]

# Width of the report box
_W = 70


def _box(text: str, char: str = "═") -> str:
    return char * _W + f"\n{text}\n" + char * _W


def _section(title: str) -> str:
    return f"\n{'─' * _W}\n  {title}\n{'─' * _W}"


def _render_report(report: dict) -> None:
    """Pretty-print the final incident report to stdout."""

    sev = report.get("severity", "?")
    sev_colors = {
        "Critical": "\033[1;31m",  # bold red
        "High":     "\033[0;31m",  # red
        "Medium":   "\033[0;33m",  # yellow
        "Low":      "\033[0;32m",  # green
    }
    reset = "\033[0m"
    sev_color = sev_colors.get(sev, "")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print("\n\n" + "═" * _W)
    print(f"  SECURITY INCIDENT REPORT  —  {ts}")
    print("  Generated by Claude Opus 4.6  (autonomous ReAct investigation)")
    print("═" * _W)

    print(f"\n  SEVERITY    {sev_color}[{sev}]{reset}    CONFIDENCE: {report.get('confidence','?')}")
    print(f"  INCIDENT    {'CONFIRMED' if report.get('incident_confirmed') else 'NOT CONFIRMED'}")
    print(f"  TYPE        {report.get('incident_type','')}")

    confirmed_str = "YES — attack was active at log end" if report.get("attack_ongoing") else "No (historical — activity has ended)"
    success_str   = "YES — evidence of successful auth" if report.get("attack_succeeded") else "No — all attempts rejected at pre-auth"
    print(f"  ONGOING     {confirmed_str}")
    print(f"  BREACHED    {success_str}")
    if report.get("log_period"):
        print(f"  LOG PERIOD  {report['log_period']}")
    if report.get("total_events_analyzed"):
        print(f"  EVENTS      {report['total_events_analyzed']:,} analyzed")

    print(_section("EXECUTIVE SUMMARY"))
    summary = report.get("summary", "")
    for line in textwrap.wrap(summary, width=_W - 4):
        print(f"  {line}")

    print(_section("TOP ATTACKING IPs"))
    for i, ip_info in enumerate(report.get("top_attacking_ips", []), 1):
        print(f"  {i:>2}. {ip_info.get('ip',''):<18} "
              f"{ip_info.get('attempts',0):>5} attempts  "
              f"[{ip_info.get('threat_level','')}]")
        behavior = textwrap.wrap(ip_info.get("behavior", ""), width=_W - 8)
        for line in behavior:
            print(f"       {line}")
        if ip_info.get("first_seen") or ip_info.get("last_seen"):
            print(f"       {ip_info.get('first_seen','')}  →  {ip_info.get('last_seen','')}")

    print(_section("TOP TARGETED USERNAMES"))
    users = report.get("top_targeted_usernames", [])
    for line in textwrap.wrap(", ".join(users), width=_W - 4):
        print(f"  {line}")

    print(_section("ATTACK PATTERNS IDENTIFIED"))
    for pattern in report.get("attack_patterns", []):
        for line in textwrap.wrap(f"• {pattern}", width=_W - 4, subsequent_indent="    "):
            print(f"  {line}")

    print(_section("INDICATORS OF COMPROMISE"))
    iocs = report.get("iocs", [])
    for line in textwrap.wrap(", ".join(iocs), width=_W - 4):
        print(f"  {line}")

    print(_section("RECOMMENDED ACTIONS"))
    for i, action in enumerate(report.get("recommended_actions", []), 1):
        for line in textwrap.wrap(f"{i}. {action}", width=_W - 4, subsequent_indent="    "):
            print(f"  {line}")

    print(_section("INVESTIGATION TRACE"))
    for step in report.get("investigation_steps", []):
        print(f"  ✓ {step}")

    print("\n" + "═" * _W + "\n")


def run_investigation(log_file: Path = DEFAULT_LOG) -> dict:
    """
    Autonomous security investigation using the ReAct pattern.

    The agent:
      1. Receives a high-level security goal
      2. Decides what to investigate (Reason)
      3. Calls tools (Act)
      4. Reads results (Observe)
      5. Repeats until confident, then calls submit_report to conclude

    Returns the final report dict.
    No human input is required or expected mid-investigation.
    """
    goal = (
        "Analyze this log file and determine if there is an active or recent "
        "security incident. Investigate autonomously and produce a final "
        "structured incident report."
    )

    messages: list[dict] = [{"role": "user", "content": goal}]
    step = 0
    final_report: dict = {}

    print("\n" + "═" * _W)
    print("  AUTONOMOUS SECURITY INVESTIGATION")
    print(f"  Goal: {goal[:60]}...")
    print(f"  Model: {MODEL}   Pattern: ReAct")
    print("═" * _W)

    while True:
        step += 1

        # ── Stream this reasoning + action step ─────────────────────────────
        with client.messages.stream(
            model=MODEL,
            max_tokens=8192,
            system=INVESTIGATION_SYSTEM_PROMPT,
            tools=INVESTIGATION_TOOLS,
            messages=messages,
        ) as stream:
            # Print Claude's reasoning text in real time
            first_chunk = True
            for text_chunk in stream.text_stream:
                if first_chunk:
                    print(f"\n[STEP {step} — REASONING]\n")
                    first_chunk = False
                print(text_chunk, end="", flush=True)

            response = stream.get_final_message()

        # ── Natural end (shouldn't happen; prompt drives toward submit_report)
        if response.stop_reason == "end_turn":
            print("\n[Investigation ended without a formal report]\n")
            break

        # ── Tool use ─────────────────────────────────────────────────────────
        if response.stop_reason == "tool_use":
            tool_blocks = [b for b in response.content if b.type == "tool_use"]

            # Append Claude's full response (with reasoning + tool_use blocks)
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            report_submitted = False

            for tb in tool_blocks:
                if tb.name == "submit_report":
                    # ── Investigation complete ────────────────────────────
                    final_report = tb.input
                    print(f"\n\n[STEP {step} — ACT: submit_report]")
                    print("  Investigation complete. Compiling report...")
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": json.dumps({"status": "report_accepted"}),
                    })
                    report_submitted = True
                else:
                    # ── Regular tool call ─────────────────────────────────
                    print(f"\n[STEP {step} — ACT: {tb.name}]")
                    args_preview = json.dumps(tb.input, separators=(",", ":"))
                    print(f"  → {tb.name}({args_preview})")

                    result_str = execute_tool(tb.name, tb.input)
                    result_obj = json.loads(result_str)

                    # Print a meaningful observation summary
                    print(f"\n[STEP {step} — OBSERVE]")
                    _print_observation(tb.name, result_obj)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": result_str,
                    })

            messages.append({"role": "user", "content": tool_results})

            if report_submitted:
                _render_report(final_report)
                break

            # Loop — Claude reads observations and decides what to do next
            continue

    return final_report


def _print_observation(tool_name: str, result: dict) -> None:
    """Print a concise, human-readable summary of a tool result."""
    if tool_name == "count_events":
        print(f"  {result.get('event_type')}: {result.get('count', 0):,} events")

    elif tool_name == "detect_brute_force":
        total = result.get("total_ips", 0)
        attackers = result.get("attackers", [])
        print(f"  {total} IPs above threshold")
        for a in attackers[:5]:
            users_preview = ", ".join(a.get("targeted_users", [])[:3])
            if len(a.get("targeted_users", [])) > 3:
                users_preview += f" (+{len(a['targeted_users'])-3} more)"
            print(f"  {a['ip']:<18} {a['attempts']:>5} attempts  "
                  f"{a.get('attack_window_minutes', 0):.0f}m  [{users_preview}]")
        if len(attackers) > 5:
            print(f"  ... and {len(attackers)-5} more IPs")

    elif tool_name == "correlate_events":
        s = result.get("summary", {})
        print(f"  IP {result.get('ip')}  —  {result.get('total_events', 0)} events")
        print(f"  First: {result.get('first_seen','')}   Last: {result.get('last_seen','')}")
        print(f"  Invalid-user: {s.get('invalid_user_attempts',0)}  "
              f"Disconnects: {s.get('disconnects',0)}  "
              f"BF-cutoffs: {s.get('brute_force_cutoffs',0)}  "
              f"Probes: {s.get('probes',0)}")
        users = s.get("targeted_users", [])
        if users:
            print(f"  Targeted: {', '.join(users[:8])}" +
                  (f" (+{len(users)-8} more)" if len(users) > 8 else ""))

    elif tool_name == "search_logs":
        print(f"  '{result.get('query')}': {result.get('total_matches', 0):,} matches")
        for m in result.get("matches", [])[:3]:
            print(f"  {m.get('line','')[:80]}")

    elif "error" in result:
        print(f"  ERROR: {result['error']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEMO_QUESTIONS = [
    "Which IPs had the most failed login attempts?",
    "Was there a brute force attack? Give me details.",
    "Which usernames are being targeted the most?",
    "Show me all activity from IP 173.192.158.3",
]

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        AWS Auth Log Security Agent  (Claude Opus 4.6)       ║
║        Log: data/auth_modern.log  |  86,839 events          ║
╚══════════════════════════════════════════════════════════════╝
Type your security question, or 'demo' to run sample questions.
Type 'quit' or Ctrl-C to exit.
""".strip()


def main() -> None:
    args = sys.argv[1:]

    # Autonomous investigation mode
    if args and args[0] == "--investigate":
        run_investigation()
        return

    # Single question from CLI arg
    if args and args[0] not in ("--demo", "--investigate"):
        question = " ".join(args)
        print(f"\nQ: {question}\n")
        print("A: ", end="")
        ask(question, verbose=True)
        return

    # Demo mode — run all four canonical questions
    if args and args[0] == "--demo":
        for i, q in enumerate(DEMO_QUESTIONS, 1):
            print(f"\n{'='*64}")
            print(f"Demo {i}/{len(DEMO_QUESTIONS)}: {q}")
            print("=" * 64)
            print()
            ask(q, verbose=True)
            print()
        return

    # Interactive REPL
    print(BANNER)
    print()
    while True:
        try:
            question = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not question:
            continue
        if question.lower() in ("quit", "exit", "q"):
            print("Bye.")
            break
        if question.lower() == "demo":
            for q in DEMO_QUESTIONS:
                print(f"\nQ: {q}\n")
                print("Agent: ", end="")
                ask(q, verbose=True)
                print()
            continue
        if question.lower() == "investigate":
            run_investigation()
            continue

        print("\nAgent: ", end="")
        ask(question, verbose=True)
        print()


if __name__ == "__main__":
    main()
