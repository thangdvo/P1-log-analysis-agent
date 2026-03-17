"""
agent.py

A Claude-powered security log analysis agent. Accepts natural language
questions and answers them by calling tools against data/auth_modern.log.

Usage:
    python src/agent.py                          # interactive REPL
    python src/agent.py "Was there a brute force attack?"  # single question
    python src/agent.py --demo                   # run all four demo questions

Architecture:
    User question
        ↓
    Claude (claude-opus-4-6) — decides which tool(s) to call
        ↓
    Tool execution (Python functions from tools.py)
        ↓
    Claude — synthesizes results into a plain-English answer
        ↓
    User
"""

import json
import os
import sys
import textwrap
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

    # Single question from CLI arg
    if args and args[0] != "--demo":
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

        print("\nAgent: ", end="")
        ask(question, verbose=True)
        print()


if __name__ == "__main__":
    main()
