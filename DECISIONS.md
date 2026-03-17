# Design Decisions — P1 Log Analysis Agent

Every non-trivial design choice made during this project, with the reasoning.

---

## 1. Timestamp Modernization (ISO 8601)

**Decision:** Pre-process `auth.log` into `auth_modern.log` with ISO 8601 timestamps before building any tools.

**Why:** Legacy syslog timestamps (`Nov 30 06:39:00`) lack a year and timezone, making them ambiguous and requiring fragile parsing in every tool. ISO 8601 (`2024-11-30T06:39:00+00:00`) is:
- Sortable as a plain string (lexicographic == chronological)
- Parseable with `datetime.fromisoformat()` — no format string needed
- Timezone-explicit — the server is UTC, and this is now encoded in the data itself

**Trade-off:** Adds a pre-processing step. Acceptable because it's a one-time O(n) pass that makes every downstream operation simpler.

---

## 2. Four Tools (Not One)

**Decision:** Split functionality across four focused tools rather than one general-purpose query function.

**Why:** Each tool is optimized for a different query pattern:
- `search_logs` — keyword/IP/username lookup, returns raw lines
- `count_events` — aggregate statistics, no line retrieval overhead
- `detect_brute_force` — ranked attacker list with pre-computed metadata (first/last seen, attack window, targeted users)
- `correlate_events` — full per-IP timeline for deep-dive investigation

A single "query" function would either be slow for statistics (scanning for counts while returning lines) or lossy for timelines (summarizing when raw order matters). Separate tools let Claude call only what a given question needs, and call multiple tools in parallel when a question needs both counts and rankings.

**Trade-off:** More tools = more tokens in the system prompt. Acceptable — the tool definitions are concise and the specialization pays off in answer quality.

---

## 3. Manual Agentic Loop (Not Tool Runner)

**Decision:** Implement the agentic loop manually (check `stop_reason`, execute tools, loop) rather than using the Anthropic SDK's beta `tool_runner`.

**Why:**
- The `tool_runner` beta is opaque — debugging requires understanding its internals
- Manual loop gives precise control over result clipping before feeding back to Claude (critical for large outputs like 748-event timelines)
- Verbose logging (`[tool]` / `[result]` lines) is trivial to add in a manual loop, and is essential for demo credibility — you can see exactly what Claude decided to call
- The loop logic is ~30 lines and well-understood

**Trade-off:** More boilerplate. Acceptable for the control and observability gained.

---

## 4. Result Clipping Before Tool Results Reach Claude

**Decision:** Truncate large tool outputs before returning them to Claude rather than passing full raw results.

**Limits applied:**
- `search_logs`: first 30 matches shown; total count always included
- `detect_brute_force`: top 20 attackers (out of up to 361)
- `correlate_events`: first 20 + last 5 timeline events when total > 25

**Why:** Claude's context window is finite, and sending 748 raw log lines for a single IP wastes tokens and can degrade response quality (Claude loses focus on the summary statistics). The summary fields (`invalid_user_attempts`, `targeted_users`, etc.) convey the same analytical value as the raw lines.

**Trade-off:** Claude can't see the full timeline. Mitigated by always including the pre-computed `summary` block alongside the clipped timeline, so the statistical picture is complete even when individual events are trimmed.

---

## 5. Streaming Output

**Decision:** Use `client.messages.stream()` + `stream.get_final_message()` rather than non-streaming `client.messages.create()`.

**Why:** This agent can run multi-step tool chains (e.g., Demo Q2 called 7 tools across two rounds). Without streaming, the terminal is silent for 10–20 seconds while Claude thinks, which is a bad demo experience. Streaming outputs text tokens as they're generated, making the agent feel responsive even on multi-tool questions.

`get_final_message()` cleanly retrieves the complete response after streaming without needing to manually accumulate deltas.

**Trade-off:** Slightly more complex context manager syntax. No real downside for a CLI application.

---

## 6. Model Choice: Claude Opus 4.6

**Decision:** Use `claude-opus-4-6` rather than Sonnet or Haiku.

**Why:** The agent needs to:
1. Read tool result JSON and extract meaningful patterns (e.g., spotting that four IPs share an identical wordlist)
2. Call the right tools for open-ended questions (e.g., "Was there a brute force?" is underspecified — the right answer requires both count and ranking data)
3. Write clear, structured security analysis with specific IP citations, not generic summaries

Opus 4.6 reliably makes good tool-selection decisions and produces analysis-quality prose. In testing, Sonnet made occasional tool-selection mistakes on compound questions and produced less insightful summaries.

**Trade-off:** Higher cost per question (~$0.05–0.15 per demo question vs ~$0.01 for Haiku). Acceptable for a portfolio demo where quality matters.

---

## 7. No "Failed Password" Events — Dataset Characteristic

**Decision:** Document explicitly that this dataset has no `Failed password` events and adjust tool patterns accordingly.

**Why:** Standard SSH brute-force analysis typically counts `Failed password` lines. This server rejects attackers at **pre-auth** — before they even attempt a password. The meaningful attack signals are:
- `Invalid user` — attempted login with a username that doesn't exist on the system
- `Too many authentication failures` — SSH's own rate-limiter kicked in mid-session
- `Did not receive identification string` — port scanner that never completed the SSH handshake

This is explicitly documented in the system prompt so Claude doesn't suggest looking for `Failed password` events and doesn't misinterpret the absence of that string as "no attacks found."

---

## 8. All Tests Against Real Data (No Mocks)

**Decision:** Write all 45 tests against the actual `auth_modern.log` rather than creating small fixture files.

**Why:**
- The tools' correctness *is* their ability to accurately analyze real logs — a synthetic fixture can't validate that
- Hard-coded known facts (e.g., "IP 173.192.158.3 had 748 events on Dec 2") provide meaningful regression coverage: if the parsing logic changes and changes the count, the test fails
- Fixtures would need to be maintained as the log processing evolves

**Trade-off:** Tests are slower (~2 seconds for the full suite) and require the data file to be present. Acceptable — the suite still runs in under 5 seconds and the data path is well-defined.

---

## 9. Structured Return Contracts for All Tools

**Decision:** Every tool returns a typed dict with consistent fields, never raw strings or bare lists.

**Why:** Claude needs to parse tool results reliably. Returning `{"total_matches": 3914, "matches": [...]}` is far more robust than a formatted string like `"Found 3914 matches:\n..."`. Structured returns let Claude:
- Extract the count without regex-parsing a sentence
- Iterate over `matches` as a list
- Access nested fields like `attacker["targeted_users"]` directly

This also makes the tools independently testable — the test suite validates field presence and data types, not string output formatting.

---

## 10. `.env` for API Key Management

**Decision:** Load `ANTHROPIC_API_KEY` from a `.env` file using `python-dotenv`, with `.env` in `.gitignore`.

**Why:** Hardcoding API keys in source or passing them as CLI arguments risks accidental exposure in shell history or git commits. The `.env` pattern is the standard Python convention for local secrets — it keeps the key out of the codebase while remaining convenient for local development.

The `.gitignore` explicitly excludes `.env` and `data/` (logs may contain IP addresses that could be considered sensitive in some jurisdictions).
