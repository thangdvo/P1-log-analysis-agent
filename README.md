# P1: Autonomous SSH Log Analysis Agent

An autonomous security investigation agent that drops a `.log` file into S3, runs a multi-step Claude Opus 4.6 ReAct loop against it, and produces a structured incident report with no human in the loop. Deployed on AWS (S3 + Lambda + SNS). Also runs locally for interactive Q&A.



---

## What It Actually Does

This is **not** a Q&A chatbot. Upload a log file and the agent investigates it autonomously:

1. Counts all SSH event categories to establish attack scale
2. Runs brute-force detection to rank all attacking IPs
3. Correlates detailed timelines for the top 3–5 threat actors
4. Searches for cross-IP patterns (shared wordlists, coordinated timing)
5. Files a structured incident report: severity, IOCs, recommended actions

The entire investigation (8 API calls, ~15 tool executions, ~2 minutes) runs without any human prompting. The final output is a JSON incident report saved back to S3 and an email alert if severity is Medium or higher.

---

## Dataset

**Source:** [SecRepo Security Log Samples](https://www.secrepo.com/): `auth.log` from an AWS EC2 honeypot (`ip-172-31-27-153`, us-east-1)

| Metric | Value |
|---|---|
| Period | Nov 30 – Dec 31, 2024 |
| Total events | 86,839 lines |
| Total SSH events | 85,246 |
| Invalid-user attempts | 12,250 |
| Brute-force cutoffs | 2,575 |
| Unique attacking IPs (≥5 attempts) | 361 |
| Port-scan probes | 969 |
| Successful authentications | **0** |

The server rejects attackers at **pre-auth**; there are no `Failed password` events. All attack signals are `Invalid user`, `Too many authentication failures`, and `Did not receive identification string`.

---

## Architecture

### Cloud (production path)

```
┌─────────────────────────────────────────────────────────────────┐
│  Developer / CI / Automated collector                           │
│  aws s3 cp auth.log s3://p1-log-analysis-tdv/logs/incoming/    │
└──────────────────────────┬──────────────────────────────────────┘
                           │  s3:ObjectCreated (*.log)
                           ▼
              ┌────────────────────────┐
              │  S3 Event Notification │
              └────────────┬───────────┘
                           │  invokes
                           ▼
        ┌──────────────────────────────────────┐
        │  Lambda: p1-log-analysis-agent       │
        │  Python 3.11 · 512 MB · 15-min limit │
        │                                      │
        │  1. Download log → /tmp              │
        │  2. run_investigation()              │
        │     └─ ReAct loop (Claude Opus 4.6) │
        │        ├─ Step 1: Triage counts      │
        │        ├─ Step 2: Brute-force rank   │
        │        ├─ Step 3: IP deep-dives      │
        │        ├─ Step 4: Pattern analysis   │
        │        └─ Step 5: submit_report      │
        │  3. Save JSON report → S3            │
        │  4. SNS alert if severity ≥ Medium   │
        └──────────┬──────────────┬────────────┘
                   │              │
          ┌────────▼───────┐  ┌───▼────────────────────────┐
          │  S3 reports/   │  │  SNS: p1-security-alerts   │
          │  *_report.json │  │  → email: thangvo@gmail.com │
          └────────────────┘  └────────────────────────────┘
                   │
          ┌────────▼────────┐
          │  CloudWatch Logs │
          │  (full ReAct     │
          │   trace)         │
          └─────────────────┘
```

### Local (interactive path)

```
python src/agent.py --investigate     # autonomous ReAct loop, same as Lambda
python src/agent.py                   # interactive Q&A REPL
python src/agent.py "Was there a brute force attack?"   # single question
python src/agent.py --demo            # four canonical demo questions
```

---

## AWS Resources Deployed

| Resource | Name | Region |
|---|---|---|
| S3 bucket | `p1-log-analysis-tdv` | us-east-2 |
| Lambda function | `p1-log-analysis-agent` | us-east-2 |
| SNS topic | `p1-security-alerts` | us-east-2 |
| IAM role | `p1-log-analysis-lambda-role` | global |

**IAM permissions (least-privilege):**

| Action | Resource scoped to |
|---|---|
| `s3:GetObject` | `logs/incoming/*` only |
| `s3:PutObject` | `reports/*` only |
| `sns:Publish` | `p1-security-alerts` ARN only |
| `logs:CreateLogGroup/Stream/PutLogEvents` | Lambda's own log group only |

---

## How to Trigger an Investigation

```bash
# Upload any .log file; Lambda fires automatically
aws s3 cp your-auth.log s3://p1-log-analysis-tdv/logs/incoming/ --region us-east-2

# Watch it run in CloudWatch Logs
aws logs tail /aws/lambda/p1-log-analysis-agent --follow --region us-east-2

# Retrieve the finished report
aws s3 cp s3://p1-log-analysis-tdv/reports/your-auth_report.json . --region us-east-2
```

Investigation takes ~2 minutes for an 86,000-line log (8 Claude API calls, 15 tool executions). An email alert fires to the subscribed address if severity is Medium, High, or Critical.

---

## Real Investigation Output

The agent ran against `auth_modern.log` and produced this report autonomously (no human prompting):

```
══════════════════════════════════════════════════════════════════════
  SECURITY INCIDENT REPORT  2026-03-17 19:36 UTC
  Generated by Claude Opus 4.6  (autonomous ReAct investigation)
══════════════════════════════════════════════════════════════════════

  SEVERITY    [High]    CONFIDENCE: High
  INCIDENT    CONFIRMED
  TYPE        Multi-Vector SSH Brute Force Campaign
  ONGOING     YES - attack was still active at log end (Dec 31)
  BREACHED    No - all 12,250 attempts rejected at pre-auth
  LOG PERIOD  2024-11-30 to 2024-12-31
  EVENTS      85,246 analyzed

──────────────────────────────────────────────────────────────────────
  EXECUTIVE SUMMARY
──────────────────────────────────────────────────────────────────────
  A sustained, multi-vector SSH brute force campaign targeted AWS EC2
  honeypot ip-172-31-27-153 throughout December 2024. 361 unique
  attacking IPs generated 12,250 invalid-user attempts and 2,575
  brute-force cutoffs. The campaign involved coordinated botnet
  clusters, persistent slow-and-low scanners, rapid-fire burst
  attackers, and an unusual actor using AWS IP addresses as SSH
  usernames (potential infrastructure reconnaissance). No successful
  authentication occurred.

──────────────────────────────────────────────────────────────────────
  TOP ATTACKING IPs
──────────────────────────────────────────────────────────────────────
   1. 218.75.153.170       731 attempts  [High]
      733 events, 695 probes: postgres credential stuffing + port scan
      2024-11-30T09:03:27  →  2024-11-30T21:27:00

   2. 220.99.93.50         409 attempts  [High]
      10,752 events: botnet node, 10,343 disconnects, shared wordlist
      2024-12-04T17:19:54  →  2024-12-04T20:47:41

   3. 222.161.209.92       356 attempts  [High]
      1,493 events over 19 days: slow-and-low IoT scanner, still
      active Dec 31. SSH flagged as POSSIBLE BREAK-IN ATTEMPT.

   4. 173.192.158.3        303 attempts  [Medium]
      748 events in 4 min 39 sec: multilingual wordlist (Portuguese,
      Indian names), reconnects per attempt to evade per-session limits

   5. 120.198.156.138       93 attempts  [Medium]
      185 events: used 54.173.x.x AWS IP addresses as usernames,
      possible infrastructure reconnaissance (Dec 24–Dec 31)

──────────────────────────────────────────────────────────────────────
  ATTACK PATTERNS IDENTIFIED
──────────────────────────────────────────────────────────────────────
  • Coordinated botnet: 4 IPs (220.99.93.50, 218.25.17.234,
    61.197.203.243, 188.87.35.25) used an identical 48-username
    wordlist with exactly 409 attempts each on different days

  • Slow-and-low evasion: 222.161.209.92 ran for 19 days,
    91.135.226.34 for 18 days, paced to stay under rate-limit
    thresholds

  • Rapid-fire blitz: 173.192.158.3 hit 303 attempts in 4 min 39 sec
    (~1 attempt/sec), reconnecting per attempt to avoid SSH cutoffs

  • Single-target credential stuffing: 218.75.153.170 hammered
    'postgres' exclusively, combined with 695 port probes

  • IoT botnet recruitment: PlcmSpIp (Polycom), ubnt (Ubiquiti),
    vyatta, pi (Raspberry Pi) targeted across multiple IPs

  • AWS infrastructure recon: 120.198.156.138 used EC2 IP addresses
    as SSH usernames; possible lateral movement mapping

──────────────────────────────────────────────────────────────────────
  TOP TARGETED USERNAMES  (of 12,250 invalid-user events)
──────────────────────────────────────────────────────────────────────
  admin (3,914) · test (1,980) · postgres · oracle · guest ·
  ftp · nagios · git · user · pi · ubnt · PlcmSpIp

──────────────────────────────────────────────────────────────────────
  RECOMMENDED ACTIONS
──────────────────────────────────────────────────────────────────────
  1. [IMMEDIATE] Implement fail2ban; ban after 3 invalid attempts
  2. [IMMEDIATE] Block top 20 IOC IPs at Security Group / NACL level
  3. [HIGH] Disable password auth in sshd_config (key-only)
  4. [HIGH] Move SSH off port 22; eliminates ~90% of automated scans
  5. [MEDIUM] Deploy GuardDuty for real-time SSH brute-force detection
  6. [MEDIUM] GeoIP-block CN ranges at the firewall level
```

---

## Agent Tools

| Tool | Purpose |
|---|---|
| `count_events(event_type)` | Count events by category: invalid_user, brute_force_cutoff, disconnect, probe, all_ssh, fatal, cron |
| `detect_brute_force(threshold)` | Rank IPs by hostile attempts; returns attack windows, first/last seen, targeted usernames |
| `correlate_events(ip)` | Full summary + timeline for a single IP |
| `search_logs(query)` | Keyword/IP/username search across all log lines |

The investigation loop also uses `submit_report`, a structured tool whose schema enforces all required report fields. Calling it ends the loop. Claude cannot finish without filing a grounded report.

---

## ReAct Loop Design

```
GOAL: "Analyze this log file and determine if there is an active
       or recent security incident."
  │
  ▼
[Reason] What do I know? What gap am I filling?
  │
  ▼
[Act]     Tool call (count_events / detect_brute_force / correlate_events / search_logs)
  │
  ▼
[Observe] What did I learn? What does it imply?
  │
  └──► [Reason] again ... (repeat for 5–8 steps)
  │
  ▼
[submit_report]  ← structured tool call that ends the loop
```

The system prompt enforces a mandatory 5-step sequence: triage → threat detection → deep-dive ≥3 IPs → pattern analysis → conclude. Claude cannot call `submit_report` as its first action. All report fields must be grounded in tool results observed during the run.

---

## Cost

| Mode | Model | Cost/run |
|---|---|---|
| Autonomous investigation | Claude Opus 4.6 | ~$0.38 |
| Autonomous investigation | Claude Sonnet 4.6 | ~$0.23 |

Two optimizations reduce cost ~31% vs. the naive baseline:
- **Prompt caching** on system prompt + tool definitions: ~12% saving (constant 1,900-token overhead cached after first call)
- **Summary-only `correlate_events`** in investigation mode: ~19% saving (raw timeline stripped; only the summary dict re-sent in subsequent calls)

At $0.38/run on Opus 4.6: ~$11/month running once daily.

---

## Repository Layout

```
P1_log_analysis_agent/
├── aws/
│   └── lambda_handler.py     ← Lambda entry point (S3 trigger → investigation → report)
├── data/
│   ├── auth.log              ← raw SecRepo dataset (not in repo, too large)
│   └── auth_modern.log       ← ISO 8601 timestamps (generated by modernize_logs.py)
├── src/
│   ├── modernize_logs.py     ← converts legacy syslog timestamps to ISO 8601
│   ├── tools.py              ← four agent tools with structured dict returns
│   └── agent.py              ← ReAct investigator + Q&A agent + streaming loop
├── tests/
│   └── test_tools.py         ← 45 tests against real log data (no mocks)
└── DECISIONS.md              ← 16 design decisions with reasoning
```

---

## Local Setup

**Requirements:** Python 3.10+, Anthropic API key

```bash
# 1. Clone
git clone https://github.com/thangdvo/P1-log-analysis-agent
cd P1-log-analysis-agent

# 2. Install dependencies
pip install anthropic python-dotenv pytest

# 3. Set your API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# 4. Download log data (not in repo)
# Get auth.log from https://www.secrepo.com/ → data/

# 5. Modernize timestamps (one-time)
python src/modernize_logs.py

# 6. Run an autonomous investigation
python src/agent.py --investigate

# 7. Interactive Q&A
python src/agent.py

# 8. Single question
python src/agent.py "Were there any low-and-slow attacks?"

# 9. Four canonical demo questions
python src/agent.py --demo
```

## Running Tests

```bash
pytest tests/ -v
# 45 passed in 2.03s
```

All 45 tests run against the real `auth_modern.log` with no mocks, no fixtures. Known facts (IP `218.75.153.170` is top attacker, `173.192.158.3` had 748 events in 4 min 39 sec) serve as regression anchors.

---

## Skills Demonstrated

- **Autonomous AI agent design**: ReAct pattern, `submit_report` as loop termination, mandatory investigation sequence enforced via system prompt
- **AWS serverless architecture**: S3 event triggers, Lambda, SNS, CloudWatch, IAM least-privilege
- **Cost engineering**: prompt caching, summary-only tool results, token footprint analysis
- **Log analysis**: legacy syslog parsing, ISO 8601 modernization, brute-force detection, botnet correlation
- **Python**: regex, datetime, boto3, structured return contracts, platform-targeted Lambda packaging
- **Testing**: 45 data-driven regression tests against real security data

---

## Part of a 12-Project Cloud Security Portfolio

Project 1 of a series combining AI agent building with AWS cloud security engineering. Each project targets a real-world security problem on AWS.
