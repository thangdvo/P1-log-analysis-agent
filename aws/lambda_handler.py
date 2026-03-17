"""
aws/lambda_handler.py

Lambda entry point for the P1 Log Analysis Agent.

Trigger: S3 ObjectCreated on s3://p1-log-analysis-tdv/logs/incoming/*.log
Flow:
  1. Download the .log file from S3 to /tmp
  2. Run run_investigation() — autonomous ReAct loop, ~8 Claude API calls
  3. Save the JSON incident report to s3://…/reports/<stem>_report.json
  4. If severity is Medium / High / Critical, publish an SNS alert
  5. Log everything to CloudWatch

Environment variables (set on the Lambda function):
  ANTHROPIC_API_KEY  — Claude API key
  SNS_TOPIC_ARN      — ARN of p1-security-alerts topic
"""

import json
import os
import sys
import textwrap
from pathlib import Path

import boto3

# /var/task is the Lambda root; put it on sys.path so "from src.X import …" works
sys.path.insert(0, "/var/task")

s3 = boto3.client("s3")
sns = boto3.client("sns", region_name="us-east-2")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ALERT_SEVERITIES = {"Medium", "High", "Critical"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def handler(event, context):
    """
    Called by Lambda when a file lands in s3://…/logs/incoming/.
    """
    record = event["Records"][0]
    bucket = record["s3"]["bucket"]["name"]
    key = record["s3"]["object"]["key"]

    print(f"[trigger] s3://{bucket}/{key}")

    # Only process .log files in the expected prefix
    if not key.startswith("logs/incoming/") or not key.endswith(".log"):
        print(f"[skip] not a .log file in logs/incoming/ — ignoring")
        return {"statusCode": 200, "body": "skipped"}

    # ── 1. Download to /tmp ────────────────────────────────────────────────
    filename = Path(key).name
    local_path = Path(f"/tmp/{filename}")
    print(f"[download] {key} → {local_path}")
    s3.download_file(bucket, key, str(local_path))
    size_mb = local_path.stat().st_size / 1_048_576
    print(f"[download] done — {size_mb:.1f} MB")

    # ── 2. Run the autonomous investigation ───────────────────────────────
    print("[investigate] starting ReAct investigation loop …")
    from src.agent import run_investigation  # lazy import — avoids cold-start cost
    report = run_investigation(log_file=local_path)

    if not report:
        print("[error] investigation returned empty report")
        return {"statusCode": 500, "body": "empty report"}

    severity = report.get("severity", "Low")
    incident_type = report.get("incident_type", "Unknown")
    print(f"[result] severity={severity}  type={incident_type}")

    # ── 3. Save JSON report to S3 ─────────────────────────────────────────
    report_key = f"reports/{Path(key).stem}_report.json"
    report_body = json.dumps(report, indent=2, default=str).encode("utf-8")
    s3.put_object(
        Bucket=bucket,
        Key=report_key,
        Body=report_body,
        ContentType="application/json",
    )
    print(f"[report] saved → s3://{bucket}/{report_key}")

    # ── 4. SNS alert for Medium+ severity ─────────────────────────────────
    if severity in ALERT_SEVERITIES and SNS_TOPIC_ARN:
        subject = f"[{severity}] {incident_type} — p1-log-analysis"
        message = _format_alert(report, bucket, report_key)
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject max = 100 chars
            Message=message,
        )
        print(f"[sns] alert published (severity={severity})")
    elif not SNS_TOPIC_ARN:
        print("[sns] SNS_TOPIC_ARN not set — skipping alert")
    else:
        print(f"[sns] severity={severity} below alert threshold — no alert sent")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "bucket": bucket,
            "source_key": key,
            "report_key": report_key,
            "severity": severity,
            "incident_confirmed": report.get("incident_confirmed", False),
        }),
    }


# ---------------------------------------------------------------------------
# SNS message formatter
# ---------------------------------------------------------------------------

def _format_alert(report: dict, bucket: str, report_key: str) -> str:
    sev = report.get("severity", "?")
    conf = report.get("confidence", "?")
    ongoing = "YES — attack still active at log end" if report.get("attack_ongoing") else "No (historical)"
    breached = "YES — evidence of successful auth" if report.get("attack_succeeded") else "No — all attempts rejected"

    lines = [
        "=" * 60,
        f"SECURITY INCIDENT DETECTED",
        "=" * 60,
        "",
        f"Severity:   {sev}  (Confidence: {conf})",
        f"Type:       {report.get('incident_type', '')}",
        f"Ongoing:    {ongoing}",
        f"Breached:   {breached}",
        "",
        "SUMMARY",
        "-------",
    ]
    for line in textwrap.wrap(report.get("summary", ""), width=60):
        lines.append(line)

    lines += ["", "TOP ATTACKING IPs", "-----------------"]
    for ip_info in report.get("top_attacking_ips", [])[:5]:
        lines.append(
            f"  {ip_info.get('ip', ''):<18}  "
            f"{ip_info.get('attempts', 0):>5} attempts  "
            f"[{ip_info.get('threat_level', '')}]"
        )
        if ip_info.get("behavior"):
            for bline in textwrap.wrap(ip_info["behavior"], width=56, initial_indent="    "):
                lines.append(bline)

    lines += ["", "RECOMMENDED ACTIONS (top 3)", "---------------------------"]
    for i, action in enumerate(report.get("recommended_actions", [])[:3], 1):
        for aline in textwrap.wrap(f"{i}. {action}", width=60, subsequent_indent="   "):
            lines.append(aline)

    lines += [
        "",
        "-" * 60,
        f"Full report: s3://{bucket}/{report_key}",
        "",
        "Automated by P1 Log Analysis Agent",
        "Claude Opus 4.6  |  Autonomous ReAct Investigation",
        "=" * 60,
    ]
    return "\n".join(lines)
