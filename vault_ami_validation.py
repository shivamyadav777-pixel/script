#!/usr/bin/env python3
import argparse
import json
import mimetypes
import random
import smtplib
import ssl
import subprocess
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CheckResult:
    name: str
    status: str
    details: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class ValidationError(Exception):
    pass


def run_cmd(
    cmd: List[str],
    env: Optional[Dict[str, str]] = None,
    check: bool = True
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        shell=False
    )
    if check and result.returncode != 0:
        raise ValidationError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def run_json_cmd(cmd: List[str], env: Optional[Dict[str, str]] = None) -> Any:
    result = run_cmd(cmd, env=env)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Expected JSON output from: {' '.join(cmd)}\nOutput was:\n{result.stdout}"
        ) from exc


def utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def build_env(base_env: Dict[str, str], vault_addr: str, vault_token: Optional[str]) -> Dict[str, str]:
    merged = dict(base_env)
    merged["VAULT_ADDR"] = vault_addr
    if vault_token:
        merged["VAULT_TOKEN"] = vault_token
    return merged


def check_vault_login(env_vars: Dict[str, str]) -> CheckResult:
    data = run_json_cmd(["vault", "token", "lookup", "-format=json"], env=env_vars)
    return CheckResult(
        name="Vault login",
        status="PASS",
        details="Vault token is valid.",
        evidence={"display_name": data.get("data", {}).get("display_name")}
    )


def check_secret_rw(env_vars: Dict[str, str], mount_path: str) -> CheckResult:
    key = f"ami_validation_{utc_now_str()}"
    value = "ok"

    run_cmd(["vault", "kv", "put", mount_path, f"{key}={value}"], env=env_vars)
    secret_data = run_json_cmd(["vault", "kv", "get", "-format=json", mount_path], env=env_vars)

    actual = secret_data.get("data", {}).get("data", {}).get(key)
    if actual != value:
        raise ValidationError(f"Secret write/read mismatch. Expected {value}, got {actual}")

    return CheckResult(
        name="Secret read/write",
        status="PASS",
        details=f"Successfully wrote and read key '{key}' in {mount_path}.",
        evidence={"path": mount_path, "key": key, "value": actual}
    )


def check_raft_peers(env_vars: Dict[str, str], cluster_name: str, expected_total: int = 5) -> CheckResult:
    data = run_json_cmd(["vault", "operator", "raft", "list-peers", "-format=json"], env=env_vars)
    peers = data.get("data", {}).get("config", {}).get("servers", [])

    total = len(peers)
    leaders = [peer for peer in peers if peer.get("leader") is True]
    followers = [peer for peer in peers if peer.get("leader") is not True]

    if total != expected_total:
        raise ValidationError(f"{cluster_name}: expected {expected_total} raft peers, found {total}")
    if len(leaders) != 1:
        raise ValidationError(f"{cluster_name}: expected 1 leader, found {len(leaders)}")
    if len(followers) != expected_total - 1:
        raise ValidationError(f"{cluster_name}: expected {expected_total - 1} followers, found {len(followers)}")

    return CheckResult(
        name=f"Raft peers ({cluster_name})",
        status="PASS",
        details=f"{cluster_name} has {total} peers: 1 leader and {len(followers)} followers.",
        evidence={"servers": peers}
    )


def check_snapshot_status(env_vars: Dict[str, str]) -> CheckResult:
    status_data = run_json_cmd(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/status/s3"],
        env=env_vars
    )
    config_data = run_json_cmd(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/config/s3"],
        env=env_vars
    )

    return CheckResult(
        name="Snapshot auto status",
        status="PASS",
        details="Retrieved raft snapshot auto status and config.",
        evidence={
            "status": status_data.get("data", {}),
            "config": config_data.get("data", {})
        }
    )


def check_s3_snapshot(bucket: str, prefix: str, aws_profile: Optional[str] = None, aws_region: Optional[str] = None) -> CheckResult:
    cmd = ["aws"]
    if aws_profile:
        cmd.extend(["--profile", aws_profile])
    if aws_region:
        cmd.extend(["--region", aws_region])

    cmd.extend([
        "s3api",
        "list-objects-v2",
        "--bucket", bucket,
        "--prefix", prefix
    ])

    data = run_json_cmd(cmd)
    contents = data.get("Contents", [])
    if not contents:
        raise ValidationError(f"No snapshot objects found in s3://{bucket}/{prefix}")

    latest = max(contents, key=lambda obj: obj["LastModified"])
    return CheckResult(
        name="S3 snapshot freshness",
        status="PASS",
        details=f"Latest snapshot found: {latest['Key']}",
        evidence={
            "bucket": bucket,
            "prefix": prefix,
            "latest_key": latest["Key"],
            "last_modified": latest["LastModified"]
        }
    )


def check_unsealed_nodes(cluster_name: str, nodes: List[Dict[str, str]], vault_token: str) -> CheckResult:
    failures = []
    results = []
    ssl_context = ssl.create_default_context()

    for node in nodes:
        url = node["health_url"]
        req = urllib.request.Request(url, headers={"X-Vault-Token": vault_token})
        try:
            with urllib.request.urlopen(req, context=ssl_context, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            failures.append({"node": node["name"], "error": str(exc)})
            continue

        sealed = payload.get("sealed")
        standby = payload.get("standby")
        initialized = payload.get("initialized")

        node_result = {
            "node": node["name"],
            "sealed": sealed,
            "standby": standby,
            "initialized": initialized,
            "cluster_name": payload.get("cluster_name")
        }
        results.append(node_result)

        if sealed is not False:
            failures.append({"node": node["name"], "error": f"sealed={sealed}"})

    if failures:
        raise ValidationError(f"{cluster_name}: unseal check failed for nodes: {failures}")

    return CheckResult(
        name=f"Unsealed nodes ({cluster_name})",
        status="PASS",
        details=f"All nodes in {cluster_name} are unsealed.",
        evidence={"nodes": results}
    )


def check_replication(env_name: str, config: Dict[str, Any], env_vars: Dict[str, str]) -> CheckResult:
    command = config.get("replication_check_command")
    if not command:
        return CheckResult(
            name="Replication health",
            status="MANUAL",
            details=f"No replication command configured for {env_name}. Add your team-approved check from the runbook.",
            evidence={}
        )

    result = run_cmd(command, env=env_vars, check=False)
    status = "PASS" if result.returncode == 0 else "FAIL"

    return CheckResult(
        name="Replication health",
        status=status,
        details="Executed configured replication check command.",
        evidence={
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    )


def check_concourse(env_name: str, config: Dict[str, Any]) -> CheckResult:
    pipelines = config.get("maintenance_pipelines", [])
    if not pipelines:
        return CheckResult(
            name="Daily maintenance pipeline",
            status="MANUAL",
            details=f"No pipeline list configured for {env_name}.",
            evidence={}
        )

    chosen = random.choice(pipelines)
    return CheckResult(
        name="Daily maintenance pipeline",
        status="MANUAL",
        details=f"Randomly selected pipeline '{chosen}'. Trigger and confirm success through Concourse CLI/API.",
        evidence={"selected_pipeline": chosen}
    )


def summarize(results: List[CheckResult]) -> str:
    overall = "PASS"
    for result in results:
        if result.status == "FAIL":
            overall = "FAIL"
            break
        if result.status == "MANUAL" and overall != "FAIL":
            overall = "PARTIAL"

    lines = [f"Overall result: {overall}", ""]
    for result in results:
        lines.append(f"[{result.status}] {result.name}: {result.details}")
    return "\n".join(lines)


def render_html_report(environment: str, results: List[CheckResult], timestamp_utc: str) -> str:
    def color(status: str) -> str:
        return {
            "PASS": "#1f7a1f",
            "FAIL": "#b42318",
            "MANUAL": "#b26b00",
            "PARTIAL": "#7a5c00"
        }.get(status, "#444")

    overall = summarize(results).splitlines()[0].replace("Overall result: ", "")

    rows = []
    for result in results:
        evidence = escape(json.dumps(result.evidence, indent=2)) if result.evidence else "N/A"
        rows.append(f"""
        <tr>
          <td><strong>{escape(result.name)}</strong></td>
          <td style="color:{color(result.status)};font-weight:700;">{escape(result.status)}</td>
          <td>{escape(result.details)}</td>
          <td><pre>{evidence}</pre></td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vault AMI Validation Report - {escape(environment)}</title>
  <style>
    body {{
      font-family: Segoe UI, Arial, sans-serif;
      margin: 24px;
      background: #f4f7fb;
      color: #1f2937;
    }}
    .card {{
      max-width: 1200px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 12px 32px rgba(15, 23, 42, 0.10);
    }}
    h1 {{
      margin: 0 0 12px 0;
    }}
    .meta {{
      color: #475467;
      margin-bottom: 20px;
    }}
    .badge {{
      display: inline-block;
      padding: 8px 14px;
      border-radius: 999px;
      font-weight: 700;
      color: #ffffff;
      background: {color(overall)};
      margin-top: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }}
    th, td {{
      text-align: left;
      padding: 12px;
      border-bottom: 1px solid #e5e7eb;
      vertical-align: top;
    }}
    th {{
      background: #f8fafc;
    }}
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0;
      font-size: 12px;
      background: #f8fafc;
      padding: 10px;
      border-radius: 8px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Vault AMI Validation Report</h1>
    <div class="meta">
      <div><strong>Environment:</strong> {escape(environment)}</div>
      <div><strong>Timestamp (UTC):</strong> {escape(timestamp_utc)}</div>
      <div><span class="badge">{escape(overall)}</span></div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Check</th>
          <th>Status</th>
          <th>Details</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


def save_html_report(path: Path, html: str) -> None:
    path.write_text(html, encoding="utf-8")


def send_email_report(
    smtp_host: str,
    smtp_port: int,
    sender: str,
    recipients: List[str],
    subject: str,
    body: str,
    attachment_path: Path,
    use_tls: bool = True
) -> None:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)

    mime_type, _ = mimetypes.guess_type(str(attachment_path))
    if mime_type is None:
        mime_type = "application/octet-stream"
    maintype, subtype = mime_type.split("/", 1)

    with attachment_path.open("rb") as handle:
        msg.add_attachment(
            handle.read(),
            maintype=maintype,
            subtype=subtype,
            filename=attachment_path.name
        )

    with smtplib.SMTP(smtp_host, smtp_port) as smtp:
        if use_tls:
            smtp.starttls()
        smtp.send_message(msg)


def main() -> int:
    parser = argparse.ArgumentParser(description="Vault AMI validation runner")
    parser.add_argument("--env", required=True, help="Environment name, e.g. le1 / xe1 / pe1")
    parser.add_argument("--config", default="vault_validation_config.json", help="Path to config JSON")
    parser.add_argument("--vault-token", default=None, help="Optional Vault token; otherwise use VAULT_TOKEN")
    parser.add_argument("--output", default=None, help="Optional JSON output path")
    parser.add_argument("--email-to", nargs="*", default=[], help="Email recipients")
    parser.add_argument("--smtp-host", default=None, help="SMTP host")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP port")
    parser.add_argument("--email-from", default=None, help="Sender email address")
    parser.add_argument("--smtp-no-tls", action="store_true", help="Disable STARTTLS")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config file not found: {config_path}", file=sys.stderr)
        return 2

    with config_path.open("r", encoding="utf-8") as handle:
        full_config = json.load(handle)

    env_config = full_config["environments"].get(args.env)
    if not env_config:
        print(f"Environment '{args.env}' not found in config", file=sys.stderr)
        return 2

    vault_token = args.vault_token or env_config.get("vault_token")
    base_env = dict(subprocess.os.environ)
    results: List[CheckResult] = []

    try:
        primary_env = build_env(base_env, env_config["primary"]["vault_addr"], vault_token)
        dr_env = build_env(base_env, env_config["dr"]["vault_addr"], vault_token)

        effective_token = vault_token or base_env.get("VAULT_TOKEN")
        if not effective_token:
            raise ValidationError("No Vault token found. Use --vault-token or set VAULT_TOKEN after vault login.")

        results.append(check_vault_login(primary_env))
        results.append(check_secret_rw(primary_env, env_config.get("kv_test_path", "kvtest/test")))
        results.append(check_replication(args.env, env_config, primary_env))
        results.append(check_unsealed_nodes("primary", env_config["primary"]["nodes"], effective_token))
        results.append(check_unsealed_nodes("dr", env_config["dr"]["nodes"], effective_token))
        results.append(check_raft_peers(primary_env, "primary"))
        results.append(check_raft_peers(dr_env, "dr"))
        results.append(check_snapshot_status(primary_env))
        results.append(
            check_s3_snapshot(
                bucket=env_config["primary"]["snapshot_bucket"],
                prefix=env_config["primary"].get("snapshot_prefix", "raft-snapshots/"),
                aws_profile=env_config.get("aws_profile"),
                aws_region=env_config.get("aws_region")
            )
        )
        results.append(check_concourse(args.env, env_config))

    except ValidationError as exc:
        results.append(CheckResult(name="Execution", status="FAIL", details=str(exc)))

    summary = summarize(results)
    print(summary)

    timestamp_utc = datetime.now(timezone.utc).isoformat()
    report = {
        "environment": args.env,
        "timestamp_utc": timestamp_utc,
        "results": [result.__dict__ for result in results]
    }

    json_path = Path(args.output) if args.output else Path(f"vault_validation_report_{args.env}_{utc_now_str()}.json")
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    html_path = json_path.with_suffix(".html")
    html = render_html_report(args.env, results, timestamp_utc)
    save_html_report(html_path, html)

    print(f"\nJSON report saved to: {json_path}")
    print(f"HTML report saved to: {html_path}")

    if args.email_to:
        if not args.smtp_host or not args.email_from:
            print("Email requested but --smtp-host or --email-from missing", file=sys.stderr)
            return 2

        send_email_report(
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            sender=args.email_from,
            recipients=args.email_to,
            subject=f"Vault AMI Validation Report - {args.env}",
            body=f"Attached is the Vault AMI validation report for {args.env}.",
            attachment_path=html_path,
            use_tls=not args.smtp_no_tls
        )
        print(f"Email sent to: {', '.join(args.email_to)}")

    return 1 if any(result.status == "FAIL" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
