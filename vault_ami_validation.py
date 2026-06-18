#!/usr/bin/env python3
from __future__ import print_function

import json
import random
import subprocess
import sys
import time
from datetime import datetime
from html import escape
from pathlib import Path


class ValidationError(Exception):
    pass


class CheckResult(object):
    def __init__(self, name, status, details, category="General", evidence=None):
        self.name = name
        self.status = status
        self.details = details
        self.category = category
        self.evidence = evidence or {}

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "details": self.details,
            "category": self.category,
            "evidence": self.evidence,
        }


def utc_now():
    return datetime.utcnow()


def utc_now_str():
    return utc_now().strftime("%Y%m%d%H%M%S")


def prompt_input(prompt):
    while True:
        value = input(prompt + ": ").strip()
        if value:
            return value
        print("Value is required.")


def read_text_file(path):
    if not path.exists():
        raise ValidationError("Required file not found: {0}".format(path))
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValidationError("Required file is empty: {0}".format(path))
    return content


def read_token_file(path):
    return read_text_file(path)


def load_simple_env_file(path):
    if not path.exists():
        raise ValidationError("AWS credentials file not found: {0}".format(path))

    env_vars = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env_vars[key.strip()] = value.strip().strip('"').strip("'")

    if not env_vars:
        raise ValidationError("AWS credentials file has no usable KEY=VALUE entries: {0}".format(path))

    return env_vars


def build_env(base_env, vault_addr=None, vault_token=None, extra_env=None):
    merged = dict(base_env)
    if extra_env:
        merged.update(extra_env)
    if vault_addr:
        merged["VAULT_ADDR"] = vault_addr
    if vault_token:
        merged["VAULT_TOKEN"] = vault_token
    return merged


def run_cmd(cmd, env=None, check=True):
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=env,
        shell=False
    )
    if check and result.returncode != 0:
        raise ValidationError(
            "Command failed: {0}\nstdout:\n{1}\nstderr:\n{2}".format(
                " ".join(cmd),
                result.stdout,
                result.stderr
            )
        )
    return result


def run_json_cmd(cmd, env=None):
    result = run_cmd(cmd, env=env)
    raw = result.stdout.strip()
    try:
        return json.loads(raw)
    except ValueError:
        raise ValidationError(
            "Expected JSON output from: {0}\nOutput was:\n{1}".format(
                " ".join(cmd), raw
            )
        )


def run_json_cmd_with_retries(cmd, env=None, retries=4, delay_seconds=15):
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            return run_json_cmd(cmd, env=env)
        except ValidationError as exc:
            last_error = exc
            if attempt == retries:
                break
            time.sleep(delay_seconds)
    raise ValidationError(
        "Command failed after {0} attempts: {1}\nLast error: {2}".format(
            retries, " ".join(cmd), last_error
        )
    )


def overall_status(results):
    if any(result.status == "FAIL" for result in results):
        return "FAIL"
    if any(result.status == "MANUAL" for result in results):
        return "PARTIAL"
    return "PASS"


def safe_run_check(results, name, category, fn):
    try:
        results.append(fn())
    except ValidationError as exc:
        results.append(CheckResult(name, "FAIL", str(exc), category))
    except Exception as exc:
        results.append(CheckResult(name, "FAIL", "Unexpected error: {0}".format(exc), category))


def find_result(results, name):
    for result in results:
        if result.name == name:
            return result
    return None


def check_vault_login(env_vars, cluster_label):
    data = run_json_cmd(["vault", "token", "lookup", "-format=json"], env=env_vars)
    return CheckResult(
        "Vault login ({0})".format(cluster_label),
        "PASS",
        "Vault token is valid.",
        "Access",
        {
            "display_name": data.get("data", {}).get("display_name"),
            "policies": data.get("data", {}).get("policies", []),
            "ttl": data.get("data", {}).get("ttl"),
        }
    )


def check_secret_rw(env_vars, mount_path):
    key = "ami_validation_{0}".format(utc_now_str())
    value = "ok"

    run_cmd(["vault", "kv", "put", mount_path, "{0}={1}".format(key, value)], env=env_vars)
    secret_data = run_json_cmd(["vault", "kv", "get", "-format=json", mount_path], env=env_vars)
    actual = secret_data.get("data", {}).get("data", {}).get(key)

    if actual != value:
        raise ValidationError("Secret write/read mismatch. Expected {0}, got {1}".format(value, actual))

    return CheckResult(
        "Secret read/write",
        "PASS",
        "Temporary validation key was written and read successfully.",
        "Functional",
        {
            "path": mount_path,
            "key": key,
            "value": actual,
        }
    )


def check_ui_manual():
    return CheckResult(
        "Vault UI validation",
        "MANUAL",
        "Validate the approved secret path from Vault UI if this remains part of team policy.",
        "Functional"
    )


def check_vault_status(env_vars, cluster_name):
    data = run_json_cmd(["vault", "status", "-format=json"], env=env_vars)

    initialized = data.get("initialized")
    sealed = data.get("sealed")

    if initialized is not True:
        raise ValidationError("{0}: initialized is not true. Found: {1}".format(cluster_name, initialized))
    if sealed is not False:
        raise ValidationError("{0}: sealed is not false. Found: {1}".format(cluster_name, sealed))

    return CheckResult(
        "Vault status ({0})".format(cluster_name),
        "PASS",
        "{0} cluster is initialized and unsealed.".format(cluster_name),
        "Cluster Health",
        {
            "initialized": initialized,
            "sealed": sealed,
            "standby": data.get("standby"),
            "performance_standby": data.get("performance_standby"),
            "replication_dr_mode": data.get("replication_dr_mode"),
            "version": data.get("version"),
            "cluster_name": data.get("cluster_name"),
            "cluster_id": data.get("cluster_id"),
        }
    )


def check_raft_peers(env_vars, cluster_name, expected_total=5):
    data = run_json_cmd(["vault", "operator", "raft", "list-peers", "-format=json"], env=env_vars)
    peers = data.get("data", {}).get("config", {}).get("servers", [])
    total = len(peers)
    leaders = [peer for peer in peers if peer.get("leader") is True]
    followers = [peer for peer in peers if peer.get("leader") is not True]

    if total != expected_total:
        raise ValidationError("{0}: expected {1} raft peers, found {2}".format(cluster_name, expected_total, total))
    if len(leaders) != 1:
        raise ValidationError("{0}: expected 1 leader, found {1}".format(cluster_name, len(leaders)))
    if len(followers) != expected_total - 1:
        raise ValidationError("{0}: expected {1} followers, found {2}".format(cluster_name, expected_total - 1, len(followers)))

    return CheckResult(
        "Raft peers ({0})".format(cluster_name),
        "PASS",
        "{0} has {1} peers with 1 leader and {2} followers.".format(cluster_name, total, len(followers)),
        "Raft",
        {
            "peer_count": total,
            "leader_count": len(leaders),
            "follower_count": len(followers),
            "servers": peers,
        }
    )


def check_replication_primary(env_vars):
    data = run_json_cmd(["vault", "read", "-format=json", "sys/replication/dr/status"], env=env_vars)
    payload = data.get("data", {})
    state = payload.get("state")
    last_wal = payload.get("last_wal")
    last_dr_wal = payload.get("last_dr_wal")

    if str(state).lower() != "running":
        raise ValidationError("DR primary state is not running. Found: {0}".format(state))

    return CheckResult(
        "DR primary replication status",
        "PASS",
        "Primary DR state is '{0}' with last_wal={1}.".format(state, last_wal),
        "Replication",
        {
            "mode": payload.get("mode"),
            "state": state,
            "last_wal": last_wal,
            "last_dr_wal": last_dr_wal,
            "secondaries": payload.get("secondaries", []),
        }
    )


def check_replication_secondary(env_vars):
    data = run_json_cmd(["vault", "read", "-format=json", "sys/replication/dr/status"], env=env_vars)
    payload = data.get("data", {})
    state = payload.get("state")
    connection_state = payload.get("connection_state")
    last_remote_wal = payload.get("last_remote_wal")
    primaries = payload.get("primaries", [])
    connection_status = primaries[0].get("connection_status") if primaries else None

    if str(state).lower() != "stream-wals":
        raise ValidationError("DR secondary state is not stream-wals. Found: {0}".format(state))
    if str(connection_state).lower() not in ["ready", "connected"]:
        raise ValidationError("DR secondary connection_state is unexpected: {0}".format(connection_state))
    if connection_status and str(connection_status).lower() != "connected":
        raise ValidationError("DR secondary connection_status is unexpected: {0}".format(connection_status))

    return CheckResult(
        "DR secondary replication status",
        "PASS",
        "Secondary DR state is '{0}', connection_state='{1}', last_remote_wal={2}.".format(
            state, connection_state, last_remote_wal
        ),
        "Replication",
        {
            "mode": payload.get("mode"),
            "state": state,
            "connection_state": connection_state,
            "last_remote_wal": last_remote_wal,
            "connection_status": connection_status,
            "primaries": primaries,
        }
    )


def check_snapshot_status(env_vars, retries, delay_seconds):
    status_data = run_json_cmd_with_retries(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/status/s3"],
        env=env_vars,
        retries=retries,
        delay_seconds=delay_seconds
    )
    config_data = run_json_cmd_with_retries(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/config/s3"],
        env=env_vars,
        retries=retries,
        delay_seconds=delay_seconds
    )

    return CheckResult(
        "Snapshot auto status",
        "PASS",
        "Snapshot auto status and config were retrieved successfully.",
        "Snapshots",
        {
            "status": status_data.get("data", {}),
            "config": config_data.get("data", {}),
            "retry_attempts": retries,
            "retry_delay_seconds": delay_seconds,
        }
    )


def check_autopilot_config(env_vars, cluster_name):
    data = run_json_cmd(["vault", "operator", "raft", "autopilot", "get-config", "-format=json"], env=env_vars)
    payload = data.get("data", data)

    return CheckResult(
        "Autopilot config ({0})".format(cluster_name),
        "PASS",
        "Autopilot config retrieved for {0}.".format(cluster_name),
        "Raft",
        payload
    )


def check_s3_snapshot(bucket, prefix, aws_env, aws_profile, aws_region):
    cmd = ["aws"]
    if aws_profile:
        cmd.extend(["--profile", aws_profile])
    if aws_region:
        cmd.extend(["--region", aws_region])
    cmd.extend(["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix])

    data = run_json_cmd(cmd, env=aws_env)
    contents = data.get("Contents", [])
    if not contents:
        raise ValidationError("No snapshot objects found in s3://{0}/{1}".format(bucket, prefix))

    latest = max(contents, key=lambda obj: obj["LastModified"])
    return CheckResult(
        "Latest S3 snapshot",
        "PASS",
        "Latest snapshot is {0} at {1}.".format(latest["Key"], latest["LastModified"]),
        "Snapshots",
        {
            "bucket": bucket,
            "prefix": prefix,
            "latest_key": latest["Key"],
            "last_modified": latest["LastModified"],
            "object_count": len(contents),
        }
    )


def check_concourse(env_name, config):
    pipelines = config.get("maintenance_pipelines", [])
    if not pipelines:
        return CheckResult(
            "Daily maintenance pipeline",
            "MANUAL",
            "No maintenance pipeline list configured for {0}.".format(env_name),
            "Operations"
        )

    chosen = random.choice(pipelines)
    return CheckResult(
        "Daily maintenance pipeline",
        "MANUAL",
        "Randomly selected pipeline '{0}'. Trigger and validate manually or via Concourse CLI/API.".format(chosen),
        "Operations",
        {"selected_pipeline": chosen}
    )


def status_color(status):
    return {
        "PASS": "#157347",
        "FAIL": "#b42318",
        "MANUAL": "#b26b00",
        "PARTIAL": "#8a6d1d",
    }.get(status, "#475467")


def metric_card(label, value):
    shown = "N/A" if value is None or value == "" else str(value)
    return """
    <div class="metric-card">
      <div class="metric-label">{0}</div>
      <div class="metric-value">{1}</div>
    </div>
    """.format(escape(label), escape(shown))


def render_html_report(environment, results, metadata, timestamp_utc):
    overall = overall_status(results)

    primary_status = find_result(results, "Vault status (primary)")
    dr_status = find_result(results, "Vault status (dr)")
    primary_raft = find_result(results, "Raft peers (primary)")
    dr_raft = find_result(results, "Raft peers (dr)")
    dr_primary = find_result(results, "DR primary replication status")
    dr_secondary = find_result(results, "DR secondary replication status")
    snapshot = find_result(results, "Latest S3 snapshot")

    summary_metrics = [
        metric_card("Overall Status", overall),
        metric_card("Primary Initialized", primary_status.evidence.get("initialized") if primary_status else None),
        metric_card("Primary Sealed", primary_status.evidence.get("sealed") if primary_status else None),
        metric_card("DR Initialized", dr_status.evidence.get("initialized") if dr_status else None),
        metric_card("DR Sealed", dr_status.evidence.get("sealed") if dr_status else None),
        metric_card("Primary Raft Peers", primary_raft.evidence.get("peer_count") if primary_raft else None),
        metric_card("DR Raft Peers", dr_raft.evidence.get("peer_count") if dr_raft else None),
        metric_card("DR Primary State", dr_primary.evidence.get("state") if dr_primary else None),
        metric_card("Primary Last WAL", dr_primary.evidence.get("last_wal") if dr_primary else None),
        metric_card("DR Secondary State", dr_secondary.evidence.get("state") if dr_secondary else None),
        metric_card("Connection State", dr_secondary.evidence.get("connection_state") if dr_secondary else None),
        metric_card("Last Remote WAL", dr_secondary.evidence.get("last_remote_wal") if dr_secondary else None),
        metric_card("Latest Snapshot Time", snapshot.evidence.get("last_modified") if snapshot else None),
    ]

    input_cards = [
        ("Environment", metadata.get("environment")),
        ("Primary Vault Address", metadata.get("primary_vault_addr")),
        ("DR Vault Address", metadata.get("dr_vault_addr")),
        ("Snapshot Bucket", metadata.get("snapshot_bucket")),
        ("Snapshot Prefix", metadata.get("snapshot_prefix")),
        ("Snapshot Retry Attempts", metadata.get("snapshot_retries")),
        ("Snapshot Retry Delay", "{0} seconds".format(metadata.get("snapshot_retry_delay_seconds"))),
        ("Primary Token File", metadata.get("primary_token_file")),
        ("DR Token File", metadata.get("dr_token_file")),
        ("AWS Keys File", metadata.get("aws_credentials_file")),
    ]

    result_rows = []
    for result in results:
        evidence_json = "N/A"
        if result.evidence:
            evidence_json = json.dumps(result.evidence, indent=2)
        result_rows.append("""
        <tr>
          <td>{0}</td>
          <td><strong>{1}</strong></td>
          <td><span class="badge" style="background:{2};">{3}</span></td>
          <td>{4}</td>
          <td><pre>{5}</pre></td>
        </tr>
        """.format(
            escape(result.category),
            escape(result.name),
            status_color(result.status),
            escape(result.status),
            escape(result.details),
            escape(evidence_json)
        ))

    input_blocks = []
    for label, value in input_cards:
        shown = "N/A" if value is None else str(value)
        input_blocks.append("""
        <div class="input-card">
          <div class="input-label">{0}</div>
          <div class="input-value">{1}</div>
        </div>
        """.format(escape(str(label)), escape(shown)))

    primary_panel = """
    <div class="panel">
      <div class="panel-title">Primary Cluster</div>
      <div class="panel-item"><span>Status</span><strong>{0}</strong></div>
      <div class="panel-item"><span>Initialized</span><strong>{1}</strong></div>
      <div class="panel-item"><span>Sealed</span><strong>{2}</strong></div>
      <div class="panel-item"><span>Raft Peers</span><strong>{3}</strong></div>
      <div class="panel-item"><span>Last WAL</span><strong>{4}</strong></div>
    </div>
    """.format(
        escape(overall if primary_status else "N/A"),
        escape(str(primary_status.evidence.get("initialized")) if primary_status else "N/A"),
        escape(str(primary_status.evidence.get("sealed")) if primary_status else "N/A"),
        escape(str(primary_raft.evidence.get("peer_count")) if primary_raft else "N/A"),
        escape(str(dr_primary.evidence.get("last_wal")) if dr_primary else "N/A")
    )

    dr_panel = """
    <div class="panel">
      <div class="panel-title">DR Cluster</div>
      <div class="panel-item"><span>Status</span><strong>{0}</strong></div>
      <div class="panel-item"><span>Initialized</span><strong>{1}</strong></div>
      <div class="panel-item"><span>Sealed</span><strong>{2}</strong></div>
      <div class="panel-item"><span>Raft Peers</span><strong>{3}</strong></div>
      <div class="panel-item"><span>Last Remote WAL</span><strong>{4}</strong></div>
    </div>
    """.format(
        escape(overall if dr_status else "N/A"),
        escape(str(dr_status.evidence.get("initialized")) if dr_status else "N/A"),
        escape(str(dr_status.evidence.get("sealed")) if dr_status else "N/A"),
        escape(str(dr_raft.evidence.get("peer_count")) if dr_raft else "N/A"),
        escape(str(dr_secondary.evidence.get("last_remote_wal")) if dr_secondary else "N/A")
    )

    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vault AMI Validation Report - {0}</title>
  <style>
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background:
        radial-gradient(circle at top right, #d8f3ff 0%, transparent 30%),
        linear-gradient(180deg, #f7fbfd 0%, #eef4f8 100%);
      color: #0f172a;
    }}
    .wrap {{
      max-width: 1480px;
      margin: 0 auto;
      padding: 30px;
    }}
    .hero {{
      background: linear-gradient(135deg, #052b3b 0%, #0e7490 50%, #155e75 100%);
      color: #ffffff;
      border-radius: 28px;
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: 0 22px 60px rgba(8, 51, 68, 0.28);
      position: relative;
      overflow: hidden;
    }}
    .hero:before {{
      content: "";
      position: absolute;
      right: -60px;
      top: -60px;
      width: 220px;
      height: 220px;
      background: rgba(255,255,255,0.08);
      border-radius: 50%;
    }}
    .hero h1 {{
      margin: 0 0 10px 0;
      font-size: 36px;
      letter-spacing: 0.02em;
      position: relative;
      z-index: 1;
    }}
    .hero p {{
      margin: 6px 0;
      color: rgba(255,255,255,0.92);
      position: relative;
      z-index: 1;
    }}
    .overall {{
      display: inline-block;
      margin-top: 16px;
      padding: 12px 20px;
      border-radius: 999px;
      font-weight: 700;
      background: {1};
      color: white;
      position: relative;
      z-index: 1;
      box-shadow: 0 10px 24px rgba(0,0,0,0.18);
    }}
    .section {{
      background: rgba(255,255,255,0.96);
      border: 1px solid #dbe4ea;
      border-radius: 24px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
      backdrop-filter: blur(8px);
    }}
    .section h2 {{
      margin: 0 0 18px 0;
      font-size: 22px;
      color: #082f49;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }}
    .two-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
    }}
    .metric-card, .input-card, .panel {{
      background: linear-gradient(180deg, #ffffff 0%, #f9fcfd 100%);
      border: 1px solid #dbe4ea;
      border-radius: 18px;
      padding: 16px;
      box-shadow: 0 6px 18px rgba(15, 23, 42, 0.04);
    }}
    .metric-label, .input-label {{
      font-size: 11px;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 8px;
      letter-spacing: 0.08em;
    }}
    .metric-value {{
      font-size: 24px;
      font-weight: 800;
      color: #0f172a;
      word-break: break-word;
    }}
    .input-value {{
      font-size: 14px;
      font-weight: 600;
      color: #1e293b;
      word-break: break-word;
    }}
    .panel-title {{
      font-size: 18px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 14px;
    }}
    .panel-item {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 0;
      border-top: 1px solid #e2e8f0;
    }}
    .panel-item:first-of-type {{
      border-top: none;
      padding-top: 0;
    }}
    .panel-item span {{
      color: #64748b;
      font-size: 13px;
    }}
    .panel-item strong {{
      color: #0f172a;
      font-size: 14px;
      text-align: right;
      word-break: break-word;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
      overflow: hidden;
      border-radius: 16px;
    }}
    th, td {{
      text-align: left;
      padding: 14px 12px;
      border-bottom: 1px solid #e2e8f0;
      vertical-align: top;
    }}
    th {{
      background: #edf6f9;
      color: #0f172a;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    tr:nth-child(even) td {{
      background: #fbfdfe;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 12px;
      font-size: 12px;
      max-height: 320px;
      overflow: auto;
      color: #0f172a;
    }}
    .badge {{
      color: white;
      padding: 7px 12px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
      display: inline-block;
      white-space: nowrap;
    }}
    .footer {{
      text-align: center;
      color: #64748b;
      font-size: 12px;
      margin-top: 18px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Vault AMI Post-Upgrade Validation Report</h1>
      <p>Executive-ready validation summary for infrastructure leadership and engineering review.</p>
      <p>Environment: <strong>{0}</strong></p>
      <p>Generated: <strong>{2}</strong></p>
      <div class="overall">Overall Result: {3}</div>
    </section>

    <section class="section">
      <h2>Executive Summary</h2>
      <div class="grid">
        {4}
      </div>
    </section>

    <section class="section">
      <h2>Cluster Overview</h2>
      <div class="two-grid">
        {5}
        {6}
      </div>
    </section>

    <section class="section">
      <h2>Run Context</h2>
      <div class="grid">
        {7}
      </div>
    </section>

    <section class="section">
      <h2>Validation Results</h2>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {8}
        </tbody>
      </table>
    </section>

    <div class="footer">
      Generated automatically by the Vault AMI validation workflow.
    </div>
  </div>
</body>
</html>
""".format(
        escape(environment),
        status_color(overall),
        escape(timestamp_utc),
        escape(overall),
        "".join(summary_metrics),
        primary_panel,
        dr_panel,
        "".join(input_blocks),
        "".join(result_rows)
    )


def save_html_report(path, html):
    path.write_text(html, encoding="utf-8")


def build_report_metadata(environment, env_config, input_dir):
    return {
        "environment": environment,
        "primary_token_file": str(input_dir / "primary-token"),
        "dr_token_file": str(input_dir / "dr-token"),
        "aws_credentials_file": str(input_dir / "aws-keys"),
        "primary_vault_addr": env_config["primary"]["vault_addr"],
        "dr_vault_addr": env_config["dr"]["vault_addr"],
        "snapshot_bucket": env_config["primary"]["snapshot_bucket"],
        "snapshot_prefix": env_config["primary"].get("snapshot_prefix", "raft-snapshots/"),
        "snapshot_retries": env_config.get("snapshot_retry_attempts", 4),
        "snapshot_retry_delay_seconds": env_config.get("snapshot_retry_delay_seconds", 15),
    }


def main():
    print("\nVault AMI Post-Upgrade Validation\n")
    environment = prompt_input("Environment (le1 / xe1 / pe1)")

    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "vault_validation_config.json"
    input_dir = script_dir / "inputs" / environment
    report_dir = script_dir / "reports" / environment
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        if not config_path.exists():
            raise ValidationError("Config file not found: {0}".format(config_path))

        full_config = json.loads(config_path.read_text(encoding="utf-8"))
        env_config = full_config["environments"].get(environment)
        if not env_config:
            raise ValidationError("Environment '{0}' not found in config".format(environment))

        primary_token = read_token_file(input_dir / "primary-token")
        dr_token = read_token_file(input_dir / "dr-token")
        aws_file_env = load_simple_env_file(input_dir / "aws-keys")

    except ValidationError as exc:
        print("\nCritical setup failure: {0}".format(exc), file=sys.stderr)
        return 2

    results = []
    base_env = dict(subprocess.os.environ)

    primary_env = build_env(
        base_env,
        vault_addr=env_config["primary"]["vault_addr"],
        vault_token=primary_token,
        extra_env=aws_file_env
    )
    dr_env = build_env(
        base_env,
        vault_addr=env_config["dr"]["vault_addr"],
        vault_token=dr_token,
        extra_env=aws_file_env
    )
    aws_env = build_env(base_env, extra_env=aws_file_env)

    snapshot_retries = env_config.get("snapshot_retry_attempts", 4)
    snapshot_retry_delay_seconds = env_config.get("snapshot_retry_delay_seconds", 15)

    safe_run_check(results, "Vault login (primary)", "Access", lambda: check_vault_login(primary_env, "primary"))
    safe_run_check(results, "Vault login (dr)", "Access", lambda: check_vault_login(dr_env, "dr"))
    safe_run_check(results, "Secret read/write", "Functional", lambda: check_secret_rw(primary_env, env_config.get("kv_test_path", "kvtest/test")))
    safe_run_check(results, "Vault UI validation", "Functional", check_ui_manual)
    safe_run_check(results, "Vault status (primary)", "Cluster Health", lambda: check_vault_status(primary_env, "primary"))
    safe_run_check(results, "Vault status (dr)", "Cluster Health", lambda: check_vault_status(dr_env, "dr"))
    safe_run_check(results, "DR primary replication status", "Replication", lambda: check_replication_primary(primary_env))
    safe_run_check(results, "DR secondary replication status", "Replication", lambda: check_replication_secondary(dr_env))
    safe_run_check(results, "Raft peers (primary)", "Raft", lambda: check_raft_peers(primary_env, "primary"))
    safe_run_check(results, "Raft peers (dr)", "Raft", lambda: check_raft_peers(dr_env, "dr"))
    safe_run_check(results, "Autopilot config (primary)", "Raft", lambda: check_autopilot_config(primary_env, "primary"))
    safe_run_check(results, "Autopilot config (dr)", "Raft", lambda: check_autopilot_config(dr_env, "dr"))
    safe_run_check(
        results,
        "Snapshot auto status",
        "Snapshots",
        lambda: check_snapshot_status(primary_env, snapshot_retries, snapshot_retry_delay_seconds)
    )
    safe_run_check(
        results,
        "Latest S3 snapshot",
        "Snapshots",
        lambda: check_s3_snapshot(
            bucket=env_config["primary"]["snapshot_bucket"],
            prefix=env_config["primary"].get("snapshot_prefix", "raft-snapshots/"),
            aws_env=aws_env,
            aws_profile=env_config.get("aws_profile"),
            aws_region=env_config.get("aws_region")
        )
    )
    safe_run_check(results, "Daily maintenance pipeline", "Operations", lambda: check_concourse(environment, env_config))

    overall = overall_status(results)
    timestamp_utc = utc_now().isoformat() + "Z"
    metadata = build_report_metadata(environment, env_config, input_dir)

    report = {
        "environment": environment,
        "timestamp_utc": timestamp_utc,
        "overall_status": overall,
        "metadata": metadata,
        "results": [result.to_dict() for result in results],
    }

    base_name = "vault_validation_report_{0}_{1}".format(environment, utc_now_str())
    json_path = report_dir / (base_name + ".json")
    html_path = report_dir / (base_name + ".html")

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    save_html_report(html_path, render_html_report(environment, results, metadata, timestamp_utc))

    print("\nOverall result: {0}".format(overall))
    for result in results:
        print("[{0}] {1}: {2}".format(result.status, result.name, result.details))

    print("\nJSON report saved to: {0}".format(json_path))
    print("HTML report saved to: {0}".format(html_path))

    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
