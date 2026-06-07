#!/usr/bin/env python3
import json
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CheckResult:
    name: str
    status: str
    details: str
    category: str = "General"
    evidence: Dict[str, Any] = field(default_factory=dict)
    raw_output: Optional[str] = None


class ValidationError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_str() -> str:
    return utc_now().strftime("%Y%m%d%H%M%S")


def prompt_input(prompt: str) -> str:
    while True:
        value = input(f"{prompt}: ").strip()
        if value:
            return value
        print("Value is required.")


def read_text_file(path: Path) -> str:
    if not path.exists():
        raise ValidationError(f"Required file not found: {path}")
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValidationError(f"Required file is empty: {path}")
    return content


def read_token_file(path: Path) -> str:
    return read_text_file(path)


def load_simple_env_file(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise ValidationError(f"AWS credentials file not found: {path}")

    env_vars: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env_vars[key.strip()] = value.strip().strip('"').strip("'")

    if not env_vars:
        raise ValidationError(f"AWS credentials file has no usable KEY=VALUE entries: {path}")

    return env_vars


def build_env(
    base_env: Dict[str, str],
    vault_addr: Optional[str] = None,
    vault_token: Optional[str] = None,
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    merged = dict(base_env)
    if extra_env:
        merged.update(extra_env)
    if vault_addr:
        merged["VAULT_ADDR"] = vault_addr
    if vault_token:
        merged["VAULT_TOKEN"] = vault_token
    return merged


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


def run_json_cmd(cmd: List[str], env: Optional[Dict[str, str]] = None) -> Tuple[Any, str]:
    result = run_cmd(cmd, env=env)
    raw = result.stdout.strip()
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Expected JSON output from: {' '.join(cmd)}\nOutput was:\n{raw}"
        ) from exc


def run_json_cmd_with_retries(
    cmd: List[str],
    env: Optional[Dict[str, str]] = None,
    retries: int = 4,
    delay_seconds: int = 15
) -> Tuple[Any, str]:
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
        f"Command failed after {retries} attempts: {' '.join(cmd)}\nLast error: {last_error}"
    )


def json_to_pretty(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def overall_status(results: List[CheckResult]) -> str:
    if any(r.status == "FAIL" for r in results):
        return "FAIL"
    if any(r.status == "MANUAL" for r in results):
        return "PARTIAL"
    return "PASS"


def safe_run_check(results: List[CheckResult], name: str, category: str, fn):
    try:
        results.append(fn())
    except ValidationError as exc:
        results.append(CheckResult(name=name, status="FAIL", details=str(exc), category=category))
    except Exception as exc:
        results.append(CheckResult(name=name, status="FAIL", details=f"Unexpected error: {exc}", category=category))


def check_vault_login(env_vars: Dict[str, str], cluster_label: str) -> CheckResult:
    data, raw = run_json_cmd(["vault", "token", "lookup", "-format=json"], env=env_vars)
    return CheckResult(
        name=f"Vault login ({cluster_label})",
        status="PASS",
        details="Vault token is valid.",
        category="Access",
        evidence={
            "display_name": data.get("data", {}).get("display_name"),
            "policies": data.get("data", {}).get("policies", []),
        },
        raw_output=raw,
    )


def check_secret_rw(env_vars: Dict[str, str], mount_path: str) -> CheckResult:
    key = f"ami_validation_{utc_now_str()}"
    value = "ok"

    run_cmd(["vault", "kv", "put", mount_path, f"{key}={value}"], env=env_vars)
    secret_data, raw = run_json_cmd(["vault", "kv", "get", "-format=json", mount_path], env=env_vars)
    actual = secret_data.get("data", {}).get("data", {}).get(key)

    if actual != value:
        raise ValidationError(f"Secret write/read mismatch. Expected {value}, got {actual}")

    return CheckResult(
        name="Secret read/write",
        status="PASS",
        details=f"Successfully wrote and read temporary key '{key}' in {mount_path}.",
        category="Functional",
        evidence={"path": mount_path, "key": key, "value": actual},
        raw_output=raw,
    )


def check_ui_manual() -> CheckResult:
    return CheckResult(
        name="Vault UI validation",
        status="MANUAL",
        details="Validate secret read/write from Vault UI if still required by team policy.",
        category="Functional",
    )


def check_vault_status(env_vars: Dict[str, str], cluster_name: str) -> CheckResult:
    data, raw = run_json_cmd(["vault", "status", "-format=json"], env=env_vars)

    initialized = data.get("initialized")
    sealed = data.get("sealed")

    if initialized is not True:
        raise ValidationError(f"{cluster_name}: initialized is not true. Found: {initialized}")
    if sealed is not False:
        raise ValidationError(f"{cluster_name}: sealed is not false. Found: {sealed}")

    return CheckResult(
        name=f"Vault status ({cluster_name})",
        status="PASS",
        details=f"{cluster_name} cluster is initialized and unsealed.",
        category="Cluster Health",
        evidence={
            "initialized": initialized,
            "sealed": sealed,
            "standby": data.get("standby"),
            "performance_standby": data.get("performance_standby"),
            "replication_dr_mode": data.get("replication_dr_mode"),
            "server_time_utc": data.get("server_time_utc"),
            "version": data.get("version"),
            "cluster_name": data.get("cluster_name"),
            "cluster_id": data.get("cluster_id"),
        },
        raw_output=raw,
    )


def check_raft_peers(env_vars: Dict[str, str], cluster_name: str, expected_total: int = 5) -> CheckResult:
    data, raw = run_json_cmd(["vault", "operator", "raft", "list-peers", "-format=json"], env=env_vars)
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
        details=f"{cluster_name} has {total} peers with 1 leader and {len(followers)} followers.",
        category="Raft",
        evidence={
            "peer_count": total,
            "leader_count": len(leaders),
            "follower_count": len(followers),
            "servers": peers,
        },
        raw_output=raw,
    )


def check_replication_primary(env_vars: Dict[str, str]) -> CheckResult:
    data, raw = run_json_cmd(["vault", "read", "-format=json", "sys/replication/dr/status"], env=env_vars)
    payload = data.get("data", {})
    state = payload.get("state")
    last_wal = payload.get("last_wal")
    last_dr_wal = payload.get("last_dr_wal")

    if str(state).lower() != "running":
        raise ValidationError(f"DR primary state is not running. Found: {state}")

    return CheckResult(
        name="DR primary replication status",
        status="PASS",
        details=f"Primary DR state is '{state}' with last_wal={last_wal}.",
        category="Replication",
        evidence={
            "mode": payload.get("mode"),
            "state": state,
            "last_wal": last_wal,
            "last_dr_wal": last_dr_wal,
            "secondaries": payload.get("secondaries", []),
        },
        raw_output=raw,
    )


def check_replication_secondary(env_vars: Dict[str, str]) -> CheckResult:
    data, raw = run_json_cmd(["vault", "read", "-format=json", "sys/replication/dr/status"], env=env_vars)
    payload = data.get("data", {})
    state = payload.get("state")
    connection_state = payload.get("connection_state")
    last_remote_wal = payload.get("last_remote_wal")
    primaries = payload.get("primaries", [])
    connection_status = primaries[0].get("connection_status") if primaries else None

    if str(state).lower() != "stream-wals":
        raise ValidationError(f"DR secondary state is not stream-wals. Found: {state}")
    if str(connection_state).lower() not in {"ready", "connected"}:
        raise ValidationError(f"DR secondary connection_state is unexpected: {connection_state}")
    if connection_status and str(connection_status).lower() != "connected":
        raise ValidationError(f"DR secondary connection_status is unexpected: {connection_status}")

    return CheckResult(
        name="DR secondary replication status",
        status="PASS",
        details=f"Secondary DR state is '{state}', connection_state='{connection_state}', last_remote_wal={last_remote_wal}.",
        category="Replication",
        evidence={
            "mode": payload.get("mode"),
            "state": state,
            "connection_state": connection_state,
            "last_remote_wal": last_remote_wal,
            "connection_status": connection_status,
            "primaries": primaries,
        },
        raw_output=raw,
    )


def check_snapshot_status(env_vars: Dict[str, str], retries: int, delay_seconds: int) -> CheckResult:
    status_data, raw_status = run_json_cmd_with_retries(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/status/s3"],
        env=env_vars,
        retries=retries,
        delay_seconds=delay_seconds,
    )
    config_data, raw_config = run_json_cmd_with_retries(
        ["vault", "read", "-format=json", "sys/storage/raft/snapshot-auto/config/s3"],
        env=env_vars,
        retries=retries,
        delay_seconds=delay_seconds,
    )

    return CheckResult(
        name="Snapshot auto status",
        status="PASS",
        details=f"Retrieved raft snapshot auto status and config after retry-aware execution.",
        category="Snapshots",
        evidence={
            "status": status_data.get("data", {}),
            "config": config_data.get("data", {}),
            "retries_configured": retries,
            "retry_delay_seconds": delay_seconds,
        },
        raw_output=f"STATUS\n{raw_status}\n\nCONFIG\n{raw_config}",
    )


def check_autopilot_config(env_vars: Dict[str, str], cluster_name: str) -> CheckResult:
    data, raw = run_json_cmd(["vault", "operator", "raft", "autopilot", "get-config", "-format=json"], env=env_vars)
    payload = data.get("data", data)

    return CheckResult(
        name=f"Autopilot config ({cluster_name})",
        status="PASS",
        details=f"Retrieved autopilot config for {cluster_name}.",
        category="Raft",
        evidence=payload,
        raw_output=raw,
    )


def check_s3_snapshot(
    bucket: str,
    prefix: str,
    aws_env: Dict[str, str],
    aws_profile: Optional[str],
    aws_region: Optional[str]
) -> CheckResult:
    cmd = ["aws"]
    if aws_profile:
        cmd.extend(["--profile", aws_profile])
    if aws_region:
        cmd.extend(["--region", aws_region])
    cmd.extend(["s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix])

    data, raw = run_json_cmd(cmd, env=aws_env)
    contents = data.get("Contents", [])
    if not contents:
        raise ValidationError(f"No snapshot objects found in s3://{bucket}/{prefix}")

    latest = max(contents, key=lambda obj: obj["LastModified"])
    return CheckResult(
        name="Latest S3 snapshot",
        status="PASS",
        details=f"Latest snapshot is {latest['Key']} at {latest['LastModified']}.",
        category="Snapshots",
        evidence={
            "bucket": bucket,
            "prefix": prefix,
            "latest_key": latest["Key"],
            "last_modified": latest["LastModified"],
            "object_count": len(contents),
        },
        raw_output=raw,
    )


def check_concourse(env_name: str, config: Dict[str, Any]) -> CheckResult:
    pipelines = config.get("maintenance_pipelines", [])
    if not pipelines:
        return CheckResult(
            name="Daily maintenance pipeline",
            status="MANUAL",
            details=f"No pipeline list configured for {env_name}.",
            category="Operations",
        )

    chosen = random.choice(pipelines)
    return CheckResult(
        name="Daily maintenance pipeline",
        status="MANUAL",
        details=f"Randomly selected pipeline '{chosen}'. Trigger and confirm success through Concourse CLI/API.",
        category="Operations",
        evidence={"selected_pipeline": chosen},
    )


def status_color(status: str) -> str:
    return {
        "PASS": "#157347",
        "FAIL": "#b42318",
        "MANUAL": "#b26b00",
        "PARTIAL": "#8a6d1d",
    }.get(status, "#475467")


def metric_card(label: str, value: str) -> str:
    return f"""
    <div class="metric-card">
      <div class="metric-label">{escape(label)}</div>
      <div class="metric-value">{escape(value)}</div>
    </div>
    """


def render_html_report(environment: str, results: List[CheckResult], metadata: Dict[str, Any], timestamp_utc: str) -> str:
    overall = overall_status(results)
    primary_replication = next((r for r in results if r.name == "DR primary replication status"), None)
    secondary_replication = next((r for r in results if r.name == "DR secondary replication status"), None)
    primary_raft = next((r for r in results if r.name == "Raft peers (primary)"), None)
    dr_raft = next((r for r in results if r.name == "Raft peers (dr)"), None)
    primary_status = next((r for r in results if r.name == "Vault status (primary)"), None)
    dr_status = next((r for r in results if r.name == "Vault status (dr)"), None)
    s3_snap = next((r for r in results if r.name == "Latest S3 snapshot"), None)

    summary_metrics = []
    if primary_status:
        summary_metrics.append(metric_card("Primary Sealed", str(primary_status.evidence.get("sealed", "N/A"))))
    if dr_status:
        summary_metrics.append(metric_card("DR Sealed", str(dr_status.evidence.get("sealed", "N/A"))))
    if primary_raft:
        summary_metrics.append(metric_card("Primary Raft Peers", str(primary_raft.evidence.get("peer_count", "N/A"))))
    if dr_raft:
        summary_metrics.append(metric_card("DR Raft Peers", str(dr_raft.evidence.get("peer_count", "N/A"))))
    if primary_replication:
        summary_metrics.append(metric_card("DR Primary State", str(primary_replication.evidence.get("state", "N/A"))))
        summary_metrics.append(metric_card("Primary Last WAL", str(primary_replication.evidence.get("last_wal", "N/A"))))
    if secondary_replication:
        summary_metrics.append(metric_card("DR Secondary State", str(secondary_replication.evidence.get("state", "N/A"))))
        summary_metrics.append(metric_card("Connection State", str(secondary_replication.evidence.get("connection_state", "N/A"))))
        summary_metrics.append(metric_card("Last Remote WAL", str(secondary_replication.evidence.get("last_remote_wal", "N/A"))))
    if s3_snap:
        summary_metrics.append(metric_card("Latest Snapshot Time", str(s3_snap.evidence.get("last_modified", "N/A"))))

    table_rows = []
    for result in results:
        evidence = "N/A" if not result.evidence else escape(json.dumps(result.evidence, indent=2))
        raw_output = escape(result.raw_output) if result.raw_output else "N/A"
        table_rows.append(f"""
        <tr>
          <td>{escape(result.category)}</td>
          <td><strong>{escape(result.name)}</strong></td>
          <td><span class="badge" style="background:{status_color(result.status)};">{escape(result.status)}</span></td>
          <td>{escape(result.details)}</td>
          <td><pre>{evidence}</pre></td>
          <td><details><summary>View</summary><pre>{raw_output}</pre></details></td>
        </tr>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vault AMI Validation Report - {escape(environment)}</title>
  <style>
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: linear-gradient(180deg, #f7fbfd 0%, #eef4f8 100%);
      color: #0f172a;
    }}
    .wrap {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 28px;
    }}
    .hero {{
      background: linear-gradient(135deg, #083344 0%, #0f766e 55%, #155e75 100%);
      color: white;
      border-radius: 24px;
      padding: 28px;
      margin-bottom: 24px;
    }}
    .overall {{
      display: inline-block;
      margin-top: 14px;
      padding: 10px 18px;
      border-radius: 999px;
      font-weight: 700;
      background: """ + status_color(overall) + """;
      color: white;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin: 18px 0 26px 0;
    }}
    .metric-card {{
      background: white;
      border: 1px solid #dbe4ea;
      border-radius: 18px;
      padding: 16px;
    }}
    .metric-label {{
      font-size: 12px;
      text-transform: uppercase;
      color: #475467;
      margin-bottom: 8px;
    }}
    .metric-value {{
      font-size: 24px;
      font-weight: 700;
    }}
    .section {{
      background: white;
      border: 1px solid #dbe4ea;
      border-radius: 22px;
      padding: 22px;
      margin-bottom: 20px;
    }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 12px;
    }}
    .meta div {{
      background: #f8fbfc;
      border: 1px solid #dbe4ea;
      border-radius: 14px;
      padding: 12px 14px;
    }}
    .meta strong {{
      display: block;
      color: #475467;
      font-size: 12px;
      text-transform: uppercase;
      margin-bottom: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 12px;
      border-bottom: 1px solid #dbe4ea;
      vertical-align: top;
    }}
    th {{
      background: #f5f9fb;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 12px;
      font-size: 12px;
      max-height: 280px;
      overflow: auto;
    }}
    .badge {{
      color: white;
      padding: 6px 10px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 12px;
      display: inline-block;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Vault AMI Post-Upgrade Validation Report</h1>
      <p>Environment: <strong>{escape(environment)}</strong> | Generated: <strong>{escape(timestamp_utc)}</strong></p>
      <div class="overall">Overall Result: {escape(overall)}</div>
    </section>

    <section class="section">
      <h2>Executive Summary</h2>
      <div class="grid">
        {''.join(summary_metrics)}
      </div>
    </section>

    <section class="section">
      <h2>Run Inputs</h2>
      <div class="meta">
        <div><strong>Environment</strong>{escape(environment)}</div>
        <div><strong>Primary Token File</strong>{escape(str(metadata.get('primary_token_file', '')))}</div>
        <div><strong>DR Token File</strong>{escape(str(metadata.get('dr_token_file', '')))}</div>
        <div><strong>AWS Keys File</strong>{escape(str(metadata.get('aws_credentials_file', '')))}</div>
        <div><strong>Primary Vault Address</strong>{escape(str(metadata.get('primary_vault_addr', '')))}</div>
        <div><strong>DR Vault Address</strong>{escape(str(metadata.get('dr_vault_addr', '')))}</div>
        <div><strong>Snapshot Bucket</strong>{escape(str(metadata.get('snapshot_bucket', '')))}</div>
        <div><strong>Snapshot Prefix</strong>{escape(str(metadata.get('snapshot_prefix', '')))}</div>
      </div>
    </section>

    <section class="section">
      <h2>Detailed Validation Results</h2>
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
            <th>Evidence</th>
            <th>Full Output</th>
          </tr>
        </thead>
        <tbody>
          {''.join(table_rows)}
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>
"""


def save_html_report(path: Path, html: str) -> None:
    path.write_text(html, encoding="utf-8")


def build_report_metadata(environment: str, env_config: Dict[str, Any], input_dir: Path) -> Dict[str, Any]:
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


def main() -> int:
    print("\nVault AMI Post-Upgrade Validation\n")
    environment = prompt_input("Environment (le1 / xe1 / pe1)")

    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "vault_validation_config.json"
    input_dir = script_dir / "inputs" / environment
    report_dir = script_dir / "reports" / environment
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        if not config_path.exists():
            raise ValidationError(f"Config file not found: {config_path}")

        full_config = json.loads(config_path.read_text(encoding="utf-8"))
        env_config = full_config["environments"].get(environment)
        if not env_config:
            raise ValidationError(f"Environment '{environment}' not found in config")

        primary_token = read_token_file(input_dir / "primary-token")
        dr_token = read_token_file(input_dir / "dr-token")
        aws_file_env = load_simple_env_file(input_dir / "aws-keys")

    except ValidationError as exc:
        print(f"\nCritical setup failure: {exc}", file=sys.stderr)
        return 2

    results: List[CheckResult] = []
    base_env = dict(subprocess.os.environ)

    primary_env = build_env(
        base_env,
        vault_addr=env_config["primary"]["vault_addr"],
        vault_token=primary_token,
        extra_env=aws_file_env,
    )
    dr_env = build_env(
        base_env,
        vault_addr=env_config["dr"]["vault_addr"],
        vault_token=dr_token,
        extra_env=aws_file_env,
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
        lambda: check_snapshot_status(primary_env, snapshot_retries, snapshot_retry_delay_seconds),
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
            aws_region=env_config.get("aws_region"),
        ),
    )
    safe_run_check(results, "Daily maintenance pipeline", "Operations", lambda: check_concourse(environment, env_config))

    overall = overall_status(results)
    timestamp_utc = utc_now().isoformat()
    metadata = build_report_metadata(environment, env_config, input_dir)

    report = {
        "environment": environment,
        "timestamp_utc": timestamp_utc,
        "overall_status": overall,
        "metadata": metadata,
        "results": [asdict(result) for result in results],
    }

    base_name = f"vault_validation_report_{environment}_{utc_now_str()}"
    json_path = report_dir / f"{base_name}.json"
    html_path = report_dir / f"{base_name}.html"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    save_html_report(html_path, render_html_report(environment, results, metadata, timestamp_utc))

    print(f"\nOverall result: {overall}")
    for result in results:
        print(f"[{result.status}] {result.name}: {result.details}")

    print(f"\nJSON report saved to: {json_path}")
    print(f"HTML report saved to: {html_path}")

    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
