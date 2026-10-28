#!/usr/bin/env python
# vault_ami_validation.py
# Python 3.5 compatible. Run from the approved Dojo environment.
#
# Safety:
# - All checks are read-only except one uniquely named validation secret.
# - No delete, seal, unseal, revoke, or configuration-changing command is run.
# - Tokens are entered interactively and are never written to reports.

from __future__ import print_function

import datetime
import getpass
import html
import json
import os
import re
import subprocess
import sys
import time


CONFIG_FILE = "vault_validation_config.json"
DEFAULT_TIMEOUT = 60
EST_OFFSET = datetime.timedelta(hours=-5)


class ValidationError(Exception):
    pass


class CommandError(Exception):
    def __init__(self, command, message):
        Exception.__init__(self, message)
        self.command = command
        self.message = message


class Result(object):
    def __init__(
            self,
            area,
            title,
            command,
            condition,
            outcome,
            evidence,
            count_only,
            summary,
            error):
        self.area = area
        self.title = title
        self.command = command
        self.condition = condition
        self.outcome = outcome
        self.evidence = evidence
        self.count_only = count_only
        self.summary = summary
        self.error = error


def est_now():
    return datetime.datetime.utcnow() + EST_OFFSET


def est_timestamp():
    return est_now().strftime("%Y-%m-%d %H:%M:%S EST")


def normalize_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def as_bool(value):
    if isinstance(value, bool):
        return value

    if value is None:
        return None

    value = str(value).strip().lower()

    if value in ["true", "yes", "1", "enabled", "running", "connected"]:
        return True

    if value in ["false", "no", "0", "disabled", "sealed", "disconnected"]:
        return False

    return None


def config_bool(value, default=False):
    if value is None:
        return default

    converted = as_bool(value)

    if converted is None:
        return default

    return converted


def expect(condition, message):
    if not condition:
        raise ValidationError(message)


def safe_command(command):
    safe_items = []

    for item in command:
        value = str(item)

        if value.startswith("-dr-token="):
            safe_items.append("-dr-token=REDACTED")
        elif "token=" in value.lower():
            safe_items.append("REDACTED")
        else:
            safe_items.append(value)

    return " ".join(safe_items)


def redact(value):
    sensitive_names = [
        "token",
        "secret",
        "password",
        "privatekey",
        "clientsecret",
        "accesskey",
        "credentials"
    ]

    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            if any(
                    name in normalize_key(key)
                    for name in sensitive_names):
                cleaned[key] = "REDACTED"
            else:
                cleaned[key] = redact(item)

        return cleaned

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


def parse_json(output):
    output = (output or "").strip()

    if not output:
        raise ValidationError("Vault returned no JSON output.")

    try:
        return json.loads(output)
    except ValueError:
        pass

    starts = [
        position for position in [
            output.find("{"),
            output.find("[")
        ]
        if position >= 0
    ]

    if not starts:
        raise ValidationError(
            "Vault did not return valid JSON: {0}".format(output[:500])
        )

    try:
        return json.loads(output[min(starts):])
    except ValueError:
        raise ValidationError(
            "Vault returned invalid JSON: {0}".format(output[:500])
        )


def extract_data(payload):
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        return payload["data"]

    return payload


def find_first(value, names):
    target_names = [normalize_key(name) for name in names]

    if isinstance(value, dict):
        for key, item in value.items():
            if normalize_key(key) in target_names:
                return item

        for item in value.values():
            found = find_first(item, names)

            if found is not None:
                return found

    if isinstance(value, list):
        for item in value:
            found = find_first(item, names)

            if found is not None:
                return found

    return None


def parse_seconds(value):
    if value is None:
        return None

    try:
        return int(float(value))
    except (ValueError, TypeError):
        pass

    total = 0
    matches = re.findall(
        r"([0-9]+)\s*([hms])",
        str(value).lower()
    )

    for number, unit in matches:
        number = int(number)

        if unit == "h":
            total += number * 3600
        elif unit == "m":
            total += number * 60
        elif unit == "s":
            total += number

    return total if total > 0 else None


def count_entries(payload):
    data = extract_data(payload)

    if isinstance(data, list):
        return len(data)

    if isinstance(data, dict):
        if isinstance(data.get("keys"), list):
            return len(data["keys"])

        return len(data)

    return 0


def raft_servers(payload):
    data = extract_data(payload)

    if isinstance(data, dict):
        if isinstance(data.get("servers"), list):
            return data["servers"]

        config = data.get("config", {})

        if isinstance(config, dict) and isinstance(
                config.get("servers"), list):
            return config["servers"]

    return []


def member_list(payload):
    data = extract_data(payload)

    if isinstance(data, dict):
        for key in ["members", "servers"]:
            if isinstance(data.get(key), list):
                return data[key]

    return []


def snapshot_backend(context):
    provider = context["profile"].get("provider", "aws").lower().strip()

    if provider == "gcp":
        return "gcs"

    return "s3"


def evidence(data, count_only=False, summary=None):
    return {
        "data": redact(data),
        "count_only": count_only,
        "summary": summary or {}
    }


class VaultRunner(object):
    def __init__(self, timeout):
        self.timeout = timeout

    def run(self, command, environment):
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            universal_newlines=True
        )

        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

            raise CommandError(
                safe_command(command),
                "Command timed out after {0} seconds.".format(self.timeout)
            )

        if process.returncode != 0:
            message = (stderr or stdout or "Unknown Vault command error.")
            raise CommandError(
                safe_command(command),
                message.strip()[:2000]
            )

        return (stdout or "").strip()

    def json(self, command, environment, retries=1, retry_delay=10):
        last_error = None

        for attempt in range(1, retries + 1):
            try:
                return parse_json(self.run(command, environment))
            except (CommandError, ValidationError) as error:
                last_error = error

                if attempt < retries:
                    time.sleep(retry_delay)

        raise last_error

    def json_fallback(self, commands, environment):
        errors = []

        for command in commands:
            try:
                return self.json(command, environment), safe_command(command)
            except (CommandError, ValidationError) as error:
                errors.append(str(error))

        raise ValidationError(
            "All supported commands failed: {0}".format(
                " | ".join(errors)
            )
        )


def vault_environment(address, token, namespace):
    environment = os.environ.copy()
    environment["VAULT_ADDR"] = address
    environment["VAULT_TOKEN"] = token
    environment["VAULT_FORMAT"] = "json"

    if namespace:
        environment["VAULT_NAMESPACE"] = namespace

    return environment


def check_status(runner, context, target):
    payload = runner.json(
        ["vault", "status", "-format=json"],
        context[target + "_env"]
    )

    initialized = find_first(payload, ["initialized"])
    sealed = find_first(payload, ["sealed"])
    recovery_shares = find_first(
        payload,
        ["recovery_shares", "total_recovery_shares"]
    )
    threshold = find_first(
        payload,
        ["recovery_threshold", "threshold"]
    )

    expect(
        as_bool(initialized) is True,
        "Vault must report Initialized=true."
    )
    expect(
        as_bool(sealed) is False,
        "Vault must report Sealed=false."
    )

    return evidence(payload, summary={
        "initialized": initialized,
        "sealed": sealed,
        "recovery_shares": recovery_shares,
        "threshold": threshold,
        "version": find_first(payload, ["version"]),
        "cluster_name": find_first(payload, ["cluster_name"])
    })


def check_raft_peers(runner, context, target):
    command = [
        "vault", "operator", "raft",
        "list-peers", "-format=json"
    ]

    if target == "dr":
        command.append("-dr-token={0}".format(context["dr_token"]))

    payload = runner.json(command, context[target + "_env"])
    servers = raft_servers(payload)

    expected_peers = int(
        context["profile"].get("raft_expected_peers", 5)
    )

    leaders = [
        server for server in servers
        if as_bool(server.get("leader")) is True
    ]

    followers = [
        server for server in servers
        if as_bool(server.get("leader")) is not True
    ]

    expect(
        len(servers) == expected_peers,
        "Expected {0} Raft peers; found {1}.".format(
            expected_peers,
            len(servers)
        )
    )
    expect(
        len(leaders) == 1,
        "Expected one leader; found {0}.".format(len(leaders))
    )
    expect(
        len(followers) == expected_peers - 1,
        "Expected {0} followers; found {1}.".format(
            expected_peers - 1,
            len(followers)
        )
    )

    return evidence(payload, summary={
        "peer_count": len(servers),
        "leader_count": len(leaders),
        "follower_count": len(followers)
    })


def check_primary_dr_replication(runner, context):
    payload = runner.json(
        [
            "vault", "read", "-format=json",
            "sys/replication/dr/status"
        ],
        context["primary_env"]
    )

    data = extract_data(payload)
    state = find_first(data, ["state", "status"])
    mode = find_first(data, ["mode"])
    last_wal = find_first(
        data,
        ["last_wal", "last_wal_entry", "last_local_wal"]
    )

    state_text = str(state).lower() if state is not None else ""
    mode_text = str(mode).lower() if mode is not None else ""

    expect(
        state_text in ["running", "primary"] or mode_text == "primary",
        "DR primary must report Running or Primary state."
    )
    expect(
        last_wal is not None,
        "DR primary last WAL entry was not found."
    )

    return evidence(payload, summary={
        "state": state,
        "mode": mode,
        "last_wal_entry": last_wal
    })


def check_dr_secondary_replication(runner, context):
    payload = runner.json(
        [
            "vault", "read", "-format=json",
            "sys/replication/dr/status"
        ],
        context["dr_env"]
    )

    data = extract_data(payload)
    state = find_first(data, ["state", "status"])
    mode = find_first(data, ["mode"])
    stream_wals = find_first(data, ["stream_wals"])
    connection = find_first(data, ["connection_state"])
    remote_wal = find_first(
        data,
        ["last_remote_wal", "last_remote_entry", "last_wal"]
    )

    mode_text = str(mode).lower() if mode is not None else ""
    state_text = str(state).lower() if state is not None else ""
    connection_text = (
        str(connection).lower()
        if connection is not None else ""
    )

    expect(
        mode_text == "secondary" or state_text == "secondary",
        "DR vault must report Secondary state."
    )
    expect(
        as_bool(stream_wals) is True,
        "DR stream_wals must be true."
    )
    expect(
        connection_text in ["connected", "running", "streaming"],
        "DR connection state must be connected."
    )
    expect(
        remote_wal is not None,
        "DR last remote WAL entry was not found."
    )

    return evidence(payload, summary={
        "state": state,
        "mode": mode,
        "stream_wals": stream_wals,
        "connection_state": connection,
        "last_remote_wal_entry": remote_wal
    })


def check_autopilot(runner, context, target):
    payload = runner.json(
        [
            "vault", "operator", "raft",
            "autopilot", "get-config", "-format=json"
        ],
        context[target + "_env"]
    )

    expect(bool(payload), "Autopilot configuration was empty.")
    return evidence(payload)


def check_license_get(runner, context, target):
    payload, command_used = runner.json_fallback(
        [
            ["vault", "license", "get", "-format=json"],
            ["vault", "read", "-format=json", "sys/license/status"]
        ],
        context[target + "_env"]
    )

    return evidence({
        "command_used": command_used,
        "license": payload
    })


def check_license_status(runner, context, target):
    payload, command_used = runner.json_fallback(
        [
            ["vault", "license", "status", "-format=json"],
            ["vault", "read", "-format=json", "sys/license/status"],
            ["vault", "license", "get", "-format=json"]
        ],
        context[target + "_env"]
    )

    return evidence({
        "command_used": command_used,
        "license_status": payload
    }, summary={
        "expiration_time": find_first(
            payload,
            ["expiration_time", "termination_time"]
        )
    })


def check_members(runner, context, target):
    payload = runner.json(
        ["vault", "operator", "members", "-format=json"],
        context[target + "_env"]
    )

    members = member_list(payload)

    expect(
        len(members) > 0,
        "Operator members output was retrieved but no member list was found."
    )

    return evidence(payload, summary={
        "member_count": len(members)
    })


def check_snapshot_config(runner, context):
    backend = snapshot_backend(context)
    path = (
        "sys/storage/raft/snapshot-auto/config/{0}"
    ).format(backend)

    payload = runner.json(
        ["vault", "read", "-format=json", path],
        context["primary_env"],
        retries=3,
        retry_delay=15
    )

    interval = find_first(
        extract_data(payload),
        ["interval", "snapshot_interval"]
    )

    expected = int(
        context["profile"].get("snapshot_interval_seconds", 1800)
    )

    reported = parse_seconds(interval)

    expect(interval is not None, "Snapshot interval was not found.")
    expect(
        reported == expected,
        "Expected interval {0}; found {1}.".format(
            expected,
            interval
        )
    )

    return evidence(payload, summary={
        "snapshot_backend": backend,
        "snapshot_path": path,
        "expected_interval_seconds": expected,
        "reported_interval_seconds": reported
    })


def check_secret_write(runner, context):
    output = runner.run(
        [
            "vault", "kv", "put", "-format=json",
            context["test_path"], "Test=success"
        ],
        context["primary_env"]
    )

    response = {
        "validation_path": context["test_path"],
        "message": "Validation secret write completed."
    }

    if output:
        try:
            response["vault_response"] = parse_json(output)
        except ValidationError:
            response["vault_response"] = output[:1000]

    return evidence(response, summary={
        "validation_path": context["test_path"]
    })


def check_secret_read(runner, context):
    payload = runner.json(
        [
            "vault", "kv", "get", "-format=json",
            context["test_path"]
        ],
        context["primary_env"]
    )

    value = find_first(payload, ["test"])

    expect(
        str(value).strip().lower() == "success",
        "Expected Test=success; found {0}.".format(value)
    )

    return evidence(payload, summary={
        "validation_path": context["test_path"],
        "actual_value": value
    })


def check_inventory(runner, context, target, inventory_name):
    commands = {
        "secrets": ["vault", "secrets", "list", "-format=json"],
        "auth": ["vault", "auth", "list", "-format=json"],
        "policies": ["vault", "policy", "list", "-format=json"]
    }

    payload = runner.json(
        commands[inventory_name],
        context[target + "_env"]
    )

    return evidence(
        {"count": count_entries(payload)},
        count_only=True,
        summary={"count": count_entries(payload)}
    )


def run_check(results, area, title, command, condition, function):
    try:
        result = function()

        results.append(Result(
            area,
            title,
            command,
            condition,
            "verified",
            result["data"],
            result["count_only"],
            result["summary"],
            ""
        ))

    except (ValidationError, CommandError, Exception) as error:
        failed_command = command

        if isinstance(error, CommandError):
            failed_command = error.command

        results.append(Result(
            area,
            title,
            failed_command,
            condition,
            "review required",
            {},
            False,
            {},
            str(error)
        ))


def score(results, area):
    area_results = [
        result for result in results
        if result.area == area
    ]

    verified = len([
        result for result in area_results
        if result.outcome == "verified"
    ])

    return verified, len(area_results)


def manual_cards(results, context):
    items = list(context.get("manual_items", []))
    provider = context["profile"].get("provider", "aws").lower().strip()
    backend = snapshot_backend(context)

    for result in results:
        if result.outcome != "verified":
            items.append({
                "title": "Manual Review: {0}".format(result.title),
                "command": result.command,
                "reason": result.error,
                "steps": [
                    "Run the displayed command from the appropriate Vault context",
                    "Confirm the stated outcome condition",
                    "Attach command evidence to the change record"
                ]
            })

    items.append({
        "title": "Snapshot Runtime Status Retry Validation",
        "command": (
            "for i in 1 2 3 4 5; do "
            "echo \"Attempt $i of 5\"; "
            "vault read -format=json "
            "sys/storage/raft/snapshot-auto/status/{0} && break; "
            "sleep 60; "
            "done"
        ).format(backend),
        "reason": (
            "This is a permanent manual post-AMI validation. "
            "It is intentionally excluded from the automated score."
        ),
        "steps": [
            "Run the command from the approved Dojo terminal",
            "Allow up to five attempts with a 60-second wait between attempts",
            "Confirm the latest snapshot timestamp is after the AMI activity",
            "Confirm a next snapshot timestamp is populated"
        ]
    })

    items.append({
        "title": "Concourse Daily Maintenance Certificate Pipeline",
        "command": "Manual Concourse validation",
        "reason": (
            "This pipeline is intentionally not triggered by the script."
        ),
        "steps": [
            "Open Concourse Daily Maintenance for the selected environment",
            "Run the Check Certificate pipeline",
            "Confirm the pipeline succeeds",
            "Attach the successful build URL to the change record"
        ]
    })

    if provider == "aws" and config_bool(
            context["profile"].get(
                "manual_latest_snapshot_check",
                True
            ),
            True):
        items.append({
            "title": "Latest Raft Snapshot Timestamp",
            "command": "Manual Snapshot Validation",
            "reason": (
                "Permanent manual validation. Confirm that a new Raft "
                "snapshot was generated after the AMI upgrade."
            ),
            "steps": [
                "Open the cloud console for the selected environment",
                "Navigate to the configured primary Raft snapshot storage bucket",
                "Open raft-snapshots and identify the most recently modified object",
                "Confirm its timestamp is later than the AMI upgrade completion time",
                "Confirm the object has a non-zero size",
                "Record the snapshot name, timestamp, and size as change evidence"
            ]
        })

    output = ""

    for item in items:
        item_steps = item.get("steps", [])

        if isinstance(item_steps, str):
            item_steps = [item_steps]

        steps = " ".join([
            "{0}.".format(html.escape(str(step)).rstrip("."))
            for step in item_steps
        ])

        command = item.get("command", "")
        command_html = ""

        if command:
            command_html = (
                '<code class="manual-command">{0}</code>'
            ).format(html.escape(str(command)))

        output += """
        <article class="manual-card">
          <span class="manual-label">Required follow-up</span>
          <h3>{0}</h3>
          {1}
          <p>{2}</p>
          <div class="manual-steps">
            <strong>Procedure:</strong> {3}
          </div>
        </article>
        """.format(
            html.escape(str(item.get("title", "Manual Validation"))),
            command_html,
            html.escape(str(item.get("reason", ""))),
            steps
        )

    return output


def result_card(result):
    state_class = (
        "verified" if result.outcome == "verified" else "review"
    )

    if result.outcome == "verified" and result.count_only:
        body = """
        <div class="count-box">
          {0}<span>Configured entries</span>
        </div>
        """.format(
            html.escape(str(result.summary.get("count", 0)))
        )

    elif result.outcome == "verified":
        body = """
        <details class="evidence">
          <summary>View JSON evidence</summary>
          <pre>{0}</pre>
        </details>
        """.format(
            html.escape(json.dumps(
                redact(result.evidence),
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                default=str
            ))
        )

    else:
        body = """
        <div class="error-box">{0}</div>
        """.format(html.escape(result.error))

    return """
    <article class="result-card">
      <div class="result-top">
        <div>
          <p class="eyebrow">{0}</p>
          <h3>{1}</h3>
        </div>
        <span class="state {2}">{3}</span>
      </div>
      <div class="outcome-box">
        <span>Outcome Condition</span>
        <strong>{4}</strong>
      </div>
      {5}
    </article>
    """.format(
        html.escape(result.area.upper()),
        html.escape(result.title),
        state_class,
        html.escape(result.outcome.upper()),
        html.escape(result.condition),
        body
    )


def cluster_rows(results, context):
    output = ""

    for area, label in [("primary", "Primary"), ("dr", "DR")]:
        status_result = None

        for result in results:
            if result.area == area and result.title == "Vault Status":
                status_result = result
                break

        summary = status_result.summary if status_result else {}

        output += """
        <tr>
          <td>{0}</td>
          <td>{1}</td>
          <td>{2}</td>
          <td>{3}</td>
          <td>{4}</td>
          <td>{5}</td>
          <td>{6}</td>
        </tr>
        """.format(
            html.escape(label),
            html.escape(context["profile"].get(area + "_addr", "")),
            html.escape(str(summary.get("initialized", "Not available"))),
            html.escape(str(summary.get("sealed", "Not available"))),
            html.escape(str(summary.get("recovery_shares", "Not available"))),
            html.escape(str(summary.get("threshold", "Not available"))),
            html.escape(str(summary.get("version", "Not available")))
        )

    return output


def create_report(context, results, report_file):
    primary_verified, primary_total = score(results, "primary")
    dr_verified, dr_total = score(results, "dr")

    primary_cards = "\n".join([
        result_card(result)
        for result in results
        if result.area == "primary"
    ])

    dr_cards = "\n".join([
        result_card(result)
        for result in results
        if result.area == "dr"
    ])

    report = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Vault IVP/AVP Testing</title>
<style>
* { box-sizing: border-box; }
body {
  margin: 0;
  color: #001149;
  background: #edf3fb;
  font-family: "Source Sans 3", "Segoe UI", sans-serif;
  line-height: 1.5;
}
.page {
  max-width: 1280px;
  min-height: 100vh;
  margin: 0 auto;
  background: #ffffff;
}
.hero {
  padding: 42px 48px;
  color: #ffffff;
  background: linear-gradient(125deg, #001149, #001871 58%, #1352DE);
}
.eyebrow {
  margin: 0 0 8px;
  color: #C7DBF4;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 1.3px;
  text-transform: uppercase;
}
h1 { margin: 0; font-size: 34px; line-height: 1.15; }
.hero p { margin: 10px 0 0; color: #e8f1ff; }
.scores { display: flex; gap: 14px; margin-top: 28px; }
.score {
  min-width: 180px;
  padding: 15px;
  border: 1px solid rgba(255,255,255,.30);
  background: rgba(0,17,73,.28);
}
.score span {
  display: block;
  color: #C7DBF4;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.score strong { display: block; margin-top: 4px; font-size: 28px; }
.content { padding: 34px 48px 50px; }
.section { margin-top: 38px; }
.section h2 {
  margin: 0 0 16px;
  padding-bottom: 9px;
  border-bottom: 3px solid #1352DE;
  color: #001871;
  font-size: 22px;
}
.context-grid, .result-grid {
  display: grid;
  gap: 15px;
  grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
}
.context-box {
  padding: 14px;
  border-left: 4px solid #CE8E49;
  background: #f4f8fd;
}
.context-box span {
  display: block;
  color: #4c607e;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.context-box strong {
  display: block;
  margin-top: 4px;
  overflow-wrap: anywhere;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { color: #ffffff; background: #001871; text-align: left; }
th, td { padding: 11px; border: 1px solid #d5e1f0; vertical-align: top; }
tr:nth-child(even) { background: #f7faff; }
.result-card {
  border: 1px solid #cfdbeb;
  border-top: 4px solid #1352DE;
  background: #ffffff;
  box-shadow: 0 6px 16px rgba(0,24,113,.08);
}
.result-top {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 18px 18px 10px;
}
.result-top h3, .manual-card h3 {
  margin: 0;
  color: #001149;
  font-size: 17px;
  line-height: 1.3;
}
.state {
  flex: 0 0 auto;
  padding: 5px 8px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .5px;
}
.verified { color: #0e4d35; background: #dcefe5; }
.review { color: #754a0a; background: #f8e9c9; }
.outcome-box {
  margin: 0 18px 16px;
  padding: 10px 12px;
  border-left: 3px solid #CE8E49;
  background: #f3f7fc;
}
.outcome-box span {
  display: block;
  color: #4c607e;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
}
.outcome-box strong { display: block; margin-top: 3px; font-size: 13px; }
.evidence { margin: 0 18px 18px; }
.evidence summary {
  color: #001871;
  cursor: pointer;
  font-size: 13px;
  font-weight: 700;
}
pre, .manual-command {
  display: block;
  max-height: 300px;
  margin: 10px 0 0;
  padding: 13px;
  overflow: auto;
  color: #e8f1ff;
  background: #001149;
  font-family: Consolas, "Courier New", monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-word;
}
.count-box {
  margin: 0 18px 18px;
  padding: 12px;
  color: #001871;
  background: #C7DBF4;
  font-size: 27px;
  font-weight: 700;
}
.count-box span {
  display: block;
  font-size: 10px;
  text-transform: uppercase;
}
.error-box {
  margin: 0 18px 18px;
  padding: 12px;
  color: #754a0a;
  border-left: 3px solid #CE8E49;
  background: #fff5de;
  overflow-wrap: anywhere;
}
.manual-card {
  margin-top: 14px;
  padding: 20px;
  border-left: 5px solid #CE8E49;
  background: #fffaf0;
}
.manual-label {
  color: #754a0a;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: .8px;
  text-transform: uppercase;
}
.manual-card p { margin: 9px 0 0; }
.manual-steps {
  margin-top: 12px;
  padding: 12px 14px;
  color: #334a6d;
  border-left: 3px solid #CE8E49;
  background: #f3f7fc;
  font-size: 13px;
}
.footer {
  margin-top: 42px;
  padding-top: 18px;
  border-top: 1px solid #d5e1f0;
  color: #4c607e;
  font-size: 12px;
}
@media (max-width: 700px) {
  .hero, .content { padding: 28px 22px; }
  .scores { display: block; }
  .score { margin-top: 10px; }
  table { display: block; overflow-x: auto; }
}
</style>
</head>
<body>
<div class="page">
<header class="hero">
  <p class="eyebrow">Operational Assurance</p>
  <h1>Vault IVP/AVP Testing</h1>
  <p>Post-upgrade infrastructure and application validation for {0}</p>
  <div class="scores">
    <div class="score">
      <span>Primary Score</span>
      <strong>{1}/{2}</strong>
    </div>
    <div class="score">
      <span>DR Score</span>
      <strong>{3}/{4}</strong>
    </div>
  </div>
</header>

<main class="content">
<section class="section">
<h2>Run Context</h2>
<div class="context-grid">
  <div class="context-box"><span>Environment</span><strong>{0}</strong></div>
  <div class="context-box"><span>Cloud Provider</span><strong>{5}</strong></div>
  <div class="context-box"><span>Generated</span><strong>{6}</strong></div>
  <div class="context-box"><span>Test Secret Path</span><strong>{7}</strong></div>
</div>
</section>

<section class="section">
<h2>Cluster Overview</h2>
<table>
<thead>
<tr>
<th>Cluster</th><th>Address</th><th>Initialized</th><th>Sealed</th>
<th>Recovery Shares</th><th>Threshold</th><th>Version</th>
</tr>
</thead>
<tbody>{8}</tbody>
</table>
</section>

<section class="section">
<h2>Primary Validation Results</h2>
<div class="result-grid">{9}</div>
</section>

<section class="section">
<h2>DR Validation Results</h2>
<div class="result-grid">{10}</div>
</section>

<section class="section">
<h2>Manual Verification Required</h2>
{11}
</section>

<footer class="footer">
Vault IVP/AVP Testing report. Tokens are not included. Sensitive evidence
fields are redacted. Snapshot runtime and latest snapshot verification remain
manual controls.
</footer>
</main>
</div>
</body>
</html>
""".format(
        html.escape(context["environment_name"]),
        primary_verified,
        primary_total,
        dr_verified,
        dr_total,
        html.escape(
            context["profile"].get("provider", "aws").upper()
        ),
        html.escape(est_timestamp()),
        html.escape(context["test_path"]),
        cluster_rows(results, context),
        primary_cards,
        dr_cards,
        manual_cards(results, context)
    )

    with open(report_file, "w") as report_handle:
        report_handle.write(report)


def cli_summary(results, report_file):
    print("")
    print("=" * 72)
    print("VAULT IVP/AVP TESTING CLI SUMMARY")
    print("=" * 72)

    for area in ["primary", "dr"]:
        verified, total = score(results, area)

        print("")
        print("{0}: {1}/{2}".format(area.upper(), verified, total))

        for result in results:
            if result.area != area:
                continue

            state = (
                "PASSED"
                if result.outcome == "verified"
                else "FAILED"
            )

            print("  [{0}] {1}".format(state, result.title))

            if result.outcome != "verified":
                print("           {0}".format(result.error))

    print("")
    print("HTML report: {0}".format(report_file))
    print("=" * 72)


def load_config(script_directory):
    config_path = os.path.join(script_directory, CONFIG_FILE)

    if not os.path.isfile(config_path):
        raise ValidationError(
            "Config file not found: {0}".format(config_path)
        )

    with open(config_path, "r") as config_handle:
        return json.load(config_handle)


def choose_profile(profiles):
    menu_order = [
        "awsle1",
        "awsxe1",
        "awspe1",
        "gcpxe1",
        "gcppe1"
    ]

    missing = [
        name for name in menu_order
        if name not in profiles
    ]

    if missing:
        raise ValidationError(
            "Missing environment profiles: {0}".format(
                ", ".join(missing)
            )
        )

    print("")
    print("Select Vault environment:")

    for index, name in enumerate(menu_order, 1):
        print("  {0}. {1}".format(index, name))

    while True:
        choice = input("Enter selection number: ").strip()

        try:
            position = int(choice) - 1

            if position < 0:
                raise IndexError

            selected = menu_order[position]
            return selected, profiles[selected]

        except (ValueError, IndexError):
            print("Invalid selection. Enter a number from 1 to 5.")


def validate_profile(profile):
    required = [
        "primary_addr",
        "dr_addr",
        "test_secret_prefix"
    ]

    for key in required:
        if not str(profile.get(key, "")).strip():
            raise ValidationError(
                "Missing required config value: {0}".format(key)
            )

    for key in ["primary_addr", "dr_addr"]:
        if not str(profile[key]).startswith(("http://", "https://")):
            raise ValidationError(
                "{0} must start with http:// or https://".format(key)
            )


def preflight_token(runner, environment, label):
    runner.json(
        ["vault", "token", "lookup", "-format=json"],
        environment
    )

    print("{0} token validation completed.".format(label))


def main():
    script_directory = os.path.dirname(os.path.abspath(__file__))

    try:
        config = load_config(script_directory)
        profiles = config.get(
            "environments",
            config.get("profiles", {})
        )

        environment_name, profile = choose_profile(profiles)
        validate_profile(profile)

        print("")
        print("Enter Vault tokens. Values are hidden and not stored.")

        primary_token = getpass.getpass("Primary Vault token: ").strip()
        dr_token = getpass.getpass("DR operation token: ").strip()

        if not primary_token or not dr_token:
            raise ValidationError(
                "Primary and DR tokens are required."
            )

        namespace = profile.get("namespace", "").strip()
        validation_timestamp = est_now().strftime(
            "%Y%m%dT%H%M%S-EST"
        )

        context = {
            "environment_name": environment_name,
            "profile": profile,
            "dr_token": dr_token,
            "test_path": "{0}/ami-validation-{1}".format(
                profile["test_secret_prefix"].strip("/"),
                validation_timestamp
            ),
            "manual_items": [],
            "primary_env": vault_environment(
                profile["primary_addr"],
                primary_token,
                namespace
            ),
            "dr_env": vault_environment(
                profile["dr_addr"],
                dr_token,
                namespace
            )
        }

        runner = VaultRunner(
            int(profile.get("command_timeout_seconds", DEFAULT_TIMEOUT))
        )

        # Critical checks: stop only if inputs or tokens are invalid.
        preflight_token(runner, context["primary_env"], "Primary")
        preflight_token(runner, context["dr_env"], "DR")

        results = []

        run_check(
            results, "primary", "Vault Status",
            "vault status -format=json",
            "Initialized=true and Sealed=false.",
            lambda: check_status(runner, context, "primary")
        )
        run_check(
            results, "primary", "Primary Raft List Peers",
            "vault operator raft list-peers -format=json",
            "Five peers are present: one leader and four followers.",
            lambda: check_raft_peers(runner, context, "primary")
        )
        run_check(
            results, "primary", "DR Primary Replication State",
            "vault read -format=json sys/replication/dr/status",
            "DR primary is running and includes a last WAL entry.",
            lambda: check_primary_dr_replication(runner, context)
        )
        run_check(
            results, "primary", "Raft Autopilot Configuration",
            "vault operator raft autopilot get-config -format=json",
            "Autopilot configuration is returned successfully.",
            lambda: check_autopilot(runner, context, "primary")
        )
        run_check(
            results, "primary", "Vault License Get",
            "vault license get -format=json",
            "License details are returned successfully.",
            lambda: check_license_get(runner, context, "primary")
        )
        run_check(
            results, "primary", "Vault License Status",
            "vault license status -format=json",
            "License status is returned successfully.",
            lambda: check_license_status(runner, context, "primary")
        )
        run_check(
            results, "primary", "Vault Operator Members",
            "vault operator members -format=json",
            "Operator members are returned successfully.",
            lambda: check_members(runner, context, "primary")
        )
        run_check(
            results, "primary", "Snapshot Configuration",
            "vault read -format=json sys/storage/raft/snapshot-auto/config/<s3-or-gcs>",
            "Configured snapshot interval matches the environment baseline.",
            lambda: check_snapshot_config(runner, context)
        )
        run_check(
            results, "primary", "Test Secret Write",
            "vault kv put -format=json <generated-test-path> Test=success",
            "Unique test secret is written successfully.",
            lambda: check_secret_write(runner, context)
        )
        run_check(
            results, "primary", "Test Secret Read",
            "vault kv get -format=json <generated-test-path>",
            "Test secret returns Test=success.",
            lambda: check_secret_read(runner, context)
        )

        for inventory in [
                ("Secrets Engine Count", "secrets"),
                ("Auth Method Count", "auth"),
                ("Policy Count", "policies")]:
            run_check(
                results, "primary", inventory[0],
                "vault {0} list -format=json".format(inventory[1]),
                "{0} inventory is retrieved.".format(inventory[0]),
                lambda inventory_name=inventory[1]: check_inventory(
                    runner,
                    context,
                    "primary",
                    inventory_name
                )
            )

        run_check(
            results, "dr", "Vault Status",
            "vault status -format=json",
            "Initialized=true and Sealed=false.",
            lambda: check_status(runner, context, "dr")
        )
        run_check(
            results, "dr", "DR Raft List Peers",
            "vault operator raft list-peers -format=json -dr-token=REDACTED",
            "Five peers are present: one leader and four followers.",
            lambda: check_raft_peers(runner, context, "dr")
        )
        run_check(
            results, "dr", "DR Secondary Replication State",
            "vault read -format=json sys/replication/dr/status",
            "DR secondary is connected, stream_wals=true, and has a last remote WAL entry.",
            lambda: check_dr_secondary_replication(runner, context)
        )
        run_check(
            results, "dr", "Raft Autopilot Configuration",
            "vault operator raft autopilot get-config -format=json",
            "Autopilot configuration is returned successfully.",
            lambda: check_autopilot(runner, context, "dr")
        )
        run_check(
            results, "dr", "Vault License Get",
            "vault license get -format=json",
            "License details are returned successfully.",
            lambda: check_license_get(runner, context, "dr")
        )
        run_check(
            results, "dr", "Vault License Status",
            "vault license status -format=json",
            "License status is returned successfully.",
            lambda: check_license_status(runner, context, "dr")
        )
        run_check(
            results, "dr", "Vault Operator Members",
            "vault operator members -format=json",
            "Operator members are returned successfully.",
            lambda: check_members(runner, context, "dr")
        )

        for inventory in [
                ("Secrets Engine Count", "secrets"),
                ("Auth Method Count", "auth"),
                ("Policy Count", "policies")]:
            run_check(
                results, "dr", inventory[0],
                "vault {0} list -format=json".format(inventory[1]),
                "{0} inventory is retrieved.".format(inventory[0]),
                lambda inventory_name=inventory[1]: check_inventory(
                    runner,
                    context,
                    "dr",
                    inventory_name
                )
            )

        report_directory = os.path.join(
            script_directory,
            profile.get("report_directory", "reports")
        )

        if not os.path.isdir(report_directory):
            os.makedirs(report_directory)

        report_file = os.path.join(
            report_directory,
            "vault_ivp_avp_testing_{0}_{1}.html".format(
                environment_name,
                est_now().strftime("%Y%m%dT%H%M%S-EST")
            )
        )

        create_report(context, results, report_file)
        cli_summary(results, report_file)

    except ValidationError as error:
        print("")
        print("CRITICAL INPUT OR TOKEN VALIDATION ERROR")
        print(str(error))
        sys.exit(2)

    except KeyboardInterrupt:
        print("")
        print("Validation cancelled.")
        sys.exit(130)

    except Exception as error:
        print("")
        print("Unexpected script error: {0}".format(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
