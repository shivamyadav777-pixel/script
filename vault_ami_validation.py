#!/usr/bin/env python3
from __future__ import print_function

import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from getpass import getpass
from html import escape
from pathlib import Path
from string import Template
from urllib.parse import urlparse


DEFAULT_COMMAND_TIMEOUT = 90
PRIMARY_SCOPE = "Primary"
DR_SCOPE = "DR"


class ValidationError(Exception):
    pass


class CheckResult(object):
    def __init__(self, name, status, details, category="General", evidence=None):
        self.name = name
        self.status = status
        self.details = details
        self.category = category
        self.evidence = evidence or {}
        self.scope = ""
        self.duration_seconds = 0

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "details": self.details,
            "category": self.category,
            "scope": self.scope,
            "duration_seconds": self.duration_seconds,
            "evidence": self.evidence
        }


class CommandRunner(object):
    def __init__(self, transcript_path, timeout_seconds):
        self.transcript_path = transcript_path
        self.timeout_seconds = timeout_seconds
        self.handle = transcript_path.open("w", encoding="utf-8")

    def close(self):
        if not self.handle.closed:
            self.handle.close()

    def redact_command(self, command):
        safe_parts = []

        for item in command:
            if item.startswith("-dr-token="):
                safe_parts.append("-dr-token=REDACTED")
            else:
                safe_parts.append(item)

        return " ".join(safe_parts)

    def record_output(self, command, stdout, stderr):
        output = "\n" + ("=" * 100) + "\n"
        output += "COMMAND: {0}\n".format(self.redact_command(command))
        output += ("-" * 100) + "\n"
        output += "STDOUT:\n{0}\n".format(stdout.strip() or "No output")

        if stderr.strip():
            output += "\nSTDERR:\n{0}\n".format(stderr.strip())

        self.handle.write(output)
        self.handle.flush()
        print(output)

    def run(self, command, env=None, check=True, timeout_seconds=None, input_text=None):
        timeout = timeout_seconds or self.timeout_seconds

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                input=input_text,
                env=env,
                shell=False,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise ValidationError(
                "Command timed out after {0} seconds: {1}".format(
                    timeout,
                    self.redact_command(command)
                )
            )

        self.record_output(command, result.stdout, result.stderr)

        if check and result.returncode != 0:
            raise ValidationError(
                "Command failed with exit code {0}: {1}".format(
                    result.returncode,
                    self.redact_command(command)
                )
            )

        return result

    def run_json(self, command, env=None, check=True, timeout_seconds=None):
        result = self.run(
            command,
            env=env,
            check=check,
            timeout_seconds=timeout_seconds
        )

        try:
            return json.loads(result.stdout.strip()), result.returncode
        except ValueError:
            raise ValidationError(
                "Command did not return valid JSON: {0}".format(
                    self.redact_command(command)
                )
            )

    def run_json_with_retries(
        self,
        command,
        env=None,
        retries=4,
        delay_seconds=15,
        timeout_seconds=None
    ):
        last_error = None

        for attempt in range(1, retries + 1):
            try:
                result, _ = self.run_json(
                    command,
                    env=env,
                    timeout_seconds=timeout_seconds
                )
                return result
            except ValidationError as exc:
                last_error = exc

                if attempt < retries:
                    print(
                        "Retrying in {0} seconds. Attempt {1} of {2}.".format(
                            delay_seconds,
                            attempt + 1,
                            retries
                        )
                    )
                    time.sleep(delay_seconds)

        raise ValidationError(
            "Command failed after {0} attempts. Last error: {1}".format(
                retries,
                last_error
            )
        )


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


def prompt_secret(prompt):
    while True:
        value = getpass(prompt + ": ").strip()
        if value:
            return value
        print("Value is required.")


def prompt_optional_secret(prompt):
    return getpass(prompt + " (leave blank if not applicable): ").strip()


def prompt_menu(title, options):
    print("\n" + title)

    for index, option in enumerate(options, 1):
        print("{0}. {1}".format(index, option))

    while True:
        selected = input("Select an option: ").strip()

        try:
            selected_number = int(selected)
            if 1 <= selected_number <= len(options):
                return selected_number
        except ValueError:
            pass

        print(
            "Invalid selection. Enter a number between 1 and {0}.".format(
                len(options)
            )
        )


def prompt_environment(config):
    environments = sorted(config.get("environments", {}).keys())

    if not environments:
        raise ValidationError("No environments were found in the config file.")

    print("\nAvailable environments:")
    for index, environment in enumerate(environments, 1):
        print("{0}. {1}".format(index, environment))

    while True:
        selected = input("\nSelect environment: ").strip()

        if selected in environments:
            return selected

        try:
            selected_number = int(selected)
            if 1 <= selected_number <= len(environments):
                return environments[selected_number - 1]
        except ValueError:
            pass

        print("Enter a valid environment name or menu number.")


def prompt_validation_label():
    selected = prompt_menu(
        "Validation Type",
        [
            "Precheck",
            "Postcheck",
            "Custom validation label"
        ]
    )

    if selected == 1:
        return "precheck"

    if selected == 2:
        return "postcheck"

    label = prompt_input("Custom validation label")
    label = re.sub(r"[^A-Za-z0-9_-]", "-", label).strip("-")

    if not label:
        raise ValidationError("Custom validation label is invalid.")

    return label


def require_command(command_name):
    if shutil.which(command_name) is None:
        raise ValidationError(
            "Required command not found in PATH: {0}".format(command_name)
        )


def build_env(base_env, vault_addr=None, vault_token=None, extra_env=None):
    values = dict(base_env)

    if extra_env:
        values.update(extra_env)

    values["VAULT_FORMAT"] = "json"
    values["VAULT_CLIENT_TIMEOUT"] = "120"

    if vault_addr:
        values["VAULT_ADDR"] = vault_addr

    if vault_token:
        values["VAULT_TOKEN"] = vault_token

    return values


def collect_runtime_credentials(cloud, base_env):
    print("\nCredential Setup")
    print("-" * 48)
    print("Vault tokens are entered securely and are never saved to disk.")

    primary_token = prompt_secret("Primary Vault admin token")
    dr_token = prompt_secret("DR operation token")

    aws_env = dict(base_env)
    gcp_env = dict(base_env)

    if cloud == "aws":
        selected = prompt_menu(
            "AWS Credential Source",
            [
                "Use existing Dojo / AWS CLI credentials",
                "Enter temporary AWS session credentials"
            ]
        )

        if selected == 2:
            aws_access_key = prompt_secret("AWS access key ID")
            aws_secret_key = prompt_secret("AWS secret access key")
            aws_session_token = prompt_optional_secret("AWS session token")

            aws_env["AWS_ACCESS_KEY_ID"] = aws_access_key
            aws_env["AWS_SECRET_ACCESS_KEY"] = aws_secret_key

            if aws_session_token:
                aws_env["AWS_SESSION_TOKEN"] = aws_session_token

    if cloud == "gcp":
        print(
            "\nGCP validation uses the active Dojo gsutil/gcloud identity. "
            "Authenticate to GCP before running this script."
        )

    return {
        "primary_token": primary_token,
        "dr_token": dr_token,
        "aws_env": aws_env,
        "gcp_env": gcp_env
    }


def extract_data(payload):
    if isinstance(payload, dict):
        return payload.get("data", payload)
    return payload


def safe_int(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def parse_iso_datetime(value):
    if not value:
        return None

    clean = str(value).strip()

    if clean.endswith("Z"):
        clean = clean[:-1]

    if "+" in clean:
        clean = clean.split("+")[0]

    for date_format in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S"
    ]:
        try:
            return datetime.strptime(clean, date_format)
        except ValueError:
            pass

    return None


def parse_openssl_datetime(value):
    try:
        return datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def status_color(status):
    colors = {
        "PASS": "#15803d",
        "FAIL": "#c2410c",
        "PARTIAL": "#b45309",
        "MANUAL": "#0369a1"
    }
    return colors.get(status, "#475569")


def display_status(status):
    values = {
        "PASS": "Pass",
        "FAIL": "Fail",
        "PARTIAL": "Pending Manual Validation",
        "MANUAL": "Manual Validation Required"
    }
    return values.get(status, status)


def overall_status(results):
    if any(item.status == "FAIL" for item in results):
        return "FAIL"

    if any(item.status == "MANUAL" for item in results):
        return "PARTIAL"

    return "PASS"


def find_result(results, name, scope=None):
    for item in results:
        if item.name == name and (scope is None or item.scope == scope):
            return item
    return None


def score(results, scope):
    scoped_results = [item for item in results if item.scope == scope]

    return {
        "total": len(scoped_results),
        "passed": len([
            item for item in scoped_results
            if item.status == "PASS"
        ]),
        "failed": len([
            item for item in scoped_results
            if item.status == "FAIL"
        ]),
        "manual": len([
            item for item in scoped_results
            if item.status == "MANUAL"
        ])
    }


def safe_run_check(results, scope, name, category, function):
    started = time.time()

    try:
        result = function()
        result.scope = scope
        result.duration_seconds = round(time.time() - started, 2)
        results.append(result)
    except ValidationError as exc:
        result = CheckResult(name, "FAIL", str(exc), category)
        result.scope = scope
        result.duration_seconds = round(time.time() - started, 2)
        results.append(result)
    except Exception as exc:
        result = CheckResult(
            name,
            "FAIL",
            "Unexpected error: {0}".format(exc),
            category
        )
        result.scope = scope
        result.duration_seconds = round(time.time() - started, 2)
        results.append(result)


def get_snapshot_config(environment_config):
    snapshot = environment_config.get("snapshot", {})
    primary = environment_config.get("primary", {})

    return {
        "bucket": snapshot.get(
            "bucket",
            primary.get("snapshot_bucket")
        ),
        "prefix": snapshot.get(
            "prefix",
            primary.get("snapshot_prefix", "raft-snapshots/")
        ),
        "region": snapshot.get(
            "region",
            environment_config.get("aws_region")
        ),
        "expected_interval_seconds": snapshot.get(
            "expected_interval_seconds"
        ),
        "max_snapshot_age_seconds": snapshot.get(
            "max_snapshot_age_seconds"
        )
    }


def expected_snapshot_interval(environment_config):
    snapshot = get_snapshot_config(environment_config)
    configured = safe_int(snapshot.get("expected_interval_seconds"))

    if configured is not None:
        return configured

    if "inc" in environment_config.get("tier", "").lower():
        return 28800

    return 1800


def expected_snapshot_window(environment_config):
    snapshot = get_snapshot_config(environment_config)
    configured = safe_int(snapshot.get("max_snapshot_age_seconds"))

    if configured is not None:
        return configured

    if "inc" in environment_config.get("tier", "").lower():
        return 28800

    return 2400


def validate_config(environment, environment_config):
    cloud = environment_config.get("cloud", "").lower()
    primary = environment_config.get("primary", {})
    dr = environment_config.get("dr", {})
    snapshot = get_snapshot_config(environment_config)

    if cloud not in ["aws", "gcp"]:
        raise ValidationError(
            "Environment '{0}' must define cloud as aws or gcp.".format(
                environment
            )
        )

    if not primary.get("vault_addr"):
        raise ValidationError("Missing primary.vault_addr in config.")

    if not dr.get("vault_addr"):
        raise ValidationError("Missing dr.vault_addr in config.")

    if not snapshot.get("bucket"):
        raise ValidationError("Missing snapshot bucket in config.")


def check_primary_token(runner, primary_env):
    data, _ = runner.run_json(
        ["vault", "token", "lookup"],
        env=primary_env
    )

    if not extract_data(data):
        raise ValidationError("Primary token validation returned no data.")


def check_dr_operation_token(runner, dr_env, dr_token):
    runner.run_json(
        [
            "vault",
            "operator",
            "raft",
            "list-peers",
            "-dr-token={0}".format(dr_token)
        ],
        env=dr_env
    )


def check_aws_credentials(runner, aws_env):
    data, _ = runner.run_json(
        ["aws", "sts", "get-caller-identity"],
        env=aws_env
    )

    if not data.get("Account") or not data.get("Arn"):
        raise ValidationError("AWS credentials could not be validated.")


def check_gcp_credentials(runner, gcp_env, bucket):
    runner.run(
        ["gsutil", "ls", "-b", "gs://{0}".format(bucket)],
        env=gcp_env
    )


def check_vault_status(runner, env_vars, cluster_name, cache, cache_key):
    data, return_code = runner.run_json(
        ["vault", "status"],
        env=env_vars,
        check=False
    )

    if return_code not in [0, 2]:
        raise ValidationError(
            "{0} vault status returned exit code {1}.".format(
                cluster_name,
                return_code
            )
        )

    cache[cache_key] = data

    if data.get("initialized") is not True:
        raise ValidationError(
            "{0} is not initialized.".format(cluster_name)
        )

    if data.get("sealed") is not False:
        raise ValidationError(
            "{0} is sealed.".format(cluster_name)
        )

    return CheckResult(
        "Vault status ({0})".format(cluster_name.lower()),
        "PASS",
        "{0} is initialized and unsealed.".format(cluster_name),
        "Cluster Health",
        {
            "initialized": data.get("initialized"),
            "sealed": data.get("sealed"),
            "version": data.get("version"),
            "cluster_name": data.get("cluster_name"),
            "ha_mode": data.get("ha_mode"),
            "storage_type": data.get("storage_type"),
            "raft_committed_index": data.get("raft_committed_index"),
            "raft_applied_index": data.get("raft_applied_index")
        }
    )


def check_raft_peers(runner, env_vars, cluster_name, expected_count, dr_token=None):
    command = ["vault", "operator", "raft", "list-peers"]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    data, _ = runner.run_json(command, env=env_vars)
    servers = extract_data(data).get("config", {}).get("servers", [])

    leaders = [
        server for server in servers
        if server.get("leader") is True
    ]
    followers = [
        server for server in servers
        if server.get("leader") is not True
    ]
    non_voters = [
        server for server in servers
        if server.get("voter") is not True
    ]

    if len(servers) != expected_count:
        raise ValidationError(
            "{0}: expected {1} Raft peers, found {2}.".format(
                cluster_name,
                expected_count,
                len(servers)
            )
        )

    if len(leaders) != 1:
        raise ValidationError(
            "{0}: expected 1 Raft leader, found {1}.".format(
                cluster_name,
                len(leaders)
            )
        )

    if len(followers) != expected_count - 1:
        raise ValidationError(
            "{0}: expected {1} followers, found {2}.".format(
                cluster_name,
                expected_count - 1,
                len(followers)
            )
        )

    if non_voters:
        raise ValidationError(
            "{0}: found {1} non-voter Raft peers.".format(
                cluster_name,
                len(non_voters)
            )
        )

    return CheckResult(
        "Raft peers ({0})".format(cluster_name.lower()),
        "PASS",
        "{0} has 1 leader, {1} followers, and all peers are voters.".format(
            cluster_name,
            len(followers)
        ),
        "Raft",
        {
            "peer_count": len(servers),
            "leader_count": len(leaders),
            "follower_count": len(followers),
            "all_voters": True,
            "servers": servers
        }
    )


def check_autopilot(runner, env_vars, cluster_name, dr_token=None):
    command = ["vault", "operator", "raft", "autopilot", "get-config"]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    data, _ = runner.run_json(command, env=env_vars)
    payload = extract_data(data)

    return CheckResult(
        "Autopilot config ({0})".format(cluster_name.lower()),
        "PASS",
        "Autopilot configuration was retrieved successfully.",
        "Raft",
        {
            "cleanup_dead_servers": payload.get("cleanup_dead_servers"),
            "last_contact_threshold": payload.get("last_contact_threshold"),
            "dead_server_last_contact_threshold": payload.get(
                "dead_server_last_contact_threshold"
            ),
            "server_stabilization_time": payload.get(
                "server_stabilization_time"
            ),
            "min_quorum": payload.get("min_quorum"),
            "max_trailing_logs": payload.get("max_trailing_logs"),
            "disable_upgrade_migration": payload.get(
                "disable_upgrade_migration"
            )
        }
    )


def create_test_secret_path(base_path, validation_label):
    safe_label = re.sub(
        r"[^A-Za-z0-9_-]",
        "-",
        validation_label
    ).strip("-")

    if not safe_label:
        raise ValidationError("Validation label cannot create a safe secret path.")

    return "{0}/{1}-{2}".format(
        base_path.strip("/"),
        utc_now().strftime("%d%b%Y"),
        safe_label
    )


def check_test_secret_write(runner, primary_env, runtime):
    runner.run(
        [
            "vault",
            "write",
            runtime["test_secret_path"],
            "Test=success"
        ],
        env=primary_env
    )

    return CheckResult(
        "Write test secret",
        "PASS",
        "Test secret was written successfully.",
        "Functional",
        {
            "secret_path": runtime["test_secret_path"],
            "key": "Test",
            "value": "success"
        }
    )


def check_test_secret_read(runner, primary_env, runtime):
    data, _ = runner.run_json(
        ["vault", "read", runtime["test_secret_path"]],
        env=primary_env
    )

    value = extract_data(data).get("Test")

    if str(value).lower() != "success":
        raise ValidationError(
            "Test secret read failed. Expected Test=success; found Test={0}.".format(
                value
            )
        )

    return CheckResult(
        "Read test secret",
        "PASS",
        "Test secret was read successfully.",
        "Functional",
        {
            "secret_path": runtime["test_secret_path"],
            "key": "Test",
            "value": value
        }
    )


def check_snapshot_config(runner, primary_env, environment_config):
    data = runner.run_json_with_retries(
        ["vault", "read", "sys/storage/raft/snapshot-auto/config/s3"],
        env=primary_env,
        retries=environment_config.get("snapshot_retry_attempts", 4),
        delay_seconds=environment_config.get("snapshot_retry_delay_seconds", 15)
    )

    payload = extract_data(data)
    interval = safe_int(payload.get("interval"))
    expected = expected_snapshot_interval(environment_config)

    if interval != expected:
        raise ValidationError(
            "Snapshot interval is {0}; expected {1} seconds.".format(
                interval,
                expected
            )
        )

    return CheckResult(
        "Auto snapshot config",
        "PASS",
        "Snapshot configuration was retrieved with the expected interval.",
        "Snapshots",
        {
            "interval_seconds": interval,
            "expected_interval_seconds": expected,
            "bucket": payload.get("aws_s3_bucket"),
            "region": payload.get("aws_s3_region"),
            "path_prefix": payload.get("path_prefix"),
            "retain": payload.get("retain"),
            "storage_type": payload.get("storage_type")
        }
    )


def check_snapshot_status(runner, primary_env, environment_config):
    data = runner.run_json_with_retries(
        ["vault", "read", "sys/storage/raft/snapshot-auto/status/s3"],
        env=primary_env,
        retries=environment_config.get("snapshot_retry_attempts", 4),
        delay_seconds=environment_config.get("snapshot_retry_delay_seconds", 15)
    )

    payload = extract_data(data)
    last_snapshot = parse_iso_datetime(payload.get("last_snapshot_end"))
    next_snapshot = parse_iso_datetime(payload.get("next_snapshot_start"))
    snapshot_url = payload.get("last_snapshot_url") or payload.get("snapshot_url")
    allowed_window = expected_snapshot_window(environment_config)
    consecutive_errors = safe_int(payload.get("consecutive_errors"))

    if not last_snapshot:
        raise ValidationError("Snapshot status does not contain last_snapshot_end.")

    if not next_snapshot:
        raise ValidationError("Snapshot status does not contain next_snapshot_start.")

    if not snapshot_url:
        raise ValidationError("Snapshot status does not contain a snapshot URL.")

    last_snapshot_age = int((utc_now() - last_snapshot).total_seconds())
    next_snapshot_wait = int((next_snapshot - utc_now()).total_seconds())

    if last_snapshot_age < 0 or last_snapshot_age > allowed_window:
        raise ValidationError(
            "Last snapshot age is {0} seconds; maximum allowed is {1} seconds.".format(
                last_snapshot_age,
                allowed_window
            )
        )

    if next_snapshot_wait < 0 or next_snapshot_wait > allowed_window:
        raise ValidationError(
            "Next snapshot is scheduled in {0} seconds; allowed maximum is {1} seconds.".format(
                next_snapshot_wait,
                allowed_window
            )
        )

    if consecutive_errors not in [None, 0]:
        raise ValidationError(
            "Snapshot status reports consecutive_errors={0}.".format(
                consecutive_errors
            )
        )

    return CheckResult(
        "Auto snapshot status",
        "PASS",
        "Last and next automated snapshots are within the expected window.",
        "Snapshots",
        {
            "last_snapshot_end": payload.get("last_snapshot_end"),
            "next_snapshot_start": payload.get("next_snapshot_start"),
            "snapshot_url": snapshot_url,
            "last_snapshot_age_seconds": last_snapshot_age,
            "next_snapshot_wait_seconds": next_snapshot_wait,
            "allowed_window_seconds": allowed_window,
            "consecutive_errors": consecutive_errors
        }
    )


def check_primary_replication(runner, primary_env):
    data, _ = runner.run_json(
        ["vault", "read", "sys/replication/status"],
        env=primary_env
    )

    dr = extract_data(data).get("dr", {})
    secondaries = dr.get("secondaries", [])
    connection_states = [
        secondary.get("connection_status")
        for secondary in secondaries
    ]

    if dr.get("mode") != "primary":
        raise ValidationError(
            "Primary replication mode is '{0}', expected 'primary'.".format(
                dr.get("mode")
            )
        )

    if dr.get("state") != "running":
        raise ValidationError(
            "Primary replication state is '{0}', expected 'running'.".format(
                dr.get("state")
            )
        )

    if not secondaries or any(status != "connected" for status in connection_states):
        raise ValidationError(
            "Primary replication is not connected to every DR secondary."
        )

    return CheckResult(
        "Replication status",
        "PASS",
        "Primary replication is running and connected.",
        "Replication",
        {
            "mode": dr.get("mode"),
            "state": dr.get("state"),
            "last_wal": dr.get("last_wal"),
            "last_dr_wal": dr.get("last_dr_wal"),
            "secondary_count": len(secondaries),
            "connection_statuses": connection_states
        }
    )


def check_dr_replication(runner, dr_env):
    data, _ = runner.run_json(
        ["vault", "read", "sys/replication/status"],
        env=dr_env
    )

    dr = extract_data(data).get("dr", {})
    primaries = dr.get("primaries", [])
    connection_states = [
        primary.get("connection_status")
        for primary in primaries
    ]

    if dr.get("mode") != "secondary":
        raise ValidationError(
            "DR replication mode is '{0}', expected 'secondary'.".format(
                dr.get("mode")
            )
        )

    if dr.get("state") != "stream-wals":
        raise ValidationError(
            "DR replication state is '{0}', expected 'stream-wals'.".format(
                dr.get("state")
            )
        )

    if dr.get("connection_state") != "ready":
        raise ValidationError(
            "DR connection state is '{0}', expected 'ready'.".format(
                dr.get("connection_state")
            )
        )

    if not primaries or any(status != "connected" for status in connection_states):
        raise ValidationError(
            "DR replication is not connected to every primary endpoint."
        )

    return CheckResult(
        "Replication status",
        "PASS",
        "DR replication is streaming WALs and connected.",
        "Replication",
        {
            "mode": dr.get("mode"),
            "state": dr.get("state"),
            "connection_state": dr.get("connection_state"),
            "last_remote_wal": dr.get("last_remote_wal"),
            "primary_count": len(primaries),
            "connection_statuses": connection_states
        }
    )


def extract_members(payload):
    data = extract_data(payload)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ["members", "servers", "nodes"]:
            if isinstance(data.get(key), list):
                return data.get(key)

    return []


def check_operator_members(runner, primary_env, expected_count):
    data, _ = runner.run_json(
        ["vault", "operator", "members"],
        env=primary_env
    )

    members = extract_members(data)

    if not members:
        raise ValidationError(
            "Operator members output was retrieved but no member list could be parsed."
        )

    if len(members) != expected_count:
        raise ValidationError(
            "Expected {0} operator members; found {1}.".format(
                expected_count,
                len(members)
            )
        )

    active_members = [
        member for member in members
        if member.get("active_node") is True
    ]

    return CheckResult(
        "Operator members",
        "PASS",
        "{0} Vault operator members were retrieved.".format(len(members)),
        "Cluster Health",
        {
            "member_count": len(members),
            "active_member_count": len(active_members)
        }
    )


def count_items(payload):
    data = extract_data(payload)

    if isinstance(data, list):
        return len(data)

    if isinstance(data, dict):
        if isinstance(data.get("keys"), list):
            return len(data.get("keys"))
        return len(data)

    return 0


def check_vault_inventory(runner, primary_env):
    secrets, _ = runner.run_json(
        ["vault", "secrets", "list"],
        env=primary_env
    )
    auth, _ = runner.run_json(
        ["vault", "auth", "list"],
        env=primary_env
    )
    policies, _ = runner.run_json(
        ["vault", "policy", "list"],
        env=primary_env
    )

    return CheckResult(
        "Secrets, auth, and policy counts",
        "PASS",
        "Secrets, auth methods, and policies were retrieved successfully.",
        "Inventory",
        {
            "secret_mount_count": count_items(secrets),
            "auth_mount_count": count_items(auth),
            "policy_count": count_items(policies)
        }
    )


def check_license(runner, primary_env, warning_days):
    data, _ = runner.run_json(
        ["vault", "license", "get"],
        env=primary_env
    )

    expiration = extract_data(data).get("expiration_time")
    expiration_date = parse_iso_datetime(expiration)

    if not expiration_date:
        raise ValidationError(
            "License expiration_time was not returned or could not be parsed."
        )

    days_remaining = int(
        (expiration_date - utc_now()).total_seconds() / 86400
    )

    if days_remaining < warning_days:
        raise ValidationError(
            "Vault license expires in {0} days; minimum required is {1} days.".format(
                days_remaining,
                warning_days
            )
        )

    return CheckResult(
        "Vault license status",
        "PASS",
        "Vault license is valid for {0} more days.".format(days_remaining),
        "Compliance",
        {
            "expiration_time": expiration,
            "days_remaining": days_remaining,
            "minimum_required_days": warning_days
        }
    )


def check_audit_devices(runner, primary_env):
    data, _ = runner.run_json(
        ["vault", "audit", "list", "-detailed"],
        env=primary_env
    )

    audit_devices = extract_data(data)
    count = len(audit_devices) if isinstance(audit_devices, dict) else 0

    return CheckResult(
        "Audit devices",
        "PASS",
        "Audit device configuration was retrieved successfully.",
        "Compliance",
        {
            "audit_device_count": count,
            "audit_paths": sorted(audit_devices.keys())
            if isinstance(audit_devices, dict) else []
        }
    )


def check_vault_version(cache, cache_key, cluster_name):
    status = cache.get(cache_key, {})
    version = status.get("version")

    if not version:
        raise ValidationError(
            "{0} Vault version was not available from vault status.".format(
                cluster_name
            )
        )

    return CheckResult(
        "Vault version",
        "PASS",
        "{0} Vault version is {1}.".format(cluster_name, version),
        "Cluster Health",
        {
            "version": version,
            "build_date": status.get("build_date")
        }
    )


def check_recovery_info(cache, cache_key, cluster_name):
    status = cache.get(cache_key, {})

    shares = status.get("recovery_shares")
    threshold = status.get("recovery_threshold")

    if shares is None:
        shares = status.get("shares")

    if threshold is None:
        threshold = status.get("threshold")

    if shares is None or threshold is None:
        raise ValidationError(
            "{0} recovery shares or threshold were not returned.".format(
                cluster_name
            )
        )

    return CheckResult(
        "Recovery shares and threshold",
        "PASS",
        "{0} recovery configuration was retrieved successfully.".format(
            cluster_name
        ),
        "Cluster Health",
        {
            "recovery_shares": shares,
            "recovery_threshold": threshold
        }
    )


def split_ssl_address(address):
    parsed = urlparse(address)

    if not parsed.hostname:
        raise ValidationError("Invalid SSL address: {0}".format(address))

    return parsed.hostname, parsed.port or 443


def check_ssl_certificate(runner, address, cluster_name, warning_days):
    host, port = split_ssl_address(address)

    handshake = runner.run(
        [
            "openssl",
            "s_client",
            "-showcerts",
            "-connect",
            "{0}:{1}".format(host, port),
            "-servername",
            host
        ],
        check=False,
        input_text=""
    )

    if not handshake.stdout.strip():
        raise ValidationError(
            "{0} SSL handshake returned no certificate output.".format(
                cluster_name
            )
        )

    certificate = runner.run(
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-startdate",
            "-enddate",
            "-fingerprint",
            "-sha256"
        ],
        input_text=handshake.stdout
    )

    values = {}
    for line in certificate.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip().lower()] = value.strip()

    expiry = parse_openssl_datetime(values.get("notafter", ""))

    if not expiry:
        raise ValidationError(
            "{0} SSL expiry date could not be parsed.".format(cluster_name)
        )

    days_remaining = int((expiry - utc_now()).total_seconds() / 86400)

    if days_remaining < warning_days:
        raise ValidationError(
            "{0} SSL certificate expires in {1} days; minimum is {2} days.".format(
                cluster_name,
                days_remaining,
                warning_days
            )
        )

    return CheckResult(
        "SSL certificate",
        "PASS",
        "{0} SSL certificate is valid for {1} more days.".format(
            cluster_name,
            days_remaining
        ),
        "Compliance",
        {
            "address": "{0}:{1}".format(host, port),
            "subject": values.get("subject"),
            "issuer": values.get("issuer"),
            "issued_on": values.get("notbefore"),
            "expires_on": values.get("notafter"),
            "days_remaining": days_remaining,
            "minimum_required_days": warning_days,
            "sha256_fingerprint": values.get("sha256 fingerprint")
        }
    )


def list_aws_snapshots(runner, aws_env, bucket, prefix, region):
    objects = []
    continuation_token = None

    while True:
        command = [
            "aws",
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket,
            "--prefix",
            prefix
        ]

        if region:
            command.extend(["--region", region])

        if continuation_token:
            command.extend([
                "--continuation-token",
                continuation_token
            ])

        page, _ = runner.run_json(command, env=aws_env)
        objects.extend(page.get("Contents", []))

        if not page.get("IsTruncated"):
            break

        continuation_token = page.get("NextContinuationToken")
        if not continuation_token:
            break

    return objects


def list_gcp_snapshots(runner, gcp_env, bucket, prefix):
    result = runner.run(
        [
            "gsutil",
            "ls",
            "-l",
            "gs://{0}/{1}**".format(bucket, prefix)
        ],
        env=gcp_env
    )

    objects = []
    pattern = re.compile(r"^\s*(\d+)\s+(\S+)\s+(gs://\S+)")

    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())

        if match:
            objects.append({
                "Size": match.group(1),
                "LastModified": match.group(2),
                "Key": match.group(3)
            })

    return objects


def check_cloud_snapshots(runner, environment_config, aws_env, gcp_env):
    cloud = environment_config["cloud"].lower()
    snapshot = get_snapshot_config(environment_config)

    if cloud == "aws":
        objects = list_aws_snapshots(
            runner,
            aws_env,
            snapshot["bucket"],
            snapshot["prefix"],
            snapshot["region"]
        )
    else:
        objects = list_gcp_snapshots(
            runner,
            gcp_env,
            snapshot["bucket"],
            snapshot["prefix"]
        )

    if not objects:
        raise ValidationError(
            "No snapshots found in {0} bucket '{1}'.".format(
                cloud.upper(),
                snapshot["bucket"]
            )
        )

    latest_three = sorted(
        objects,
        key=lambda item: item.get("LastModified", ""),
        reverse=True
    )[:3]

    return CheckResult(
        "Latest cloud snapshots",
        "PASS",
        "The latest three {0} snapshots were retrieved successfully.".format(
            cloud.upper()
        ),
        "Snapshots",
        {
            "cloud": cloud.upper(),
            "bucket": snapshot["bucket"],
            "prefix": snapshot["prefix"],
            "snapshots": [
                {
                    "object": item.get("Key"),
                    "last_modified": item.get("LastModified"),
                    "size": item.get("Size")
                }
                for item in latest_three
            ]
        }
    )


def evidence_summary(evidence):
    if not evidence:
        return "No additional evidence."

    output = []

    for key in sorted(evidence.keys()):
        value = evidence.get(key)

        if value is None:
            continue

        if isinstance(value, list):
            shown = "{0} item(s)".format(len(value))
        elif isinstance(value, dict):
            shown = "{0} field(s)".format(len(value))
        else:
            shown = str(value)

        output.append(
            "{0}: {1}".format(
                key.replace("_", " ").title(),
                shown
            )
        )

        if len(output) >= 5:
            break

    return " | ".join(output) if output else "No additional evidence."


def metric_card(label, value, tone=None):
    shown = "N/A" if value is None or value == "" else str(value)
    border = ""

    if tone:
        border = ' style="border-top:4px solid {0};"'.format(tone)

    return """
    <div class="metric-card"{0}>
      <div class="metric-label">{1}</div>
      <div class="metric-value">{2}</div>
    </div>
    """.format(
        border,
        escape(label),
        escape(shown)
    )


def report_row(item):
    return """
    <tr>
      <td>{0}</td>
      <td>{1}</td>
      <td><strong>{2}</strong></td>
      <td><span class="badge" style="background:{3};">{4}</span></td>
      <td>{5}</td>
      <td>{6}</td>
      <td>{7}s</td>
    </tr>
    """.format(
        escape(item.scope),
        escape(item.category),
        escape(item.name),
        status_color(item.status),
        escape(display_status(item.status)),
        escape(item.details),
        escape(evidence_summary(item.evidence)),
        escape(str(item.duration_seconds))
    )


def cluster_panel(title, status, raft, replication, wal_field):
    status_label = "N/A"
    initialized = "N/A"
    sealed = "N/A"
    peers = "N/A"
    wal = "N/A"

    if status:
        status_label = display_status(status.status)
        initialized = status.evidence.get("initialized")
        sealed = status.evidence.get("sealed")

    if raft:
        peers = raft.evidence.get("peer_count")

    if replication:
        wal = replication.evidence.get(wal_field)

    return """
    <section class="cluster-panel">
      <h3>{0}</h3>
      <div class="cluster-line"><span>Status</span><strong>{1}</strong></div>
      <div class="cluster-line"><span>Initialized</span><strong>{2}</strong></div>
      <div class="cluster-line"><span>Sealed</span><strong>{3}</strong></div>
      <div class="cluster-line"><span>Raft peers</span><strong>{4}</strong></div>
      <div class="cluster-line"><span>Replication index</span><strong>{5}</strong></div>
    </section>
    """.format(
        escape(title),
        escape(str(status_label)),
        escape(str(initialized)),
        escape(str(sealed)),
        escape(str(peers)),
        escape(str(wal))
    )


def render_html_report(environment, validation_label, config, results, metadata):
    overall = overall_status(results)
    primary_score = score(results, PRIMARY_SCOPE)
    dr_score = score(results, DR_SCOPE)

    primary_status = find_result(
        results,
        "Vault status (primary)",
        PRIMARY_SCOPE
    )
    dr_status = find_result(
        results,
        "Vault status (dr)",
        DR_SCOPE
    )
    primary_raft = find_result(
        results,
        "Raft peers (primary)",
        PRIMARY_SCOPE
    )
    dr_raft = find_result(
        results,
        "Raft peers (dr)",
        DR_SCOPE
    )
    primary_replication = find_result(
        results,
        "Replication status",
        PRIMARY_SCOPE
    )
    dr_replication = find_result(
        results,
        "Replication status",
        DR_SCOPE
    )
    cloud_snapshots = find_result(
        results,
        "Latest cloud snapshots",
        PRIMARY_SCOPE
    )
    license_status = find_result(
        results,
        "Vault license status",
        PRIMARY_SCOPE
    )

    metrics = [
        metric_card(
            "Overall Result",
            display_status(overall),
            status_color(overall)
        ),
        metric_card(
            "Primary Score",
            "{0}/{1}".format(
                primary_score["passed"],
                primary_score["total"]
            ),
            "#0f766e"
        ),
        metric_card(
            "DR Score",
            "{0}/{1}".format(
                dr_score["passed"],
                dr_score["total"]
            ),
            "#0f766e"
        ),
        metric_card(
            "Primary Raft Peers",
            primary_raft.evidence.get("peer_count")
            if primary_raft else None
        ),
        metric_card(
            "DR Raft Peers",
            dr_raft.evidence.get("peer_count")
            if dr_raft else None
        ),
        metric_card(
            "License Days Remaining",
            license_status.evidence.get("days_remaining")
            if license_status else None
        ),
        metric_card(
            "Latest Snapshot",
            cloud_snapshots.evidence.get("snapshots", [{}])[0].get(
                "last_modified"
            )
            if cloud_snapshots and cloud_snapshots.evidence.get("snapshots")
            else None
        )
    ]

    failures = [
        item for item in results
        if item.status == "FAIL"
    ]

    exceptions = """
    <div class="exception exception-pass">
      <h3>Validation Summary</h3>
      <p>All automated validation checks completed successfully.</p>
    </div>
    """

    if failures:
        exceptions = """
        <div class="exception exception-fail">
          <h3>Validation Failures</h3>
          <ul>{0}</ul>
        </div>
        """.format(
            "".join([
                "<li><strong>{0}</strong>: {1}</li>".format(
                    escape(item.name),
                    escape(item.details)
                )
                for item in failures
            ])
        )

    snapshot = get_snapshot_config(config)

    context = [
        ("Cloud", config.get("cloud", "").upper()),
        ("Tier", config.get("tier", "N/A")),
        ("Primary Vault Address", config.get("primary", {}).get("vault_addr")),
        ("DR Vault Address", config.get("dr", {}).get("vault_addr")),
        ("Test Secret Path", metadata.get("test_secret_path")),
        ("Snapshot Bucket", snapshot.get("bucket")),
        ("Snapshot Prefix", snapshot.get("prefix")),
        ("Transcript File", metadata.get("transcript_path"))
    ]

    context_cards = []
    for label, value in context:
        context_cards.append("""
        <div class="context-card">
          <div class="context-label">{0}</div>
          <div class="context-value">{1}</div>
        </div>
        """.format(
            escape(label),
            escape(str(value or "N/A"))
        ))

    template = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vault Validation Report - $environment</title>
<style>
body {
  margin: 0;
  background: #edf4f7;
  color: #102a43;
  font-family: "Segoe UI", Arial, sans-serif;
}
.page {
  width: 94%;
  max-width: 1480px;
  margin: 0 auto;
  padding: 30px 0 44px;
}
.hero {
  padding: 34px;
  border-radius: 26px;
  color: #ffffff;
  background: linear-gradient(125deg, #062f3c 0%, #0e7490 52%, #164e63 100%);
  box-shadow: 0 20px 50px rgba(8, 47, 73, 0.25);
}
.hero h1 {
  margin: 0 0 10px;
  font-size: 34px;
}
.hero p {
  margin: 6px 0;
  color: rgba(255, 255, 255, 0.91);
}
.overall {
  display: inline-block;
  margin-top: 16px;
  padding: 11px 18px;
  border-radius: 100px;
  background: $overall_color;
  color: white;
  font-size: 15px;
  font-weight: 700;
}
.section {
  margin-top: 20px;
  padding: 24px;
  border: 1px solid #d8e3e9;
  border-radius: 22px;
  background: #ffffff;
  box-shadow: 0 9px 25px rgba(15, 42, 67, 0.06);
}
.section h2 {
  margin: 0 0 16px;
  color: #082f49;
  font-size: 22px;
}
.metric-grid, .context {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 14px;
}
.cluster-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
}
.metric-card, .context-card, .cluster-panel {
  padding: 16px;
  border: 1px solid #dce8ed;
  border-radius: 16px;
  background: linear-gradient(180deg, #ffffff, #f7fbfc);
}
.metric-label, .context-label {
  color: #5d7484;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.09em;
  text-transform: uppercase;
}
.metric-value {
  margin-top: 9px;
  color: #0c3b50;
  font-size: 23px;
  font-weight: 800;
  overflow-wrap: anywhere;
}
.context-value {
  margin-top: 7px;
  color: #102a43;
  font-size: 14px;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.cluster-panel h3 {
  margin: 0 0 13px;
  color: #0b5568;
  font-size: 19px;
}
.cluster-line {
  display: flex;
  justify-content: space-between;
  gap: 15px;
  padding: 10px 0;
  border-top: 1px solid #dfeaec;
}
.cluster-line:first-of-type {
  border-top: 0;
}
.cluster-line span {
  color: #5d7484;
}
.cluster-line strong {
  color: #102a43;
  text-align: right;
}
.exception {
  padding: 16px 18px;
  border-radius: 15px;
}
.exception h3 {
  margin: 0 0 9px;
}
.exception p, .exception ul {
  margin: 0;
}
.exception-fail {
  border: 1px solid #fed7aa;
  background: #fff7ed;
  color: #9a3412;
}
.exception-pass {
  border: 1px solid #bbf7d0;
  background: #f0fdf4;
  color: #166534;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th, td {
  padding: 13px 11px;
  border-bottom: 1px solid #deeaed;
  text-align: left;
  vertical-align: top;
}
th {
  background: #ecf6f8;
  color: #31566a;
  font-size: 11px;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}
tr:nth-child(even) td {
  background: #fbfdfe;
}
.badge {
  display: inline-block;
  padding: 6px 9px;
  border-radius: 99px;
  color: white;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}
.footer {
  padding-top: 20px;
  color: #607d8b;
  font-size: 12px;
  text-align: center;
}
</style>
</head>
<body>
<main class="page">
  <section class="hero">
    <h1>Vault AMI Validation Report</h1>
    <p>Infrastructure validation summary for engineering and leadership review.</p>
    <p>Environment: <strong>$environment</strong> | Validation: <strong>$validation_label</strong></p>
    <p>Generated: <strong>$timestamp</strong></p>
    <div class="overall">Overall Result: $overall_label</div>
  </section>

  <section class="section">
    <h2>Executive Summary</h2>
    <div class="metric-grid">$metrics</div>
  </section>

  <section class="section">
    <h2>Cluster Overview</h2>
    <div class="cluster-grid">
      $primary_panel
      $dr_panel
    </div>
  </section>

  <section class="section">
    <h2>Exceptions and Follow-up</h2>
    $exceptions
  </section>

  <section class="section">
    <h2>Run Context</h2>
    <div class="context">$context_cards</div>
  </section>

  <section class="section">
    <h2>Validation Results</h2>
    <table>
      <thead>
        <tr>
          <th>Scope</th>
          <th>Category</th>
          <th>Check</th>
          <th>Status</th>
          <th>Outcome</th>
          <th>Evidence</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>$rows</tbody>
    </table>
  </section>

  <div class="footer">
    Full command output is retained in the transcript file. Token values are never included in the HTML or JSON report.
  </div>
</main>
</body>
</html>
""")

    return template.substitute(
        environment=escape(environment),
        validation_label=escape(validation_label),
        timestamp=escape(metadata["timestamp_utc"]),
        overall_color=status_color(overall),
        overall_label=escape(display_status(overall)),
        metrics="".join(metrics),
        primary_panel=cluster_panel(
            "Primary Cluster",
            primary_status,
            primary_raft,
            primary_replication,
            "last_wal"
        ),
        dr_panel=cluster_panel(
            "DR Cluster",
            dr_status,
            dr_raft,
            dr_replication,
            "last_remote_wal"
        ),
        exceptions=exceptions,
        context_cards="".join(context_cards),
        rows="".join([report_row(item) for item in results])
    )


def main():
    script_dir = Path(__file__).resolve().parent
    config_path = script_dir / "vault_validation_config.json"

    if not config_path.exists():
        print(
            "Config file not found: {0}".format(config_path),
            file=sys.stderr
        )
        return 2

    try:
        full_config = json.loads(
            config_path.read_text(encoding="utf-8")
        )
    except ValueError as exc:
        print("Config JSON is invalid: {0}".format(exc), file=sys.stderr)
        return 2

    runner = None

    try:
        print("\nVault AMI Validation")
        print("=" * 48)

        environment = prompt_environment(full_config)
        validation_label = prompt_validation_label()
        environment_config = full_config["environments"][environment]

        validate_config(environment, environment_config)

        cloud = environment_config["cloud"].lower()
        report_dir = script_dir / "reports" / environment
        report_dir.mkdir(parents=True, exist_ok=True)

        require_command("vault")
        require_command("openssl")

        if cloud == "aws":
            require_command("aws")

        if cloud == "gcp":
            require_command("gsutil")

        base_env = dict(os.environ)
        credentials = collect_runtime_credentials(cloud, base_env)

        primary_env = build_env(
            base_env,
            vault_addr=environment_config["primary"]["vault_addr"],
            vault_token=credentials["primary_token"]
        )

        dr_env = build_env(
            base_env,
            vault_addr=environment_config["dr"]["vault_addr"],
            vault_token=credentials["dr_token"]
        )

        dr_operation_env = build_env(
            base_env,
            vault_addr=environment_config["dr"]["vault_addr"]
        )

        command_timeout = environment_config.get(
            "command_timeout_seconds",
            DEFAULT_COMMAND_TIMEOUT
        )

        transcript_path = report_dir / (
            "vault_validation_transcript_{0}_{1}.log".format(
                environment,
                utc_now_str()
            )
        )

        runner = CommandRunner(transcript_path, command_timeout)

        snapshot = get_snapshot_config(environment_config)

        print("\nRunning critical credential prechecks...")
        check_primary_token(runner, primary_env)
        check_dr_operation_token(
            runner,
            dr_operation_env,
            credentials["dr_token"]
        )

        if cloud == "aws":
            check_aws_credentials(runner, credentials["aws_env"])

        if cloud == "gcp":
            check_gcp_credentials(
                runner,
                credentials["gcp_env"],
                snapshot["bucket"]
            )

        runtime = {
            "test_secret_path": create_test_secret_path(
                environment_config.get(
                    "test_secret_base_path",
                    "kvtest/test"
                ),
                validation_label
            )
        }

        results = []
        status_cache = {}
        expected_peers = environment_config.get("expected_raft_peers", 5)
        license_warning_days = environment_config.get(
            "license_warning_days",
            60
        )
        certificate_warning_days = environment_config.get(
            "certificate_warning_days",
            60
        )

        # Primary cluster: 16 checks
        safe_run_check(
            results, PRIMARY_SCOPE, "Vault status (primary)", "Cluster Health",
            lambda: check_vault_status(
                runner, primary_env, "Primary", status_cache, "primary"
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Raft peers (primary)", "Raft",
            lambda: check_raft_peers(
                runner, primary_env, "Primary", expected_peers
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Autopilot config (primary)", "Raft",
            lambda: check_autopilot(runner, primary_env, "Primary")
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Write test secret", "Functional",
            lambda: check_test_secret_write(runner, primary_env, runtime)
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Read test secret", "Functional",
            lambda: check_test_secret_read(runner, primary_env, runtime)
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Auto snapshot config", "Snapshots",
            lambda: check_snapshot_config(
                runner, primary_env, environment_config
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Auto snapshot status", "Snapshots",
            lambda: check_snapshot_status(
                runner, primary_env, environment_config
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Replication status", "Replication",
            lambda: check_primary_replication(runner, primary_env)
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Operator members", "Cluster Health",
            lambda: check_operator_members(
                runner, primary_env, expected_peers
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Secrets, auth, and policy counts", "Inventory",
            lambda: check_vault_inventory(runner, primary_env)
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Vault license status", "Compliance",
            lambda: check_license(
                runner, primary_env, license_warning_days
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Audit devices", "Compliance",
            lambda: check_audit_devices(runner, primary_env)
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Latest cloud snapshots", "Snapshots",
            lambda: check_cloud_snapshots(
                runner,
                environment_config,
                credentials["aws_env"],
                credentials["gcp_env"]
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Vault version", "Cluster Health",
            lambda: check_vault_version(
                status_cache, "primary", "Primary"
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "Recovery shares and threshold", "Cluster Health",
            lambda: check_recovery_info(
                status_cache, "primary", "Primary"
            )
        )
        safe_run_check(
            results, PRIMARY_SCOPE, "SSL certificate", "Compliance",
            lambda: check_ssl_certificate(
                runner,
                environment_config["primary"].get(
                    "ssl_address",
                    environment_config["primary"]["vault_addr"]
                ),
                "Primary",
                certificate_warning_days
            )
        )

        # DR cluster: 7 checks
        safe_run_check(
            results, DR_SCOPE, "Vault status (dr)", "Cluster Health",
            lambda: check_vault_status(
                runner, dr_env, "DR", status_cache, "dr"
            )
        )
        safe_run_check(
            results, DR_SCOPE, "Raft peers (dr)", "Raft",
            lambda: check_raft_peers(
                runner,
                dr_operation_env,
                "DR",
                expected_peers,
                credentials["dr_token"]
            )
        )
        safe_run_check(
            results, DR_SCOPE, "Autopilot config (dr)", "Raft",
            lambda: check_autopilot(
                runner,
                dr_operation_env,
                "DR",
                credentials["dr_token"]
            )
        )
        safe_run_check(
            results, DR_SCOPE, "Replication status", "Replication",
            lambda: check_dr_replication(runner, dr_env)
        )
        safe_run_check(
            results, DR_SCOPE, "Vault version", "Cluster Health",
            lambda: check_vault_version(status_cache, "dr", "DR")
        )
        safe_run_check(
            results, DR_SCOPE, "Recovery shares and threshold", "Cluster Health",
            lambda: check_recovery_info(status_cache, "dr", "DR")
        )
        safe_run_check(
            results, DR_SCOPE, "SSL certificate", "Compliance",
            lambda: check_ssl_certificate(
                runner,
                environment_config["dr"].get(
                    "ssl_address",
                    environment_config["dr"]["vault_addr"]
                ),
                "DR",
                certificate_warning_days
            )
        )

        runner.close()

        timestamp = utc_now().isoformat() + "Z"
        overall = overall_status(results)

        metadata = {
            "timestamp_utc": timestamp,
            "validation_label": validation_label,
            "test_secret_path": runtime["test_secret_path"],
            "transcript_path": str(transcript_path)
        }

        report = {
            "environment": environment,
            "validation_label": validation_label,
            "timestamp_utc": timestamp,
            "overall_status": overall,
            "metadata": metadata,
            "scores": {
                "primary": score(results, PRIMARY_SCOPE),
                "dr": score(results, DR_SCOPE)
            },
            "results": [item.to_dict() for item in results]
        }

        report_name = "vault_validation_report_{0}_{1}".format(
            environment,
            utc_now_str()
        )

        json_path = report_dir / (report_name + ".json")
        html_path = report_dir / (report_name + ".html")

        json_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )

        html_path.write_text(
            render_html_report(
                environment,
                validation_label,
                environment_config,
                results,
                metadata
            ),
            encoding="utf-8"
        )

        print("\n" + ("=" * 48))
        print("Overall result: {0}".format(display_status(overall)))

        for result in results:
            print(
                "[{0}] {1} - {2}: {3}".format(
                    display_status(result.status),
                    result.scope,
                    result.name,
                    result.details
                )
            )

        print("\nHTML report: {0}".format(html_path))
        print("JSON report: {0}".format(json_path))
        print("Command transcript: {0}".format(transcript_path))

        return 1 if overall == "FAIL" else 0

    except ValidationError as exc:
        if runner:
            runner.close()

        print(
            "\nCritical setup failure: {0}".format(exc),
            file=sys.stderr
        )
        return 2

    except KeyboardInterrupt:
        if runner:
            runner.close()

        print("\nValidation cancelled by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
