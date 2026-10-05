#!/usr/bin/env python
# Python 3.5 compatible.
# Read-only except for one uniquely named validation secret under kvtest/test.

from __future__ import print_function

import copy
import datetime
import getpass
import html
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from string import Template
from urllib.parse import urlparse


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "vault_validation_config.json")
REPORT_ROOT = os.path.join(SCRIPT_DIR, "reports")


class ValidationError(Exception):
    pass


class CommandError(Exception):
    def __init__(self, command, returncode, stderr):
        self.command = command
        self.returncode = returncode
        self.stderr = stderr

        message = "Command returned exit code {0}: {1}".format(
            returncode,
            command
        )

        if stderr:
            message += " - {0}".format(clean_error(stderr))

        Exception.__init__(self, message)


class CheckResult(object):
    def __init__(self, section, title, command, steps, counts_only=False):
        self.section = section
        self.title = title
        self.command = command
        self.steps = steps
        self.counts_only = counts_only
        self.outcome = "review"
        self.evidence = None
        self.error = ""


def clean_error(value):
    text = str(value or "").strip()

    text = re.sub(
        r"(?i)(token|password|secret|access_key)[=:][^\s,;]+",
        r"\1=***",
        text
    )

    return text[:800]


def display_command(command):
    values = []

    for item in command:
        value = str(item)

        if value.startswith("-dr-token="):
            value = "-dr-token=***"

        values.append(value)

    return " ".join(values)


class CommandRunner(object):
    def run(self, command, environment, allowed_codes=None, timeout=60):
        if allowed_codes is None:
            allowed_codes = [0]

        command_environment = os.environ.copy()
        command_environment.update(environment or {})
        command_environment["VAULT_FORMAT"] = "json"
        command_environment["VAULT_CLI_NO_COLOR"] = "1"

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=command_environment
            )

            stdout, stderr = process.communicate(timeout=timeout)

        except OSError as exc:
            raise ValidationError(
                "Unable to start {0}: {1}".format(
                    display_command(command),
                    exc
                )
            )

        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

            raise ValidationError(
                "Command timed out: {0}".format(display_command(command))
            )

        if not isinstance(stdout, str):
            stdout = stdout.decode("utf-8", "replace")

        if not isinstance(stderr, str):
            stderr = stderr.decode("utf-8", "replace")

        if process.returncode not in allowed_codes:
            raise CommandError(
                display_command(command),
                process.returncode,
                stderr
            )

        return stdout

    def run_json(self, command, environment, allowed_codes=None, retries=1):
        last_error = None

        for attempt in range(retries):
            try:
                output = self.run(
                    command,
                    environment,
                    allowed_codes=allowed_codes
                )

                return json.loads(output)

            except (ValueError, ValidationError, CommandError) as exc:
                last_error = exc

                if attempt + 1 < retries:
                    time.sleep(5)

        if isinstance(last_error, ValueError):
            raise ValidationError(
                "Expected JSON output from {0}.".format(
                    display_command(command)
                )
            )

        raise last_error


def load_config():
    if not os.path.isfile(CONFIG_FILE):
        raise ValidationError(
            "Configuration file not found: {0}".format(CONFIG_FILE)
        )

    try:
        with open(CONFIG_FILE, "r") as config_file:
            config = json.load(config_file)
    except (IOError, ValueError) as exc:
        raise ValidationError(
            "Unable to read configuration file: {0}".format(exc)
        )

    if not isinstance(config.get("environments"), dict):
        raise ValidationError(
            "Configuration must contain an environments object."
        )

    return config


def choose(title, values):
    while True:
        print("\n{0}".format(title))

        for number, value in enumerate(values, 1):
            print("  {0}. {1}".format(number, value))

        answer = input("Choose an option: ").strip()

        try:
            selected = int(answer)

            if 1 <= selected <= len(values):
                return selected - 1
        except ValueError:
            pass

        print("Please select a valid menu number.")


def required_secret(label):
    for unused_attempt in range(3):
        value = getpass.getpass(label).strip()

        if value:
            return value

        print("A value is required.")

    raise ValidationError("Required input was not supplied.")


def get_label():
    selected = choose(
        "Validation type",
        ["Precheck", "Postcheck", "Custom label"]
    )

    if selected == 0:
        return "precheck"

    if selected == 1:
        return "postcheck"

    while True:
        label = input(
            "Enter label (letters, numbers, hyphens, underscores): "
        ).strip()

        if re.match(r"^[A-Za-z0-9_-]{1,40}$", label):
            return label.lower()

        print("Invalid label.")


def get_aws_options():
    selected = choose(
        "AWS S3 snapshot validation",
        [
            "Use AWS credentials already available in Dojo",
            "Enter temporary AWS credentials for this run",
            "Skip AWS credential-dependent snapshot checks"
        ]
    )

    if selected == 0:
        return True, {}, ""

    if selected == 2:
        return False, {}, "AWS credentials were intentionally skipped."

    environment = {
        "AWS_ACCESS_KEY_ID": required_secret("AWS access key ID: "),
        "AWS_SECRET_ACCESS_KEY": required_secret(
            "AWS secret access key: "
        )
    }

    session_token = getpass.getpass(
        "AWS session token (press Enter if not applicable): "
    ).strip()

    if session_token:
        environment["AWS_SESSION_TOKEN"] = session_token

    return True, environment, ""


def validate_profile(name, profile):
    required_keys = [
        "provider",
        "primary_addr",
        "dr_addr",
        "test_secret_prefix"
    ]

    for key in required_keys:
        value = str(profile.get(key, "")).strip()

        if not value:
            raise ValidationError(
                "Environment {0} is missing {1}.".format(name, key)
            )

        if "PRIMARY-VAULT-ADDRESS" in value:
            raise ValidationError(
                "Update primary_addr for {0}.".format(name)
            )

        if "DR-VAULT-ADDRESS" in value:
            raise ValidationError(
                "Update dr_addr for {0}.".format(name)
            )


def build_context():
    config = load_config()
    environment_names = sorted(config["environments"].keys())

    environment_name = environment_names[
        choose("Select Vault environment", environment_names)
    ]

    profile = copy.deepcopy(config["environments"][environment_name])
    validate_profile(environment_name, profile)

    label = get_label()

    print("\nTokens remain in process memory only and are never written to disk.")

    primary_token = required_secret("Primary Vault token: ")
    dr_token = required_secret("DR operation token: ")

    aws_enabled = False
    aws_environment = {}
    aws_skip_reason = ""

    if profile["provider"] == "aws":
        aws_enabled, aws_environment, aws_skip_reason = get_aws_options()

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    secret_path = "{0}/{1}-{2}-{3}".format(
        profile["test_secret_prefix"].strip("/"),
        datetime.datetime.utcnow().strftime("%Y%m%d"),
        label,
        timestamp
    )

    primary_environment = {
        "VAULT_ADDR": profile["primary_addr"],
        "VAULT_TOKEN": primary_token
    }

    dr_environment = {
        "VAULT_ADDR": profile["dr_addr"],
        "VAULT_TOKEN": dr_token
    }

    primary_environment.update(aws_environment)
    dr_environment.update(aws_environment)

    return {
        "environment": environment_name,
        "profile": profile,
        "label": label,
        "timestamp": timestamp,
        "secret_path": secret_path,
        "primary_token": primary_token,
        "dr_token": dr_token,
        "primary_env": primary_environment,
        "dr_env": dr_environment,
        "aws_enabled": aws_enabled,
        "aws_skip_reason": aws_skip_reason,
        "manual_items": []
    }


def extract_data(payload):
    if isinstance(payload, dict):
        if isinstance(payload.get("data"), (dict, list)):
            return payload["data"]

    return payload


def as_bool(value):
    return value is True or str(value).strip().lower() == "true"


def expect(condition, message):
    if not condition:
        raise ValidationError(message)


def find_first(value, names):
    wanted = set([name.lower() for name in names])

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in wanted and item not in (None, ""):
                return item

        for item in value.values():
            found = find_first(item, names)

            if found not in (None, ""):
                return found

    elif isinstance(value, list):
        for item in value:
            found = find_first(item, names)

            if found not in (None, ""):
                return found

    return None


def values_for_keys(value, names):
    wanted = set([name.lower() for name in names])
    output = []

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in wanted:
                output.append(item)

            output.extend(values_for_keys(item, names))

    elif isinstance(value, list):
        for item in value:
            output.extend(values_for_keys(item, names))

    return output


def parse_timestamp(value):
    if not value:
        return None

    text = str(value).strip()
    text = text.replace("Z", "+0000")
    text = re.sub(r"([+-]\d\d):(\d\d)$", r"\1\2", text)

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S"
    ]

    for timestamp_format in formats:
        try:
            parsed = datetime.datetime.strptime(text, timestamp_format)

            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=datetime.timezone.utc)

            return parsed.astimezone(datetime.timezone.utc)

        except ValueError:
            pass

    return None


def evidence(payload, assessment=None):
    output = {"command_output": payload}

    if assessment:
        output["assessment"] = assessment

    return output


def status_json(runner, environment):
    return runner.run_json(
        ["vault", "status", "-format=json"],
        environment,
        allowed_codes=[0, 1, 2, 3, 4]
    )


def check_status(runner, environment):
    payload = status_json(runner, environment)

    expect(as_bool(payload.get("initialized")), "Vault is not initialized.")
    expect(not as_bool(payload.get("sealed")), "Vault is sealed.")

    return evidence(payload, {
        "initialized": payload.get("initialized"),
        "sealed": payload.get("sealed")
    })


def find_raft_servers(value):
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            matching = []

            for item in value:
                if "state" in item and (
                    "voter" in item or
                    "node_id" in item or
                    "id" in item
                ):
                    matching.append(item)

            if matching:
                return matching

        for item in value:
            found = find_raft_servers(item)

            if found:
                return found

    elif isinstance(value, dict):
        for item in value.values():
            found = find_raft_servers(item)

            if found:
                return found

    return []


def check_raft_peers(runner, environment, dr_token=None):
    command = [
        "vault",
        "operator",
        "raft",
        "list-peers",
        "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    payload = runner.run_json(command, environment)
    servers = find_raft_servers(extract_data(payload))

    expect(bool(servers), "Raft output did not contain a peer list.")

    leaders = [
        item for item in servers
        if str(item.get("state", "")).lower() == "leader"
    ]

    followers = [
        item for item in servers
        if str(item.get("state", "")).lower() == "follower"
    ]

    voters = [
        item for item in servers
        if as_bool(item.get("voter"))
    ]

    expect(len(servers) == 5, "Expected 5 Raft peers; found {0}.".format(
        len(servers)
    ))
    expect(len(leaders) == 1, "Expected 1 Raft leader.")
    expect(len(followers) == 4, "Expected 4 Raft followers.")
    expect(len(voters) == 5, "Expected 5 Raft voters.")

    return evidence(payload, {
        "peer_count": len(servers),
        "leader_count": len(leaders),
        "follower_count": len(followers),
        "voter_count": len(voters)
    })


def check_autopilot(runner, environment, dr_token=None):
    command = [
        "vault",
        "operator",
        "raft",
        "autopilot",
        "get-config",
        "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    payload = runner.run_json(command, environment)
    return evidence(payload)


def check_secret_write(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "write",
            "-format=json",
            context["secret_path"],
            "Test=success"
        ],
        context["primary_env"]
    )

    return evidence(payload, {
        "validation_path": context["secret_path"]
    })


def find_test_value(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() == "test":
                return item

            found = find_test_value(item)

            if found is not None:
                return found

    elif isinstance(value, list):
        for item in value:
            found = find_test_value(item)

            if found is not None:
                return found

    return None


def check_secret_read(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "read",
            "-format=json",
            context["secret_path"]
        ],
        context["primary_env"]
    )

    test_value = find_test_value(payload)

    expect(
        str(test_value).strip().lower() == "success",
        "Expected Test=success; got {0}.".format(test_value)
    )

    return evidence(payload, {
        "validation_path": context["secret_path"],
        "Test": test_value
    })


def check_snapshot_config(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "read",
            "-format=json",
            "sys/storage/raft/snapshot-auto/config/s3"
        ],
        context["primary_env"],
        retries=3
    )

    interval = find_first(
        extract_data(payload),
        ["interval", "snapshot_interval"]
    )

    expected_interval = int(
        context["profile"].get("snapshot_interval_seconds", 1800)
    )

    expect(interval is not None, "Snapshot interval was not found.")

    try:
        expect(
            int(interval) == expected_interval,
            "Expected interval {0}; found {1}.".format(
                expected_interval,
                interval
            )
        )
    except (TypeError, ValueError):
        raise ValidationError(
            "Snapshot interval is invalid: {0}.".format(interval)
        )

    return evidence(payload, {
        "expected_interval_seconds": expected_interval,
        "reported_interval_seconds": interval
    })


def check_snapshot_status(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "read",
            "-format=json",
            "sys/storage/raft/snapshot-auto/status/s3"
        ],
        context["primary_env"],
        retries=3
    )

    data = extract_data(payload)

    latest_text = find_first(data, [
        "last_snapshot_time",
        "last_snapshot",
        "last_successful_snapshot",
        "last_snapshot_start"
    ])

    next_text = find_first(data, [
        "next_snapshot_time",
        "next_snapshot"
    ])

    latest = parse_timestamp(latest_text)

    expect(
        latest is not None,
        "Snapshot status does not contain a readable latest timestamp."
    )

    maximum_age = int(
        context["profile"].get("snapshot_max_age_seconds", 2400)
    )

    age_seconds = (
        datetime.datetime.now(datetime.timezone.utc) - latest
    ).total_seconds()

    expect(
        age_seconds <= maximum_age,
        "Latest snapshot is {0:.0f} seconds old; allowed {1}.".format(
            age_seconds,
            maximum_age
        )
    )

    return evidence(payload, {
        "latest_snapshot": latest_text,
        "next_snapshot": next_text,
        "age_seconds": int(age_seconds),
        "maximum_age_seconds": maximum_age
    })


def check_replication(runner, environment, expected_mode, expected_state):
    payload = runner.run_json(
        [
            "vault",
            "read",
            "-format=json",
            "sys/replication/status"
        ],
        environment
    )

    data = extract_data(payload)

    if isinstance(data, dict):
        dr_data = data.get("dr", data)
    else:
        dr_data = data

    mode = find_first(dr_data, ["mode"])
    state = find_first(dr_data, ["state"])

    values = values_for_keys(
        dr_data,
        ["connection_state", "connection_status"]
    )

    connections = []

    for value in values:
        if isinstance(value, list):
            connections.extend([
                str(item).lower()
                for item in value
                if item not in (None, "")
            ])
        elif value not in (None, ""):
            connections.append(str(value).lower())

    expect(
        str(mode).lower() == expected_mode,
        "Expected DR mode {0}; found {1}.".format(
            expected_mode,
            mode
        )
    )

    expect(
        str(state).lower() == expected_state,
        "Expected DR state {0}; found {1}.".format(
            expected_state,
            state
        )
    )

    expect(bool(connections), "Replication connection state was not found.")

    allowed_connections = ["connected"]

    if expected_mode == "secondary":
        allowed_connections.append("ready")

    expect(
        all(item in allowed_connections for item in connections),
        "Unexpected replication connection state: {0}.".format(
            ", ".join(connections)
        )
    )

    return evidence(payload, {
        "mode": mode,
        "state": state,
        "connection_states": connections,
        "last_wal_entry": find_first(
            dr_data,
            ["last_wal", "last_wal_entry"]
        ),
        "last_remote_entry": find_first(
            dr_data,
            ["last_remote_wal", "last_remote_entry"]
        )
    })


def member_records(value):
    if isinstance(value, list):
        output = []

        for item in value:
            output.extend(member_records(item))

        return output

    if not isinstance(value, dict):
        return []

    fields = [
        "hostname",
        "host_name",
        "api_address",
        "cluster_address",
        "active_node",
        "last_echo"
    ]

    if any(field in value for field in fields):
        return [value]

    output = []

    for item in value.values():
        output.extend(member_records(item))

    return output


def check_members(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "operator",
            "members",
            "-format=json"
        ],
        context["primary_env"]
    )

    members = member_records(extract_data(payload))

    expect(bool(members), "Operator members output has no member list.")

    active_members = [
        item for item in members
        if as_bool(item.get("active_node"))
    ]

    expect(
        len(members) == 5,
        "Expected 5 operator members; found {0}.".format(len(members))
    )

    expect(
        len(active_members) == 1,
        "Expected 1 active operator member."
    )

    return evidence(payload, {
        "member_count": len(members),
        "active_member_count": len(active_members)
    })


def check_inventory(runner, context):
    secrets = runner.run_json(
        ["vault", "secrets", "list", "-format=json"],
        context["primary_env"]
    )

    auth = runner.run_json(
        ["vault", "auth", "list", "-format=json"],
        context["primary_env"]
    )

    policies = runner.run_json(
        ["vault", "policy", "list", "-format=json"],
        context["primary_env"]
    )

    secret_data = extract_data(secrets)
    auth_data = extract_data(auth)
    policy_data = extract_data(policies)

    if isinstance(policy_data, dict):
        policy_data = policy_data.get("keys", [])

    return {
        "secret_mount_count": len(secret_data)
        if isinstance(secret_data, dict) else 0,

        "auth_mount_count": len(auth_data)
        if isinstance(auth_data, dict) else 0,

        "policy_count": len(policy_data)
        if isinstance(policy_data, list) else 0
    }


def check_license(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "license",
            "get",
            "-format=json"
        ],
        context["primary_env"]
    )

    expiration_text = find_first(
        payload,
        ["expiration_time", "expiration"]
    )

    expiration = parse_timestamp(expiration_text)

    expect(
        expiration is not None,
        "License expiration time was not found."
    )

    days_remaining = (
        expiration - datetime.datetime.now(datetime.timezone.utc)
    ).total_seconds() / 86400.0

    expect(
        days_remaining >= 60,
        "License expires in {0:.0f} days.".format(days_remaining)
    )

    return evidence(payload, {
        "expiration_time": expiration_text,
        "days_remaining": int(days_remaining)
    })


def check_audit(runner, context):
    payload = runner.run_json(
        [
            "vault",
            "audit",
            "list",
            "-detailed",
            "-format=json"
        ],
        context["primary_env"]
    )

    return evidence(payload)


def check_cloud_snapshots(runner, context):
    bucket = str(
        context["profile"].get("snapshot_bucket", "")
    ).strip()

    prefix = str(
        context["profile"].get("snapshot_prefix", "")
    ).strip()

    expect(
        bucket and "SNAPSHOT-BUCKET" not in bucket,
        "Snapshot bucket is not configured."
    )

    if context["profile"]["provider"] == "aws":
        command = [
            "aws",
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket,
            "--prefix",
            prefix,
            "--output",
            "json",
            "--query",
            "reverse(sort_by(Contents,&LastModified))[:3]."
            "{Key:Key,LastModified:LastModified,Size:Size}"
        ]

        payload = runner.run_json(command, context["primary_env"])

    else:
        target = "gs://{0}/{1}".format(bucket, prefix)

        payload = runner.run_json(
            [
                "gcloud",
                "storage",
                "objects",
                "list",
                target,
                "--format=json",
                "--sort-by=~updateTime",
                "--limit=3"
            ],
            context["primary_env"]
        )

    if isinstance(payload, list):
        snapshots = payload
    elif isinstance(payload, dict):
        snapshots = payload.get("Contents", [])
    else:
        snapshots = []

    expect(bool(snapshots), "No cloud raft snapshots were found.")

    return evidence(payload, {
        "snapshot_count_returned": len(snapshots)
    })


def check_version(runner, environment):
    payload = status_json(runner, environment)
    version = find_first(payload, ["version"])

    expect(bool(version), "Vault version was not found.")

    return evidence(payload, {"version": version})


def check_recovery(runner, environment):
    payload = status_json(runner, environment)

    shares = find_first(payload, [
        "recovery_seal_shares",
        "total_recovery_shares",
        "recovery_shares"
    ])

    threshold = find_first(payload, [
        "recovery_seal_threshold",
        "recovery_threshold"
    ])

    expect(
        shares is not None,
        "Total Recovery Shares was not found in vault status."
    )

    expect(
        threshold is not None,
        "Recovery Threshold was not found in vault status."
    )

    return evidence(payload, {
        "total_recovery_shares": shares,
        "recovery_threshold": threshold
    })


def check_tls(address):
    parsed = urlparse(address)
    hostname = parsed.hostname
    port = parsed.port or 443

    expect(bool(hostname), "Invalid Vault address: {0}".format(address))

    ssl_context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=15) as raw:
            with ssl_context.wrap_socket(
                raw,
                server_hostname=hostname
            ) as secure:
                certificate = secure.getpeercert()

    except (socket.error, ssl.SSLError) as exc:
        raise ValidationError(
            "TLS validation failed for {0}:{1}: {2}".format(
                hostname,
                port,
                exc
            )
        )

    expiry = certificate.get("notAfter")

    try:
        expiry_epoch = ssl.cert_time_to_seconds(expiry)
    except (TypeError, ValueError):
        raise ValidationError("TLS certificate expiry was not found.")

    days_remaining = (expiry_epoch - time.time()) / 86400.0

    expect(
        days_remaining >= 60,
        "TLS certificate expires in {0:.0f} days.".format(days_remaining)
    )

    return {
        "host": hostname,
        "port": port,
        "certificate_expiry": expiry,
        "days_remaining": int(days_remaining),
        "subject": certificate.get("subject", []),
        "issuer": certificate.get("issuer", [])
    }


def execute_check(results, section, title, command, steps, callback,
                  counts_only=False):
    result = CheckResult(
        section,
        title,
        command,
        steps,
        counts_only=counts_only
    )

    try:
        result.evidence = callback()
        result.outcome = "verified"

    except (ValidationError, CommandError) as exc:
        result.outcome = "review"
        result.error = clean_error(exc)

    except Exception as exc:
        result.outcome = "review"
        result.error = "Unexpected validation error: {0}".format(
            clean_error(exc)
        )

    results.append(result)


def run_checks(context):
    runner = CommandRunner()
    results = []

    # Invalid Primary token is a critical stop condition.
    runner.run_json(
        [
            "vault",
            "token",
            "lookup",
            "-format=json"
        ],
        context["primary_env"]
    )

    primary_env = context["primary_env"]
    dr_env = context["dr_env"]
    secret_path = context["secret_path"]

    primary_checks = [
        (
            "Vault status (Primary)",
            "vault status -format=json",
            ["Confirm Initialized is true and Sealed is false."],
            lambda: check_status(runner, primary_env),
            False
        ),
        (
            "Raft list-peers (Primary)",
            "vault operator raft list-peers -format=json",
            ["Confirm 1 leader, 4 followers, and 5 voters."],
            lambda: check_raft_peers(runner, primary_env),
            False
        ),
        (
            "Raft autopilot configuration (Primary)",
            "vault operator raft autopilot get-config -format=json",
            ["Compare output with the approved configuration."],
            lambda: check_autopilot(runner, primary_env),
            False
        ),
        (
            "Validation secret write (Primary)",
            "vault write -format=json {0} Test=success".format(
                secret_path
            ),
            ["Confirm the token has write access to the approved test path."],
            lambda: check_secret_write(runner, context),
            False
        ),
        (
            "Validation secret read (Primary)",
            "vault read -format=json {0}".format(secret_path),
            ["Confirm Test=success is returned."],
            lambda: check_secret_read(runner, context),
            False
        ),
        (
            "Snapshot configuration (Primary)",
            "vault read -format=json "
            "sys/storage/raft/snapshot-auto/config/s3",
            ["Confirm snapshot interval matches the environment baseline."],
            lambda: check_snapshot_config(runner, context),
            False
        ),
        (
            "Snapshot runtime status (Primary)",
            "vault read -format=json "
            "sys/storage/raft/snapshot-auto/status/s3",
            [
                "Retry after five minutes if necessary.",
                "Confirm latest snapshot time is recent."
            ],
            lambda: check_snapshot_status(runner, context),
            False
        ),
        (
            "DR replication state (Primary)",
            "vault read -format=json sys/replication/status",
            [
                "Confirm mode is primary.",
                "Confirm state is running.",
                "Confirm connections are connected."
            ],
            lambda: check_replication(
                runner,
                primary_env,
                "primary",
                "running"
            ),
            False
        ),
        (
            "Operator members (Primary)",
            "vault operator members -format=json",
            [
                "Run from the active Vault node.",
                "Confirm active node and expected peers are listed."
            ],
            lambda: check_members(runner, context),
            False
        ),
        (
            "Vault inventory counts (Primary)",
            "vault secrets list -format=json; "
            "vault auth list -format=json; "
            "vault policy list -format=json",
            ["Compare count values with the approved baseline."],
            lambda: check_inventory(runner, context),
            True
        ),
        (
            "Vault license (Primary)",
            "vault license get -format=json",
            [
                "Confirm license expiration is at least 60 days away.",
                "Do not use vault license status."
            ],
            lambda: check_license(runner, context),
            False
        ),
        (
            "Audit devices (Primary)",
            "vault audit list -detailed -format=json",
            ["Confirm approved audit devices remain configured."],
            lambda: check_audit(runner, context),
            False
        ),
        (
            "Vault version (Primary)",
            "vault status -format=json",
            ["Confirm version matches the approved AMI release."],
            lambda: check_version(runner, primary_env),
            False
        ),
        (
            "Recovery shares and threshold (Primary)",
            "vault status -format=json",
            [
                "Confirm Total Recovery Shares.",
                "Confirm Recovery Threshold matches the approved design."
            ],
            lambda: check_recovery(runner, primary_env),
            False
        ),
        (
            "TLS certificate (Primary)",
            "TLS handshake to Primary Vault address",
            ["Confirm certificate expiry is at least 60 days away."],
            lambda: check_tls(context["profile"]["primary_addr"]),
            False
        )
    ]

    if context["profile"]["provider"] != "aws" or context["aws_enabled"]:
        primary_checks.insert(
            12,
            (
                "Latest raft snapshots (Primary)",
                "aws s3api list-objects-v2 --bucket "
                "<configured-bucket> --prefix <configured-prefix> "
                "--output json",
                [
                    "Confirm latest three raft snapshots exist.",
                    "Confirm timestamps are later than AMI activity."
                ],
                lambda: check_cloud_snapshots(runner, context),
                False
            )
        )
    else:
        context["manual_items"].append({
            "title": "Latest raft snapshots (Primary)",
            "command": "aws s3api list-objects-v2 --bucket "
            "<configured-bucket> --prefix <configured-prefix> "
            "--output json",
            "reason": context["aws_skip_reason"],
            "steps": [
                "Open the configured S3 bucket.",
                "Open the raft-snapshots prefix.",
                "Confirm latest three snapshots are after the AMI activity."
            ]
        })

    for index, item in enumerate(primary_checks, 1):
        print("[Primary {0}/{1}] {2}".format(
            index,
            len(primary_checks),
            item[0]
        ))

        execute_check(
            results,
            "Primary",
            item[0],
            item[1],
            item[2],
            item[3],
            item[4]
        )

    dr_checks = [
        (
            "Vault status (DR)",
            "vault status -format=json",
            ["Confirm Initialized is true and Sealed is false."],
            lambda: check_status(runner, dr_env),
            False
        ),
        (
            "Raft list-peers (DR)",
            "vault operator raft list-peers -format=json -dr-token=***",
            [
                "Run with the DR operation token.",
                "Confirm 1 leader, 4 followers, and 5 voters."
            ],
            lambda: check_raft_peers(
                runner,
                dr_env,
                context["dr_token"]
            ),
            False
        ),
        (
            "Raft autopilot configuration (DR)",
            "vault operator raft autopilot get-config "
            "-format=json -dr-token=***",
            [
                "Run with the DR operation token.",
                "Compare with the approved configuration."
            ],
            lambda: check_autopilot(
                runner,
                dr_env,
                context["dr_token"]
            ),
            False
        ),
        (
            "DR replication state (DR)",
            "vault read -format=json sys/replication/status",
            [
                "Confirm mode is secondary.",
                "Confirm state is stream-wals.",
                "Confirm connection state is ready.",
                "Confirm last remote entry continues advancing."
            ],
            lambda: check_replication(
                runner,
                dr_env,
                "secondary",
                "stream-wals"
            ),
            False
        ),
        (
            "Vault version (DR)",
            "vault status -format=json",
            ["Confirm version matches the approved AMI release."],
            lambda: check_version(runner, dr_env),
            False
        ),
        (
            "Recovery shares and threshold (DR)",
            "vault status -format=json",
            [
                "Confirm Total Recovery Shares.",
                "Confirm Recovery Threshold matches the approved design."
            ],
            lambda: check_recovery(runner, dr_env),
            False
        ),
        (
            "TLS certificate (DR)",
            "TLS handshake to DR Vault address",
            ["Confirm certificate expiry is at least 60 days away."],
            lambda: check_tls(context["profile"]["dr_addr"]),
            False
        )
    ]

    for index, item in enumerate(dr_checks, 1):
        print("[DR {0}/{1}] {2}".format(
            index,
            len(dr_checks),
            item[0]
        ))

        execute_check(
            results,
            "DR",
            item[0],
            item[1],
            item[2],
            item[3],
            item[4]
        )

    return results


def redact(value, key=""):
    sensitive_keys = [
        "token",
        "password",
        "secret_id",
        "access_key",
        "private_key"
    ]

    if any(item in str(key).lower() for item in sensitive_keys):
        return "***"

    if isinstance(value, dict):
        return dict(
            (name, redact(item, name))
            for name, item in value.items()
        )

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


def format_evidence(value):
    try:
        return json.dumps(
            redact(value),
            indent=2,
            sort_keys=True,
            default=str
        )
    except (TypeError, ValueError):
        return json.dumps({"evidence": str(value)}, indent=2)


def score(results, section):
    selected = [
        result for result in results
        if result.section == section
    ]

    verified = [
        result for result in selected
        if result.outcome == "verified"
    ]

    return len(verified), len(selected)


def find_result(results, title):
    for result in results:
        if result.title == title:
            return result

    return None


def assessment_value(results, title, key, default_value="Not reported"):
    result = find_result(results, title)

    if not result or not isinstance(result.evidence, dict):
        return default_value

    assessment = result.evidence.get("assessment", {})

    if not isinstance(assessment, dict):
        return default_value

    value = assessment.get(key)

    if value in (None, ""):
        return default_value

    return str(value)


def result_outcome(results, title):
    result = find_result(results, title)

    if not result:
        return "Manual review"

    if result.outcome == "verified":
        return "Evidence captured"

    return "Manual review"


def overview_row(label, value, detail=""):
    detail_html = ""

    if detail:
        detail_html = "<span>{0}</span>".format(html.escape(detail))

    return """
    <div class="overview-row">
      <div>
        <strong>{0}</strong>
        {1}
      </div>
      <b>{2}</b>
    </div>
    """.format(
        html.escape(label),
        detail_html,
        html.escape(str(value))
    )


def cluster_overview(results, context):
    primary_raft_summary = "{0} peers | {1} leader | {2} followers".format(
        assessment_value(
            results,
            "Raft list-peers (Primary)",
            "peer_count"
        ),
        assessment_value(
            results,
            "Raft list-peers (Primary)",
            "leader_count"
        ),
        assessment_value(
            results,
            "Raft list-peers (Primary)",
            "follower_count"
        )
    )

    dr_raft_summary = "{0} peers | {1} leader | {2} followers".format(
        assessment_value(
            results,
            "Raft list-peers (DR)",
            "peer_count"
        ),
        assessment_value(
            results,
            "Raft list-peers (DR)",
            "leader_count"
        ),
        assessment_value(
            results,
            "Raft list-peers (DR)",
            "follower_count"
        )
    )

    primary_rows = "".join([
        overview_row(
            "Vault endpoint",
            context["profile"]["primary_addr"]
        ),
        overview_row(
            "Vault status",
            result_outcome(results, "Vault status (Primary)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment_value(
                    results,
                    "Vault status (Primary)",
                    "initialized"
                ),
                assessment_value(
                    results,
                    "Vault status (Primary)",
                    "sealed"
                )
            )
        ),
        overview_row(
            "Raft topology",
            result_outcome(results, "Raft list-peers (Primary)"),
            primary_raft_summary
        ),
        overview_row(
            "DR replication",
            result_outcome(results, "DR replication state (Primary)"),
            "Mode: {0} | State: {1}".format(
                assessment_value(
                    results,
                    "DR replication state (Primary)",
                    "mode"
                ),
                assessment_value(
                    results,
                    "DR replication state (Primary)",
                    "state"
                )
            )
        ),
        overview_row(
            "Vault version",
            assessment_value(
                results,
                "Vault version (Primary)",
                "version"
            )
        )
    ])

    dr_rows = "".join([
        overview_row(
            "Vault endpoint",
            context["profile"]["dr_addr"]
        ),
        overview_row(
            "Vault status",
            result_outcome(results, "Vault status (DR)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment_value(
                    results,
                    "Vault status (DR)",
                    "initialized"
                ),
                assessment_value(
                    results,
                    "Vault status (DR)",
                    "sealed"
                )
            )
        ),
        overview_row(
            "Raft topology",
            result_outcome(results, "Raft list-peers (DR)"),
            dr_raft_summary
        ),
        overview_row(
            "DR replication",
            result_outcome(results, "DR replication state (DR)"),
            "Mode: {0} | State: {1}".format(
                assessment_value(
                    results,
                    "DR replication state (DR)",
                    "mode"
                ),
                assessment_value(
                    results,
                    "DR replication state (DR)",
                    "state"
                )
            )
        ),
        overview_row(
            "Vault version",
            assessment_value(
                results,
                "Vault version (DR)",
                "version"
            )
        )
    ])

    return """
    <div class="cluster-grid">
      <article class="cluster-card primary-cluster">
        <div class="cluster-card-head">
          <span>Primary Cluster</span>
          <strong>Primary</strong>
        </div>
        {0}
      </article>

      <article class="cluster-card dr-cluster">
        <div class="cluster-card-head">
          <span>Disaster Recovery Cluster</span>
          <strong>DR</strong>
        </div>
        {1}
      </article>
    </div>
    """.format(primary_rows, dr_rows)


def render_run_context(context):
    snapshot_validation = "Included"

    if (
        context["profile"]["provider"] == "aws" and
        not context["aws_enabled"]
    ):
        snapshot_validation = "Manual verification required"

    values = [
        ("Environment", context["environment"]),
        ("Provider", context["profile"]["provider"].upper()),
        ("Validation label", context["label"]),
        ("Generated UTC", context["timestamp"]),
        ("Test secret path", context["secret_path"]),
        ("Snapshot validation", snapshot_validation)
    ]

    output = ""

    for label, value in values:
        output += """
        <div class="context-item">
          <span>{0}</span>
          <strong>{1}</strong>
        </div>
        """.format(
            html.escape(label),
            html.escape(str(value))
        )

    return '<div class="context-grid">{0}</div>'.format(output)


def render_card(result, number):
    card_type = "captured"
    review_note = ""

    if result.outcome != "verified":
        card_type = "review"

        review_note = """
        <div class="review-note">
          <strong>Review note</strong>
          <span>{0}</span>
        </div>
        """.format(html.escape(result.error))

    json_output = format_evidence(result.evidence)

    outcome = "Evidence captured"

    if result.outcome != "verified":
        outcome = "Manual verification required"

    return """
    <article class="validation-card {0}">
      <div class="validation-head">
        <div class="validation-title">
          <span class="validation-number">{1:02d}</span>
          <div>
            <h3>{2}</h3>
            <p>{3}</p>
          </div>
        </div>
        <span class="validation-outcome {0}">{4}</span>
      </div>

      {5}

      <details class="evidence-panel" open>
        <summary>View JSON evidence</summary>
        <pre>{6}</pre>
      </details>
    </article>
    """.format(
        card_type,
        number,
        html.escape(result.title),
        html.escape(result.command),
        outcome,
        review_note,
        html.escape(json_output)
    )


def manual_items(results, context):
    items = list(context["manual_items"])

    for result in results:
        if result.outcome == "review":
            items.append({
                "title": result.title,
                "command": result.command,
                "reason": result.error,
                "steps": result.steps
            })

    items.append({
        "title": "Concourse daily maintenance certificate pipeline",
        "command": "Manual Concourse validation",
        "reason": "This pipeline is intentionally not triggered by the script.",
        "steps": [
            "Open Concourse and choose Daily Maintenance for the selected environment.",
            "Run the Check Certificate pipeline.",
            "Confirm the pipeline completes successfully.",
            "Attach the successful build URL to the change record."
        ]
    })

    return items


def render_manual(item):
    steps = "".join([
        "<li>{0}</li>".format(html.escape(step))
        for step in item["steps"]
    ])

    return """
    <article class="manual-card">
      <div class="manual-card-title">
        <span>Follow-up</span>
        <h3>{0}</h3>
      </div>

      <p class="manual-command">{1}</p>
      <p class="manual-reason">{2}</p>

      <ol>{3}</ol>
    </article>
    """.format(
        html.escape(item["title"]),
        html.escape(item["command"]),
        html.escape(item["reason"]),
        steps
    )


HTML_TEMPLATE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vault Validation Report - $environment</title>
<style>
:root {
  --navy: #071c35;
  --navy-light: #0f3156;
  --teal: #00958f;
  --teal-soft: #dff6f3;
  --gold: #d59527;
  --gold-soft: #fff2d7;
  --ink: #183047;
  --muted: #62788c;
  --surface: #ffffff;
  --canvas: #edf4f7;
  --line: #d8e4ea;
  --shadow: 0 12px 30px rgba(25,49,70,.09);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  color: var(--ink);
  background:
    radial-gradient(circle at 0% 0%, #d7f3ef 0%, transparent 30%),
    radial-gradient(circle at 100% 0%, #faead0 0%, transparent 28%),
    var(--canvas);
  font-family: Georgia, "Times New Roman", serif;
}
.wrap { width: min(1240px, 94%); margin: 0 auto; }
header {
  position: relative;
  overflow: hidden;
  padding: 48px 0 40px;
  color: #fff;
  background: linear-gradient(125deg, var(--navy), #0a2847 54%, #105560);
  border-bottom: 6px solid var(--teal);
}
header:after {
  position: absolute;
  top: -180px;
  right: -90px;
  width: 440px;
  height: 440px;
  content: "";
  border: 1px solid rgba(255,255,255,.13);
  border-radius: 50%;
  box-shadow:
    0 0 0 48px rgba(255,255,255,.04),
    0 0 0 96px rgba(255,255,255,.025);
}
.header-content { position: relative; z-index: 1; }
.eyebrow {
  margin: 0 0 8px;
  color: #91e7e1;
  font: 700 11px Arial,sans-serif;
  letter-spacing: .18em;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-size: 38px;
  font-weight: normal;
}
.header-meta {
  margin: 10px 0 0;
  color: #c6d9e8;
  font: 14px Arial,sans-serif;
}
.score-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 17px;
  margin-top: 30px;
}
.score-card {
  min-width: 245px;
  padding: 18px 21px;
  border: 1px solid rgba(191,226,239,.34);
  background: rgba(255,255,255,.08);
}
.score-card span {
  display: block;
  color: #b8d8e9;
  font: 700 10px Arial,sans-serif;
  letter-spacing: .14em;
  text-transform: uppercase;
}
.score-card strong {
  display: block;
  margin-top: 3px;
  font-size: 38px;
  font-weight: normal;
}
main { padding: 38px 0 52px; }
section { margin-bottom: 42px; }
.section-heading {
  display: flex;
  gap: 14px;
  align-items: baseline;
  margin-bottom: 18px;
  padding-bottom: 10px;
  border-bottom: 2px solid var(--ink);
}
.section-heading h2 {
  margin: 0;
  font-size: 28px;
  font-weight: normal;
}
.section-heading span {
  color: var(--muted);
  font: 700 10px Arial,sans-serif;
  letter-spacing: .15em;
  text-transform: uppercase;
}
.cluster-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
}
.cluster-card {
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--line);
  box-shadow: var(--shadow);
}
.primary-cluster { border-top: 5px solid var(--teal); }
.dr-cluster { border-top: 5px solid var(--gold); }
.cluster-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 20px;
  color: #fff;
  background: var(--navy);
}
.cluster-card-head span {
  color: #c8dcea;
  font: 700 10px Arial,sans-serif;
  letter-spacing: .13em;
  text-transform: uppercase;
}
.cluster-card-head strong {
  font: normal 21px Georgia,serif;
}
.overview-row {
  display: flex;
  gap: 18px;
  justify-content: space-between;
  padding: 14px 20px;
  border-top: 1px solid #e5edf1;
}
.overview-row strong {
  display: block;
  font: 700 12px Arial,sans-serif;
}
.overview-row span {
  display: block;
  margin-top: 3px;
  color: var(--muted);
  font: 11px Arial,sans-serif;
}
.overview-row b {
  max-width: 52%;
  color: #23435d;
  text-align: right;
  font: 600 12px Arial,sans-serif;
  overflow-wrap: anywhere;
}
.context-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  overflow: hidden;
  background: var(--surface);
  border: 1px solid var(--line);
  box-shadow: var(--shadow);
}
.context-item {
  min-height: 97px;
  padding: 19px 21px;
  border-right: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}
.context-item:nth-child(3n) { border-right: 0; }
.context-item span {
  display: block;
  color: var(--muted);
  font: 700 10px Arial,sans-serif;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.context-item strong {
  display: block;
  margin-top: 8px;
  color: var(--navy-light);
  font: 16px Georgia,serif;
  overflow-wrap: anywhere;
}
.validation-card {
  margin: 13px 0;
  padding: 21px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 5px solid var(--teal);
  box-shadow: 0 7px 18px rgba(17,44,65,.06);
}
.validation-card.review { border-left-color: var(--gold); }
.validation-head {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  justify-content: space-between;
}
.validation-title {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}
.validation-number {
  padding-top: 3px;
  color: var(--teal);
  font: 700 12px Arial,sans-serif;
  letter-spacing: .1em;
}
.review .validation-number { color: var(--gold); }
.validation-title h3 {
  margin: 0;
  font-size: 20px;
  font-weight: normal;
}
.validation-title p {
  margin: 6px 0 0;
  color: var(--muted);
  font: 12px Consolas,"Courier New",monospace;
  overflow-wrap: anywhere;
}
.validation-outcome {
  flex: 0 0 auto;
  padding: 6px 9px;
  border-radius: 3px;
  font: 700 10px Arial,sans-serif;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.validation-outcome.captured {
  color: #006760;
  background: var(--teal-soft);
}
.validation-outcome.review {
  color: #8a5100;
  background: var(--gold-soft);
}
.review-note {
  display: flex;
  gap: 9px;
  margin: 16px 0;
  padding: 11px 13px;
  color: #815002;
  background: #fff7e8;
  border-left: 3px solid var(--gold);
  font: 13px Arial,sans-serif;
}
.evidence-panel { margin-top: 17px; }
.evidence-panel summary {
  cursor: pointer;
  color: var(--navy-light);
  font: 700 12px Arial,sans-serif;
}
.evidence-panel pre {
  max-height: 350px;
  overflow: auto;
  margin: 12px 0 0;
  padding: 16px;
  color: #e7f1f7;
  background: #0d2743;
  border-radius: 3px;
  font: 12px/1.55 Consolas,"Courier New",monospace;
  white-space: pre;
}
.manual-section {
  padding: 26px;
  background: #fff9ed;
  border: 1px solid #efd8a7;
}
.manual-card {
  padding: 20px 0;
  border-top: 1px solid #ead6ad;
}
.manual-card:first-of-type {
  padding-top: 0;
  border-top: 0;
}
.manual-card-title {
  display: flex;
  gap: 10px;
  align-items: baseline;
}
.manual-card-title span {
  color: #8c570b;
  font: 700 10px Arial,sans-serif;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.manual-card-title h3 {
  margin: 0;
  color: #623d05;
  font-size: 19px;
  font-weight: normal;
}
.manual-command {
  margin: 10px 0 7px;
  color: #70542a;
  font: 12px Consolas,"Courier New",monospace;
  overflow-wrap: anywhere;
}
.manual-reason {
  margin: 0;
  color: #76592d;
  font: 13px Arial,sans-serif;
}
.manual-card ol {
  margin: 12px 0 0 22px;
  padding: 0;
  color: #294057;
  font: 14px Arial,sans-serif;
}
.manual-card li { margin: 6px 0; }
footer {
  padding: 24px;
  color: var(--muted);
  text-align: center;
  font: 12px Arial,sans-serif;
}
@media (max-width: 800px) {
  .cluster-grid,
  .context-grid {
    grid-template-columns: 1fr;
  }
  .context-item,
  .context-item:nth-child(3n) {
    border-right: 0;
  }
}
@media (max-width: 620px) {
  h1 { font-size: 30px; }
  .score-card { width: 100%; }
  .validation-head { display: block; }
  .validation-outcome {
    display: inline-block;
    margin-top: 12px;
  }
  .overview-row { display: block; }
  .overview-row b {
    display: block;
    max-width: 100%;
    margin-top: 6px;
    text-align: left;
  }
}
</style>
</head>
<body>
<header>
  <div class="wrap header-content">
    <p class="eyebrow">Vault AMI Validation</p>
    <h1>$environment</h1>
    <p class="header-meta">
      Run label: $label | Generated: $timestamp UTC
    </p>
    <div class="score-grid">
      <div class="score-card">
        <span>Primary score</span>
        <strong>$primary_score / $primary_total</strong>
      </div>
      <div class="score-card">
        <span>DR score</span>
        <strong>$dr_score / $dr_total</strong>
      </div>
    </div>
  </div>
</header>

<main class="wrap">
  <section>
    <div class="section-heading">
      <h2>Cluster Overview</h2>
      <span>Primary and DR posture</span>
    </div>
    $cluster_overview
  </section>

  <section>
    <div class="section-heading">
      <h2>Run Context</h2>
      <span>Execution details</span>
    </div>
    $run_context
  </section>

  <section>
    <div class="section-heading">
      <h2>Primary Validation Results</h2>
      <span>Command evidence</span>
    </div>
    $primary_cards
  </section>

  <section>
    <div class="section-heading">
      <h2>DR Validation Results</h2>
      <span>Command evidence</span>
    </div>
    $dr_cards
  </section>

  <section class="manual-section">
    <div class="section-heading">
      <h2>Manual Verification Required</h2>
      <span>Follow-up actions</span>
    </div>
    $manual_cards
  </section>
</main>

<footer>
  Vault AMI validation report. Token and cloud credential values are redacted.
</footer>
</body>
</html>
""")


def create_report(results, context):
    primary_results = [
        result for result in results
        if result.section == "Primary"
    ]

    dr_results = [
        result for result in results
        if result.section == "DR"
    ]

    primary_verified, primary_total = score(results, "Primary")
    dr_verified, dr_total = score(results, "DR")

    primary_cards = "".join([
        render_card(result, index + 1)
        for index, result in enumerate(primary_results)
    ])

    dr_cards = "".join([
        render_card(result, index + 1)
        for index, result in enumerate(dr_results)
    ])

    manual_cards = "".join([
        render_manual(item)
        for item in manual_items(results, context)
    ])

    return HTML_TEMPLATE.substitute(
        environment=html.escape(context["environment"]),
        label=html.escape(context["label"]),
        timestamp=html.escape(context["timestamp"]),
        primary_score=primary_verified,
        primary_total=primary_total,
        dr_score=dr_verified,
        dr_total=dr_total,
        cluster_overview=cluster_overview(results, context),
        run_context=render_run_context(context),
        primary_cards=primary_cards,
        dr_cards=dr_cards,
        manual_cards=manual_cards
    )


def save_report(content, context):
    output_directory = os.path.join(
        REPORT_ROOT,
        context["environment"]
    )

    if not os.path.isdir(output_directory):
        os.makedirs(output_directory)

    filename = "vault_ami_validation_{0}_{1}.html".format(
        context["environment"],
        context["timestamp"]
    )

    report_path = os.path.join(output_directory, filename)

    with open(report_path, "w") as report_file:
        report_file.write(content)

    return report_path


def main():
    print("Vault AMI Validation")
    print(
        "This script is read-only except for one uniquely named validation secret."
    )

    try:
        context = build_context()
        results = run_checks(context)
        report_path = save_report(
            create_report(results, context),
            context
        )

        primary_verified, primary_total = score(results, "Primary")
        dr_verified, dr_total = score(results, "DR")

        print("\nReport created:")
        print(report_path)
        print("Primary score: {0}/{1}".format(
            primary_verified,
            primary_total
        ))
        print("DR score: {0}/{1}".format(
            dr_verified,
            dr_total
        ))

    except ValidationError as exc:
        print("\nUnable to start validation: {0}".format(exc))
        sys.exit(2)

    except KeyboardInterrupt:
        print("\nValidation cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
