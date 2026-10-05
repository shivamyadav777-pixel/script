#!/usr/bin/env python
# vault_ami_validation.py
# Python 3.5 compatible. Run inside approved Dojo only.

from __future__ import print_function

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


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "vault_validation_config.json")
REPORT_DIR = os.path.join(BASE_DIR, "reports")


class ValidationError(Exception):
    pass


class CommandError(Exception):
    pass


class Result(object):
    def __init__(self, section, title, command, condition, steps,
                 counts_only=False):
        self.section = section
        self.title = title
        self.command = command
        self.condition = condition
        self.steps = steps
        self.counts_only = counts_only
        self.outcome = "review"
        self.evidence = None
        self.error = ""


def clean_error(value):
    text = str(value or "").strip()
    return re.sub(
        r"(?i)(token|password|secret|access_key)[=:][^\s,;]+",
        r"\1=***",
        text
    )[:800]


def display_command(command):
    output = []

    for value in command:
        value = str(value)

        if value.startswith("-dr-token="):
            value = "-dr-token=***"

        output.append(value)

    return " ".join(output)


class Runner(object):
    def run(self, command, env, allowed_codes=None, timeout=60):
        if allowed_codes is None:
            allowed_codes = [0]

        command_env = os.environ.copy()
        command_env.update(env)
        command_env["VAULT_FORMAT"] = "json"
        command_env["VAULT_CLI_NO_COLOR"] = "1"

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=command_env
            )
            stdout, stderr = process.communicate(timeout=timeout)

        except OSError as exc:
            raise ValidationError(
                "Unable to start {0}: {1}".format(
                    display_command(command), exc
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
                "{0} - {1}".format(
                    display_command(command),
                    clean_error(stderr)
                )
            )

        return stdout

    def json(self, command, env, allowed_codes=None, retries=1):
        last_error = None

        for attempt in range(retries):
            try:
                return json.loads(
                    self.run(command, env, allowed_codes=allowed_codes)
                )
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


def choose(title, values):
    while True:
        print("\n{0}".format(title))

        for number, value in enumerate(values, 1):
            print("  {0}. {1}".format(number, value))

        try:
            selected = int(input("Choose an option: ").strip())
            if 1 <= selected <= len(values):
                return selected - 1
        except ValueError:
            pass

        print("Enter a valid menu number.")


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


def aws_options():
    selected = choose(
        "AWS S3 snapshot validation",
        [
            "Use existing AWS credentials in Dojo",
            "Enter temporary AWS credentials",
            "Skip AWS credential-dependent checks"
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

    token = getpass.getpass(
        "AWS session token (Enter if not applicable): "
    ).strip()

    if token:
        environment["AWS_SESSION_TOKEN"] = token

    return True, environment, ""


def get_context():
    if not os.path.isfile(CONFIG_FILE):
        raise ValidationError(
            "Configuration file not found: {0}".format(CONFIG_FILE)
        )

    with open(CONFIG_FILE, "r") as input_file:
        config = json.load(input_file)

    names = sorted(config["environments"].keys())
    name = names[choose("Select Vault environment", names)]
    profile = config["environments"][name]

    for key in ["primary_addr", "dr_addr", "test_secret_prefix"]:
        value = str(profile.get(key, "")).strip()

        if not value or "VAULT-ADDRESS" in value:
            raise ValidationError(
                "Set {0} for {1} in vault_validation_config.json.".format(
                    key, name
                )
            )

    label = get_label()

    print("\nTokens remain in memory only and are not saved.")
    primary_token = required_secret("Primary Vault token: ")
    dr_token = required_secret("DR operation token: ")

    aws_enabled = False
    aws_env = {}
    aws_skip_reason = ""

    if profile.get("provider") == "aws":
        aws_enabled, aws_env, aws_skip_reason = aws_options()

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    test_path = "{0}/{1}-{2}-{3}".format(
        profile["test_secret_prefix"].strip("/"),
        datetime.datetime.utcnow().strftime("%Y%m%d"),
        label,
        timestamp
    )

    primary_env = {
        "VAULT_ADDR": profile["primary_addr"],
        "VAULT_TOKEN": primary_token
    }

    dr_env = {
        "VAULT_ADDR": profile["dr_addr"],
        "VAULT_TOKEN": dr_token
    }

    primary_env.update(aws_env)
    dr_env.update(aws_env)

    return {
        "environment": name,
        "profile": profile,
        "label": label,
        "timestamp": timestamp,
        "test_path": test_path,
        "primary_env": primary_env,
        "dr_env": dr_env,
        "dr_token": dr_token,
        "aws_enabled": aws_enabled,
        "aws_skip_reason": aws_skip_reason,
        "manual_items": []
    }


def expect(condition, message):
    if not condition:
        raise ValidationError(message)


def as_bool(value):
    return value is True or str(value).lower() == "true"


def extract_data(value):
    if isinstance(value, dict) and isinstance(value.get("data"), (dict, list)):
        return value["data"]

    return value


def find_first(value, names):
    names = set([name.lower() for name in names])

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names and item not in (None, ""):
                return item

        for item in value.values():
            found = find_first(item, names)
            if found not in (None, ""):
                return found

    if isinstance(value, list):
        for item in value:
            found = find_first(item, names)
            if found not in (None, ""):
                return found

    return None


def all_values(value, names):
    names = set([name.lower() for name in names])
    output = []

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names:
                output.append(item)
            output.extend(all_values(item, names))

    elif isinstance(value, list):
        for item in value:
            output.extend(all_values(item, names))

    return output


def parse_time(value):
    if not value:
        return None

    text = str(value).replace("Z", "+0000")
    text = re.sub(r"([+-]\d\d):(\d\d)$", r"\1\2", text)

    for item_format in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S"
    ]:
        try:
            value = datetime.datetime.strptime(text, item_format)

            if value.tzinfo is None:
                return value.replace(tzinfo=datetime.timezone.utc)

            return value.astimezone(datetime.timezone.utc)

        except ValueError:
            pass

    return None


def make_evidence(output, assessment=None):
    data = {"command_output": output}

    if assessment:
        data["assessment"] = assessment

    return data


def status(runner, env):
    return runner.json(
        ["vault", "status", "-format=json"],
        env,
        allowed_codes=[0, 1, 2, 3, 4]
    )


def check_status(runner, env):
    payload = status(runner, env)

    expect(as_bool(payload.get("initialized")), "Vault is not initialized.")
    expect(not as_bool(payload.get("sealed")), "Vault is sealed.")

    return make_evidence(payload, {
        "initialized": payload.get("initialized"),
        "sealed": payload.get("sealed")
    })


def raft_servers(value):
    if isinstance(value, list):
        matching = [
            item for item in value
            if isinstance(item, dict) and
            "node_id" in item and
            "address" in item and
            "leader" in item and
            "voter" in item
        ]

        if matching:
            return matching

        for item in value:
            found = raft_servers(item)
            if found:
                return found

    elif isinstance(value, dict):
        for item in value.values():
            found = raft_servers(item)
            if found:
                return found

    return []


def check_raft(runner, env, dr_token=None):
    command = [
        "vault", "operator", "raft", "list-peers", "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    payload = runner.json(command, env)
    servers = raft_servers(extract_data(payload))

    expect(bool(servers), "Raft JSON output did not contain servers.")

    leaders = [item for item in servers if as_bool(item.get("leader"))]
    followers = [item for item in servers if not as_bool(item.get("leader"))]
    voters = [item for item in servers if as_bool(item.get("voter"))]

    expect(len(servers) == 5, "Expected 5 Raft peers; found {0}.".format(
        len(servers)
    ))
    expect(len(leaders) == 1, "Expected 1 Raft leader.")
    expect(len(followers) == 4, "Expected 4 Raft followers.")
    expect(len(voters) == 5, "Expected 5 Raft voters.")

    return make_evidence(payload, {
        "peer_count": len(servers),
        "leader_count": len(leaders),
        "follower_count": len(followers),
        "voter_count": len(voters)
    })


def check_autopilot(runner, env, dr_token=None):
    command = [
        "vault", "operator", "raft", "autopilot", "get-config",
        "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    return make_evidence(runner.json(command, env))


def check_write(runner, context):
    command = [
        "vault", "write", "-format=json",
        context["test_path"], "Test=success"
    ]

    output = runner.run(command, context["primary_env"])

    try:
        response = json.loads(output) if output.strip() else {}
    except ValueError:
        response = {"message": output.strip()}

    if not response:
        response = {
            "message": "Vault accepted the write with no response body."
        }

    return make_evidence(response, {
        "validation_path": context["test_path"],
        "write_command_completed": True
    })


def find_test(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() == "test":
                return item

            found = find_test(item)
            if found is not None:
                return found

    elif isinstance(value, list):
        for item in value:
            found = find_test(item)
            if found is not None:
                return found

    return None


def check_read(runner, context):
    payload = runner.json(
        ["vault", "read", "-format=json", context["test_path"]],
        context["primary_env"]
    )

    value = find_test(payload)

    expect(
        str(value).lower() == "success",
        "Expected Test=success; got {0}.".format(value)
    )

    return make_evidence(payload, {
        "validation_path": context["test_path"],
        "Test": value
    })


def check_snapshot_config(runner, context):
    payload = runner.json(
        [
            "vault", "read", "-format=json",
            "sys/storage/raft/snapshot-auto/config/s3"
        ],
        context["primary_env"],
        retries=3
    )

    interval = find_first(
        extract_data(payload),
        ["interval", "snapshot_interval"]
    )

    expected = int(
        context["profile"].get("snapshot_interval_seconds", 1800)
    )

    expect(interval is not None, "Snapshot interval was not found.")
    expect(
        int(interval) == expected,
        "Expected interval {0}; found {1}.".format(expected, interval)
    )

    return make_evidence(payload, {
        "expected_interval_seconds": expected,
        "reported_interval_seconds": interval
    })


def check_snapshot_status(runner, context):
    payload = runner.json(
        [
            "vault", "read", "-format=json",
            "sys/storage/raft/snapshot-auto/status/s3"
        ],
        context["primary_env"],
        retries=3
    )

    data = extract_data(payload)

    latest_text = find_first(data, [
        "last_snapshot_time",
        "last_snapshot",
        "last_successful_snapshot"
    ])

    latest = parse_time(latest_text)

    expect(latest is not None, "Latest snapshot timestamp was not found.")

    max_age = int(
        context["profile"].get("snapshot_max_age_seconds", 2400)
    )

    age = (
        datetime.datetime.now(datetime.timezone.utc) - latest
    ).total_seconds()

    expect(
        age <= max_age,
        "Latest snapshot is {0:.0f} seconds old.".format(age)
    )

    return make_evidence(payload, {
        "latest_snapshot": latest_text,
        "next_snapshot": find_first(
            data,
            ["next_snapshot_time", "next_snapshot"]
        ),
        "age_seconds": int(age),
        "maximum_age_seconds": max_age
    })


def check_replication(runner, env, expected_mode, expected_state):
    payload = runner.json(
        ["vault", "read", "-format=json", "sys/replication/status"],
        env
    )

    data = extract_data(payload)
    dr_data = data.get("dr", data) if isinstance(data, dict) else data

    mode = find_first(dr_data, ["mode"])
    state = find_first(dr_data, ["state"])

    raw_connections = all_values(
        dr_data,
        ["connection_state", "connection_status"]
    )

    connections = []

    for item in raw_connections:
        if isinstance(item, list):
            connections.extend([
                str(value).lower() for value in item
                if value not in (None, "")
            ])
        elif item not in (None, ""):
            connections.append(str(item).lower())

    expect(str(mode).lower() == expected_mode, "Unexpected DR mode.")
    expect(str(state).lower() == expected_state, "Unexpected DR state.")
    expect(bool(connections), "Replication connection state not found.")

    valid = ["connected"]

    if expected_mode == "secondary":
        valid.append("ready")

    expect(
        all(value in valid for value in connections),
        "Unexpected connection state: {0}.".format(
            ", ".join(connections)
        )
    )

    return make_evidence(payload, {
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

    keys = [
        "hostname", "host_name", "api_address",
        "cluster_address", "active_node", "last_echo"
    ]

    if any(key in value for key in keys):
        return [value]

    output = []

    for item in value.values():
        output.extend(member_records(item))

    return output


def check_members(runner, context):
    payload = runner.json(
        ["vault", "operator", "members", "-format=json"],
        context["primary_env"]
    )

    members = member_records(extract_data(payload))
    active = [
        item for item in members if as_bool(item.get("active_node"))
    ]

    expect(bool(members), "No operator member list was returned.")
    expect(len(members) == 5, "Expected 5 members; found {0}.".format(
        len(members)
    ))
    expect(len(active) == 1, "Expected 1 active operator member.")

    return make_evidence(payload, {
        "member_count": len(members),
        "active_member_count": len(active)
    })


def check_inventory(runner, context):
    secrets = extract_data(runner.json(
        ["vault", "secrets", "list", "-format=json"],
        context["primary_env"]
    ))

    auth = extract_data(runner.json(
        ["vault", "auth", "list", "-format=json"],
        context["primary_env"]
    ))

    policies = extract_data(runner.json(
        ["vault", "policy", "list", "-format=json"],
        context["primary_env"]
    ))

    if isinstance(policies, dict):
        policies = policies.get("keys", [])

    return {
        "secret_mount_count": len(secrets)
        if isinstance(secrets, dict) else 0,

        "auth_mount_count": len(auth)
        if isinstance(auth, dict) else 0,

        "policy_count": len(policies)
        if isinstance(policies, list) else 0
    }


def check_license(runner, context):
    payload = runner.json(
        ["vault", "license", "get", "-format=json"],
        context["primary_env"]
    )

    expiration_text = find_first(
        payload,
        ["expiration_time", "expiration"]
    )

    expiration = parse_time(expiration_text)

    expect(expiration is not None, "License expiration was not found.")

    days = (
        expiration - datetime.datetime.now(datetime.timezone.utc)
    ).total_seconds() / 86400.0

    expect(days >= 60, "License expires in {0:.0f} days.".format(days))

    return make_evidence(payload, {
        "expiration_time": expiration_text,
        "days_remaining": int(days)
    })


def check_audit(runner, context):
    payload = runner.json(
        [
            "vault", "audit", "list",
            "-detailed", "-format=json"
        ],
        context["primary_env"]
    )

    return make_evidence(payload)


def check_cloud_snapshots(runner, context):
    bucket = context["profile"].get("snapshot_bucket", "")
    prefix = context["profile"].get("snapshot_prefix", "")

    expect(
        bucket and "SNAPSHOT-BUCKET" not in bucket,
        "Snapshot bucket is not configured."
    )

    if context["profile"]["provider"] == "aws":
        command = [
            "aws", "s3api", "list-objects-v2",
            "--bucket", bucket,
            "--prefix", prefix,
            "--output", "json",
            "--query",
            "reverse(sort_by(Contents,&LastModified))[:3]."
            "{Key:Key,LastModified:LastModified,Size:Size}"
        ]

        payload = runner.json(command, context["primary_env"])

    else:
        payload = runner.json(
            [
                "gcloud", "storage", "objects", "list",
                "gs://{0}/{1}".format(bucket, prefix),
                "--format=json",
                "--sort-by=~updateTime",
                "--limit=3"
            ],
            context["primary_env"]
        )

    snapshots = payload if isinstance(payload, list) else payload.get(
        "Contents", []
    )

    expect(bool(snapshots), "No raft snapshots found.")

    return make_evidence(payload, {
        "snapshot_count_returned": len(snapshots)
    })


def check_version(runner, env):
    payload = status(runner, env)
    version = find_first(payload, ["version"])

    expect(bool(version), "Vault version was not found.")
    return make_evidence(payload, {"version": version})


def check_recovery(runner, env):
    payload = status(runner, env)

    shares = find_first(payload, [
        "recovery_seal_shares",
        "total_recovery_shares",
        "recovery_shares",
        "n"
    ])

    threshold = find_first(payload, [
        "recovery_seal_threshold",
        "recovery_threshold",
        "t"
    ])

    expect(shares is not None, "Recovery shares not found in vault status.")
    expect(
        threshold is not None,
        "Recovery threshold not found in vault status."
    )

    return make_evidence(payload, {
        "source": "vault status -format=json",
        "total_recovery_shares": shares,
        "recovery_threshold": threshold
    })


def check_tls(address):
    parsed = urlparse(address)
    hostname = parsed.hostname
    port = parsed.port or 443

    expect(bool(hostname), "Invalid Vault address.")

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=15) as raw:
            with context.wrap_socket(
                raw,
                server_hostname=hostname
            ) as secure:
                certificate = secure.getpeercert()

    except (socket.error, ssl.SSLError) as exc:
        raise ValidationError("TLS validation failed: {0}".format(exc))

    expiry = certificate.get("notAfter")
    expiry_epoch = ssl.cert_time_to_seconds(expiry)
    days = (expiry_epoch - time.time()) / 86400.0

    expect(days >= 60, "TLS certificate expires in {0:.0f} days.".format(
        days
    ))

    return {
        "host": hostname,
        "port": port,
        "certificate_expiry": expiry,
        "days_remaining": int(days)
    }


def execute(results, section, title, command, condition, steps, callback,
            counts_only=False):
    result = Result(
        section, title, command, condition, steps, counts_only
    )

    try:
        result.evidence = callback()
        result.outcome = "verified"

    except (ValidationError, CommandError) as exc:
        result.error = clean_error(exc)

    except Exception as exc:
        result.error = "Unexpected validation error: {0}".format(
            clean_error(exc)
        )

    results.append(result)


def run_validations(context):
    runner = Runner()
    results = []

    # Critical token validation. Stop only if the Primary token is invalid.
    runner.json(
        ["vault", "token", "lookup", "-format=json"],
        context["primary_env"]
    )

    primary = context["primary_env"]
    dr = context["dr_env"]
    path = context["test_path"]

    checks = [
        ("Primary", "Vault status (Primary)",
         "vault status -format=json",
         "Initialized is true and Sealed is false.",
         ["Confirm Initialized is true and Sealed is false."],
         lambda: check_status(runner, primary), False),

        ("Primary", "Raft list-peers (Primary)",
         "vault operator raft list-peers -format=json",
         "5 peers: 1 leader, 4 followers, and all 5 are voters.",
         ["Confirm 1 leader, 4 followers, and 5 voters."],
         lambda: check_raft(runner, primary), False),

        ("Primary", "Raft autopilot configuration (Primary)",
         "vault operator raft autopilot get-config -format=json",
         "Autopilot configuration JSON is retrieved successfully.",
         ["Compare output with approved configuration."],
         lambda: check_autopilot(runner, primary), False),

        ("Primary", "Validation secret write (Primary)",
         "vault write -format=json {0} Test=success".format(path),
         "Vault accepts Test=success at the generated validation path.",
         ["Confirm token write access to the validation path."],
         lambda: check_write(runner, context), False),

        ("Primary", "Validation secret read (Primary)",
         "vault read -format=json {0}".format(path),
         "The generated validation path returns Test=success.",
         ["Confirm Test=success is returned."],
         lambda: check_read(runner, context), False),

        ("Primary", "Snapshot configuration (Primary)",
         "vault read -format=json "
         "sys/storage/raft/snapshot-auto/config/s3",
         "Configured snapshot interval matches the environment baseline.",
         ["Confirm snapshot interval matches the baseline."],
         lambda: check_snapshot_config(runner, context), False),

        ("Primary", "Snapshot runtime status (Primary)",
         "vault read -format=json "
         "sys/storage/raft/snapshot-auto/status/s3",
         "Latest snapshot is within the configured age limit.",
         ["Retry after five minutes if required."],
         lambda: check_snapshot_status(runner, context), False),

        ("Primary", "DR replication state (Primary)",
         "vault read -format=json sys/replication/status",
         "Mode is primary, state is running, and connections are connected.",
         ["Confirm Primary DR replication is healthy."],
         lambda: check_replication(runner, primary, "primary", "running"),
         False),

        ("Primary", "Operator members (Primary)",
         "vault operator members -format=json",
         "5 members are listed and exactly 1 member is active.",
         ["Confirm active node and expected peers are shown."],
         lambda: check_members(runner, context), False),

        ("Primary", "Vault inventory counts (Primary)",
         "vault secrets list -format=json; vault auth list -format=json; "
         "vault policy list -format=json",
         "Secret mount, auth mount, and policy counts are retrieved.",
         ["Compare counts with the approved baseline."],
         lambda: check_inventory(runner, context), True),

        ("Primary", "Vault license (Primary)",
         "vault license get -format=json",
         "License expiration is at least 60 days away.",
         ["Confirm license expiration date."],
         lambda: check_license(runner, context), False),

        ("Primary", "Audit devices (Primary)",
         "vault audit list -detailed -format=json",
         "Detailed audit-device configuration is retrieved.",
         ["Confirm approved audit devices remain configured."],
         lambda: check_audit(runner, context), False),

        ("Primary", "Vault version (Primary)",
         "vault status -format=json",
         "A Primary Vault version is returned.",
         ["Confirm version matches approved AMI release."],
         lambda: check_version(runner, primary), False),

        ("Primary", "Recovery shares and threshold (Primary)",
         "vault status -format=json",
         "Recovery shares and threshold are returned by vault status.",
         ["Confirm shares and threshold match approved recovery design."],
         lambda: check_recovery(runner, primary), False),

        ("Primary", "TLS certificate (Primary)",
         "TLS handshake to Primary Vault address",
         "Certificate expiry is at least 60 days away.",
         ["Confirm certificate expiry date."],
         lambda: check_tls(context["profile"]["primary_addr"]), False),

        ("DR", "Vault status (DR)",
         "vault status -format=json",
         "Initialized is true and Sealed is false.",
         ["Confirm Initialized is true and Sealed is false."],
         lambda: check_status(runner, dr), False),

        ("DR", "Raft list-peers (DR)",
         "vault operator raft list-peers -format=json -dr-token=***",
         "5 peers: 1 leader, 4 followers, and all 5 are voters.",
         ["Confirm DR has 1 leader, 4 followers, and 5 voters."],
         lambda: check_raft(runner, dr, context["dr_token"]), False),

        ("DR", "Raft autopilot configuration (DR)",
         "vault operator raft autopilot get-config "
         "-format=json -dr-token=***",
         "Autopilot configuration JSON is retrieved successfully.",
         ["Compare output with approved DR configuration."],
         lambda: check_autopilot(runner, dr, context["dr_token"]), False),

        ("DR", "DR replication state (DR)",
         "vault read -format=json sys/replication/status",
         "Mode is secondary, state is stream-wals, and connection is ready.",
         ["Confirm remote WAL continues advancing."],
         lambda: check_replication(runner, dr, "secondary", "stream-wals"),
         False),

        ("DR", "Vault version (DR)",
         "vault status -format=json",
         "A DR Vault version is returned.",
         ["Confirm version matches approved AMI release."],
         lambda: check_version(runner, dr), False),

        ("DR", "Recovery shares and threshold (DR)",
         "vault status -format=json",
         "Recovery shares and threshold are returned by vault status.",
         ["Confirm shares and threshold match approved recovery design."],
         lambda: check_recovery(runner, dr), False),

        ("DR", "TLS certificate (DR)",
         "TLS handshake to DR Vault address",
         "Certificate expiry is at least 60 days away.",
         ["Confirm certificate expiry date."],
         lambda: check_tls(context["profile"]["dr_addr"]), False)
    ]

    if context["profile"].get("provider") != "aws" or context["aws_enabled"]:
        checks.insert(
            12,
            (
                "Primary", "Latest raft snapshots (Primary)",
                "aws s3api list-objects-v2 --bucket <configured-bucket> "
                "--prefix <configured-prefix> --output json",
                "Latest 3 raft snapshots are found in cloud storage.",
                ["Confirm latest snapshot timestamps are after AMI activity."],
                lambda: check_cloud_snapshots(runner, context),
                False
            )
        )
    else:
        context["manual_items"].append({
            "title": "Latest raft snapshots (Primary)",
            "command": "aws s3api list-objects-v2 --bucket "
            "<configured-bucket> --prefix <configured-prefix> --output json",
            "reason": context["aws_skip_reason"],
            "steps": [
                "Open the configured S3 bucket and raft-snapshots prefix.",
                "Confirm latest three snapshot timestamps are after AMI activity."
            ]
        })

    for index, item in enumerate(checks, 1):
        print("[{0}/{1}] {2}".format(index, len(checks), item[1]))
        execute(
            results, item[0], item[1], item[2],
            item[3], item[4], item[5], item[6]
        )

    return results


def redact(value, key=""):
    sensitive = [
        "token", "password", "secret_id",
        "access_key", "private_key"
    ]

    if any(item in str(key).lower() for item in sensitive):
        return "***"

    if isinstance(value, dict):
        return dict(
            (name, redact(item, name))
            for name, item in value.items()
        )

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


def pretty_json(value):
    return json.dumps(
        redact(value),
        indent=2,
        sort_keys=True,
        default=str
    )


def score(results, section):
    items = [item for item in results if item.section == section]
    good = [item for item in items if item.outcome == "verified"]
    return len(good), len(items)


def find_result(results, title):
    for result in results:
        if result.title == title:
            return result
    return None


def assessment(results, title, key, default="Not reported"):
    result = find_result(results, title)

    if not result or not isinstance(result.evidence, dict):
        return default

    data = result.evidence.get("assessment", {})

    if not isinstance(data, dict):
        return default

    return str(data.get(key, default))


def state(results, title):
    result = find_result(results, title)

    if result and result.outcome == "verified":
        return "Evidence captured"

    return "Manual review"


def overview_row(label, value, detail=""):
    return """
    <div class="row">
      <div><b>{0}</b><small>{1}</small></div>
      <strong>{2}</strong>
    </div>
    """.format(
        html.escape(label),
        html.escape(detail),
        html.escape(str(value))
    )


def cluster_overview(results, context):
    primary = "".join([
        overview_row("Vault endpoint", context["profile"]["primary_addr"]),
        overview_row(
            "Vault status",
            state(results, "Vault status (Primary)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment(results, "Vault status (Primary)", "initialized"),
                assessment(results, "Vault status (Primary)", "sealed")
            )
        ),
        overview_row(
            "Raft topology",
            state(results, "Raft list-peers (Primary)"),
            "{0} peers | {1} leader | {2} followers".format(
                assessment(results, "Raft list-peers (Primary)", "peer_count"),
                assessment(results, "Raft list-peers (Primary)", "leader_count"),
                assessment(results, "Raft list-peers (Primary)", "follower_count")
            )
        ),
        overview_row(
            "Replication",
            state(results, "DR replication state (Primary)"),
            "Mode: {0} | State: {1}".format(
                assessment(results, "DR replication state (Primary)", "mode"),
                assessment(results, "DR replication state (Primary)", "state")
            )
        )
    ])

    dr = "".join([
        overview_row("Vault endpoint", context["profile"]["dr_addr"]),
        overview_row(
            "Vault status",
            state(results, "Vault status (DR)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment(results, "Vault status (DR)", "initialized"),
                assessment(results, "Vault status (DR)", "sealed")
            )
        ),
        overview_row(
            "Raft topology",
            state(results, "Raft list-peers (DR)"),
            "{0} peers | {1} leader | {2} followers".format(
                assessment(results, "Raft list-peers (DR)", "peer_count"),
                assessment(results, "Raft list-peers (DR)", "leader_count"),
                assessment(results, "Raft list-peers (DR)", "follower_count")
            )
        ),
        overview_row(
            "Replication",
            state(results, "DR replication state (DR)"),
            "Mode: {0} | State: {1}".format(
                assessment(results, "DR replication state (DR)", "mode"),
                assessment(results, "DR replication state (DR)", "state")
            )
        )
    ])

    return """
    <div class="clusters">
      <article><header>Primary Cluster</header>{0}</article>
      <article><header>DR Cluster</header>{1}</article>
    </div>
    """.format(primary, dr)


def render_context(context):
    cloud = "Included"

    if context["profile"].get("provider") == "aws" and not context["aws_enabled"]:
        cloud = "Manual verification required"

    values = [
        ("Environment", context["environment"]),
        ("Provider", context["profile"].get("provider", "").upper()),
        ("Validation label", context["label"]),
        ("Generated UTC", context["timestamp"]),
        ("Test secret path", context["test_path"]),
        ("Snapshot validation", cloud)
    ]

    return "".join([
        """
        <div class="context">
          <span>{0}</span>
          <strong>{1}</strong>
        </div>
        """.format(html.escape(label), html.escape(str(value)))
        for label, value in values
    ])


def render_card(result, number):
    style = "good" if result.outcome == "verified" else "review"
    note = ""

    if result.outcome != "verified":
        note = """
        <div class="note"><b>Review note:</b> {0}</div>
        """.format(html.escape(result.error))

    return """
    <article class="check {0}">
      <div class="check-head">
        <div>
          <span class="number">{1:02d}</span>
          <h3>{2}</h3>
          <p>{3}</p>
        </div>
      </div>
      <div class="condition">
        <span>Outcome</span>
        <strong>{4}</strong>
      </div>
      {5}
      <details open>
        <summary>View JSON evidence</summary>
        <pre>{6}</pre>
      </details>
    </article>
    """.format(
        style,
        number,
        html.escape(result.title),
        html.escape(result.command),
        html.escape(result.condition),
        note,
        html.escape(pretty_json(result.evidence))
    )


def manual_cards(results, context):
    items = list(context["manual_items"])

    for result in results:
        if result.outcome != "verified":
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
            "Open Concourse Daily Maintenance for the selected environment.",
            "Run the Check Certificate pipeline.",
            "Confirm the pipeline succeeds.",
            "Attach the successful build URL to the change record."
        ]
    })

    output = ""

    for item in items:
        steps = "".join([
            "<li>{0}</li>".format(html.escape(step))
            for step in item["steps"]
        ])

        output += """
        <article class="manual">
          <h3>{0}</h3>
          <code>{1}</code>
          <p>{2}</p>
          <ol>{3}</ol>
        </article>
        """.format(
            html.escape(item["title"]),
            html.escape(item["command"]),
            html.escape(item["reason"]),
            steps
        )

    return output


HTML = Template("""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vault Validation - $environment</title>
<style>
:root{--navy:#071c35;--teal:#008f88;--gold:#bf7912;--ink:#193047;--muted:#60758a;--line:#d8e4ea;--paper:#eef5f7}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Georgia,serif}.wrap{width:min(1220px,94%);margin:auto}
body>header{padding:46px 0;background:linear-gradient(120deg,#071c35,#0b3458,#0c5b60);border-bottom:6px solid var(--teal);color:#fff}.eyebrow{color:#8fe9e1;font:700 11px Arial;letter-spacing:.16em;text-transform:uppercase}h1{margin:7px 0;font-size:38px;font-weight:normal}.meta{font:14px Arial;color:#c9dfeb}.scores{display:flex;gap:16px;margin-top:27px}.score{min-width:235px;padding:17px 20px;border:1px solid #51809a;background:#ffffff12}.score span,.context span{display:block;font:700 10px Arial;letter-spacing:.12em;text-transform:uppercase}.score span{color:#c9e2ee}.score strong{display:block;font-size:36px;font-weight:normal}main{padding:35px 0}.heading{display:flex;gap:12px;align-items:baseline;border-bottom:2px solid var(--ink);margin:35px 0 18px;padding-bottom:10px}.heading h2{margin:0;font-size:28px;font-weight:normal}.heading span{color:var(--muted);font:700 10px Arial;letter-spacing:.12em;text-transform:uppercase}.clusters{display:grid;grid-template-columns:1fr 1fr;gap:20px}.clusters article,.context-grid,.check{background:#fff;border:1px solid var(--line);box-shadow:0 8px 20px #19304712}.clusters header{padding:16px 19px;background:var(--navy);color:#fff;font:normal 20px Georgia}.row{display:flex;justify-content:space-between;gap:20px;padding:13px 19px;border-top:1px solid var(--line)}.row b,.row small{display:block;font:700 12px Arial}.row small{margin-top:3px;color:var(--muted);font-weight:normal}.row strong{max-width:52%;font:600 12px Arial;text-align:right;overflow-wrap:anywhere}.context-grid{display:grid;grid-template-columns:repeat(3,1fr)}.context{min-height:93px;padding:18px;border-right:1px solid var(--line);border-bottom:1px solid var(--line)}.context span{color:var(--muted)}.context strong{display:block;margin-top:8px;overflow-wrap:anywhere}.check{margin:13px 0;padding:20px;border-left:5px solid var(--teal)}.check.review{border-left-color:var(--gold)}.check-head{display:flex;justify-content:space-between}.number{color:var(--teal);font:700 12px Arial;letter-spacing:.1em}.review .number{color:var(--gold)}h3{display:inline;margin-left:10px;font-size:20px;font-weight:normal}.check-head p{margin:8px 0 0;color:var(--muted);font:12px Consolas,monospace;overflow-wrap:anywhere}.condition{margin:17px 0 0 25px;padding:10px 13px;background:#e5f6f3;border-left:3px solid var(--teal);font:13px Arial}.review .condition{background:#fff3dc;border-left-color:var(--gold)}.condition span{margin-right:10px;color:var(--muted);font:700 10px Arial;letter-spacing:.1em;text-transform:uppercase}.note{margin:14px 0;padding:10px;color:#805002;background:#fff6e6;font:13px Arial}details{margin-top:16px}summary{cursor:pointer;font:700 12px Arial;color:#173e5d}pre{max-height:340px;overflow:auto;margin:12px 0 0;padding:15px;border-radius:3px;background:#0d2743;color:#e7f0f7;font:12px/1.5 Consolas,monospace}.manuals{padding:24px;background:#fff9ed;border:1px solid #ecd49f}.manual{padding:17px 0;border-top:1px solid #ead7b0}.manual:first-child{border-top:0}.manual h3{margin:0;color:#693f05}.manual code{display:block;margin:9px 0;color:#715326;overflow-wrap:anywhere}.manual p,.manual ol{font:13px Arial}.manual ol{padding-left:20px}@media(max-width:700px){.clusters,.context-grid{grid-template-columns:1fr}.scores{display:block}.score{margin:10px 0}.row{display:block}.row strong{display:block;max-width:100%;margin-top:7px;text-align:left}}
</style>
</head>
<body>
<header><div class="wrap">
<div class="eyebrow">Vault AMI Validation</div>
<h1>$environment</h1>
<div class="meta">Run label: $label | Generated: $timestamp UTC</div>
<div class="scores">
<div class="score"><span>Primary score</span><strong>$primary_score / $primary_total</strong></div>
<div class="score"><span>DR score</span><strong>$dr_score / $dr_total</strong></div>
</div>
</div></header>
<main class="wrap">
<div class="heading"><h2>Cluster Overview</h2><span>Primary and DR posture</span></div>
$overview
<div class="heading"><h2>Run Context</h2><span>Execution details</span></div>
<div class="context-grid">$context</div>
<div class="heading"><h2>Primary Validation Results</h2><span>Command evidence</span></div>
$primary
<div class="heading"><h2>DR Validation Results</h2><span>Command evidence</span></div>
$dr
<div class="heading"><h2>Manual Verification Required</h2><span>Follow-up actions</span></div>
<div class="manuals">$manual</div>
</main>
</body>
</html>""")


def create_report(results, context):
    primary = [item for item in results if item.section == "Primary"]
    dr = [item for item in results if item.section == "DR"]

    primary_score, primary_total = score(results, "Primary")
    dr_score, dr_total = score(results, "DR")

    return HTML.substitute(
        environment=html.escape(context["environment"]),
        label=html.escape(context["label"]),
        timestamp=html.escape(context["timestamp"]),
        primary_score=primary_score,
        primary_total=primary_total,
        dr_score=dr_score,
        dr_total=dr_total,
        overview=cluster_overview(results, context),
        context=render_context(context),
        primary="".join([
            render_card(item, index + 1)
            for index, item in enumerate(primary)
        ]),
        dr="".join([
            render_card(item, index + 1)
            for index, item in enumerate(dr)
        ]),
        manual=manual_cards(results, context)
    )


def save_report(report, context):
    folder = os.path.join(REPORT_DIR, context["environment"])

    if not os.path.isdir(folder):
        os.makedirs(folder)

    path = os.path.join(
        folder,
        "vault_ami_validation_{0}_{1}.html".format(
            context["environment"],
            context["timestamp"]
        )
    )

    with open(path, "w") as output:
        output.write(report)

    return path
def print_cli_summary(results):
    print("\n" + "=" * 72)
    print("VALIDATION SUMMARY")
    print("=" * 72)

    for section in ["Primary", "DR"]:
        print("\n{0}:".format(section))

        section_results = [
            result for result in results
            if result.section == section
        ]

        for result in section_results:
            if result.outcome == "verified":
                print("  [PASSED] {0}".format(result.title))
            else:
                print("  [FAILED] {0}".format(result.title))
                print("           Reason: {0}".format(
                    result.error or "Manual verification required."
                ))

        passed = len([
            result for result in section_results
            if result.outcome == "verified"
        ])

        failed = len(section_results) - passed

        print("  Total: {0} passed, {1} failed".format(
            passed,
            failed
        ))

    print("\n" + "=" * 72)


def main():
    print("Vault AMI Validation")

    try:
        context = get_context()
        results = run_validations(context)
        path = save_report(create_report(results, context), context)
        print_cli_summary(results)

        primary_good, primary_total = score(results, "Primary")
        dr_good, dr_total = score(results, "DR")

        print("\nReport created: {0}".format(path))
        print("Primary score: {0}/{1}".format(
            primary_good, primary_total
        ))
        print("DR score: {0}/{1}".format(dr_good, dr_total))

    except ValidationError as exc:
        print("\nUnable to start validation: {0}".format(exc))
        sys.exit(2)

    except KeyboardInterrupt:
        print("\nValidation cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
