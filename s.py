#!/usr/bin/env python
# vault_ami_validation.py
# Python 3.5 compatible. Run inside approved Dojo.
# Read-only except for one uniquely named validation secret.

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
EST_OFFSET = datetime.timedelta(hours=-5)


class ValidationError(Exception):
    pass


class CommandError(Exception):
    pass


def est_now():
    return datetime.datetime.utcnow() + EST_OFFSET


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


def command_text(command):
    output = []

    for value in command:
        value = str(value)

        if value.startswith("-dr-token="):
            value = "-dr-token=***"

        output.append(value)

    return " ".join(output)
    
def snapshot_backend(context):
    provider = context["profile"].get("provider", "aws").strip().lower()

    if provider == "gcp":
        return "gcs"

    return "s3"


class Runner(object):
    def run(self, command, environment, codes=None, timeout=60):
        if codes is None:
            codes = [0]

        env = os.environ.copy()
        env.update(environment)
        env["VAULT_FORMAT"] = "json"
        env["VAULT_CLI_NO_COLOR"] = "1"

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env
            )

            stdout, stderr = process.communicate(timeout=timeout)

        except OSError as exc:
            raise ValidationError(
                "Unable to start {0}: {1}".format(
                    command_text(command),
                    exc
                )
            )

        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

            raise ValidationError(
                "Command timed out: {0}".format(command_text(command))
            )

        if not isinstance(stdout, str):
            stdout = stdout.decode("utf-8", "replace")

        if not isinstance(stderr, str):
            stderr = stderr.decode("utf-8", "replace")

        if process.returncode not in codes:
            raise CommandError(
                "{0} - {1}".format(
                    command_text(command),
                    clean_error(stderr)
                )
            )

        return stdout

    def json(self, command, environment, codes=None, retries=1):
        last_error = None

        for attempt in range(retries):
            try:
                return json.loads(self.run(command, environment, codes))
            except (ValueError, ValidationError, CommandError) as exc:
                last_error = exc

                if attempt + 1 < retries:
                    time.sleep(5)

        if isinstance(last_error, ValueError):
            raise ValidationError(
                "Expected JSON output from {0}.".format(
                    command_text(command)
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

    session_token = getpass.getpass(
        "AWS session token (Enter if not applicable): "
    ).strip()

    if session_token:
        environment["AWS_SESSION_TOKEN"] = session_token

    return True, environment, ""


def get_context():
    if not os.path.isfile(CONFIG_FILE):
        raise ValidationError(
            "Configuration file not found: {0}".format(CONFIG_FILE)
        )

    with open(CONFIG_FILE, "r") as input_file:
        config = json.load(input_file)

    names = [
        "awsle1",
        "awsxe1",
        "awspe1",
        "gcpxe1",
        "gcppe1"
    ]

    for required_name in names:
        if required_name not in config["environments"]:
            raise ValidationError(
                "Environment profile not found: {0}".format(required_name)
            )

    name = names[choose("Select Vault environment", names)]
    profile = config["environments"][name]

    for key in ["primary_addr", "dr_addr", "test_secret_prefix"]:
        value = str(profile.get(key, "")).strip()

        if not value or "VAULT-ADDRESS" in value:
            raise ValidationError(
                "Update {0} for {1} in vault_validation_config.json.".format(
                    key,
                    name
                )
            )

    label = get_label()

    print("\nTokens remain in memory only and are never saved.")

    primary_token = required_secret("Primary Vault token: ")
    dr_token = required_secret("DR operation token: ")

    aws_enabled = False
    aws_env = {}
    aws_skip_reason = ""

    if profile.get("provider") == "aws":
        aws_enabled, aws_env, aws_skip_reason = aws_options()

    timestamp = est_now().strftime("%Y%m%dT%H%M%S-EST")

    test_path = "{0}/{1}-{2}-{3}".format(
        profile["test_secret_prefix"].strip("/"),
        est_now().strftime("%Y%m%d"),
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

    elif isinstance(value, list):
        for item in value:
            found = find_first(item, names)

            if found not in (None, ""):
                return found

    return None


def find_all(value, names):
    names = set([name.lower() for name in names])
    output = []

    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in names:
                output.append(item)

            output.extend(find_all(item, names))

    elif isinstance(value, list):
        for item in value:
            output.extend(find_all(item, names))

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
            parsed = datetime.datetime.strptime(text, item_format)

            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=datetime.timezone.utc)

            return parsed.astimezone(datetime.timezone.utc)

        except ValueError:
            pass

    return None


def evidence(command_output, assessment=None):
    output = {"command_output": command_output}

    if assessment:
        output["assessment"] = assessment

    return output


def vault_status(runner, environment):
    return runner.json(
        ["vault", "status", "-format=json"],
        environment,
        codes=[0, 1, 2, 3, 4]
    )


def check_status(runner, environment):
    payload = vault_status(runner, environment)

    expect(as_bool(payload.get("initialized")), "Vault is not initialized.")
    expect(not as_bool(payload.get("sealed")), "Vault is sealed.")

    return evidence(payload, {
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


def check_raft(runner, environment, dr_token=None):
    command = [
        "vault", "operator", "raft", "list-peers", "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    payload = runner.json(command, environment)
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

    return evidence(payload, {
        "peer_count": len(servers),
        "leader_count": len(leaders),
        "follower_count": len(followers),
        "voter_count": len(voters)
    })


def check_autopilot(runner, environment, dr_token=None):
    command = [
        "vault", "operator", "raft", "autopilot", "get-config",
        "-format=json"
    ]

    if dr_token:
        command.append("-dr-token={0}".format(dr_token))

    return evidence(runner.json(command, environment))


def check_secret_write(runner, context):
    command = [
        "vault", "kv", "put", "-format=json",
        context["test_path"], "Test=success"
    ]
    output = runner.run(command, context["primary_env"])

    return evidence({
        "message": "Test secret written successfully.",
        "validation_path": context["test_path"],
        "vault_output": output.strip() or "No output returned by Vault."
    }, {
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


def check_secret_read(runner, context):
    payload = runner.json(
        ["vault", "kv", "get", "-format=json", context["test_path"]],
        context["primary_env"]
    )

    value = find_test(payload)
    expect(
        str(value).lower() == "success",
        "Expected Test=success, got {0}".format(value)
    )

    return evidence(payload, {
        "validation_path": context["test_path"],
        "expected_value": "success",
        "actual_value": value
    })


def check_snapshot_config(runner, context):
    backend = snapshot_backend(context)
    snapshot_path = (
        "sys/storage/raft/snapshot-auto/config/{0}"
    ).format(backend)

    payload = runner.json(
        [
            "vault", "read", "-format=json",
            snapshot_path
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

    return evidence(payload, {
        "snapshot_backend": backend,
        "snapshot_config_path": snapshot_path,
        "expected_interval_seconds": expected,
        "reported_interval_seconds": interval
    })


def check_replication(runner, environment, expected_mode, expected_state):
    payload = runner.json(
        ["vault", "read", "-format=json", "sys/replication/status"],
        environment
    )

    data = extract_data(payload)
    dr_data = data.get("dr", data) if isinstance(data, dict) else data

    mode = find_first(dr_data, ["mode"])
    state = find_first(dr_data, ["state"])
    raw_connections = find_all(
        dr_data,
        ["connection_state", "connection_status"]
    )

    connections = []

    for item in raw_connections:
        if isinstance(item, list):
            connections.extend([
                str(value).lower()
                for value in item
                if value not in (None, "")
            ])
        elif item not in (None, ""):
            connections.append(str(item).lower())

    expect(str(mode).lower() == expected_mode, "Unexpected DR mode.")
    expect(str(state).lower() == expected_state, "Unexpected DR state.")
    expect(bool(connections), "Replication connection state not found.")

    allowed = ["connected"]

    if expected_mode == "secondary":
        allowed.append("ready")

    expect(
        all(value in allowed for value in connections),
        "Unexpected connection state: {0}.".format(
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
        item for item in members
        if as_bool(item.get("active_node"))
    ]

    expect(bool(members), "No operator member list was returned.")
    expect(len(members) == 5, "Expected 5 members; found {0}.".format(
        len(members)
    ))
    expect(len(active) == 1, "Expected 1 active operator member.")

    return evidence(payload, {
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

    return evidence(payload, {
        "expiration_time": expiration_text,
        "days_remaining": int(days)
    })


def check_audit(runner, context):
    return evidence(runner.json(
        [
            "vault", "audit", "list",
            "-detailed", "-format=json"
        ],
        context["primary_env"]
    ))


def check_cloud_snapshots(runner, context):
    bucket = context["profile"].get("snapshot_bucket", "")
    prefix = context["profile"].get("snapshot_prefix", "")

    expect(
        bucket and "SNAPSHOT-BUCKET" not in bucket,
        "Snapshot bucket is not configured."
    )

    if context["profile"]["provider"] == "aws":
        payload = runner.json(
            [
                "aws", "s3api", "list-objects-v2",
                "--bucket", bucket,
                "--prefix", prefix,
                "--output", "json",
                "--query",
                "reverse(sort_by(Contents,&LastModified))[:3]."
                "{Key:Key,LastModified:LastModified,Size:Size}"
            ],
            context["primary_env"]
        )
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

    return evidence(payload, {
        "snapshot_count_returned": len(snapshots)
    })


def check_version(runner, environment):
    payload = vault_status(runner, environment)
    version = find_first(payload, ["version"])

    expect(bool(version), "Vault version was not found.")
    return evidence(payload, {"version": version})


def check_recovery(runner, environment):
    payload = vault_status(runner, environment)

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

    return evidence(payload, {
        "source": "vault status -format=json",
        "total_recovery_shares": shares,
        "recovery_threshold": threshold
    })


def check_tls(address):
    parsed = urlparse(address)
    hostname = parsed.hostname
    port = parsed.port or 443

    expect(bool(hostname), "Invalid Vault address.")

    ssl_context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=15) as raw:
            with ssl_context.wrap_socket(
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

    # Critical token validation. The script stops only if this fails.
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
         ["Compare output with the approved configuration."],
         lambda: check_autopilot(runner, primary), False),

        ("Primary", "Validation secret write (Primary)",
         "vault write -format=json {0} Test=success".format(path),
         "Vault accepts Test=success at the generated validation path.",
         ["Confirm token write access to the validation path."],
         lambda: check_secret_write(runner, context), False),

        ("Primary", "Validation secret read (Primary)",
         "vault read -format=json {0}".format(path),
         "The generated validation path returns Test=success.",
         ["Confirm Test=success is returned."],
         lambda: check_secret_read(runner, context), False),

        ("Primary", "Snapshot configuration (Primary)",
         "vault read -format=json "
         "sys/storage/raft/snapshot-auto/config/s3",
         "Configured snapshot interval matches the environment baseline.",
         ["Confirm snapshot interval matches the baseline."],
         lambda: check_snapshot_config(runner, context), False),

        ("Primary", "DR replication state (Primary)",
         "vault read -format=json sys/replication/status",
         "Mode is primary, state is running, and connections are connected.",
         ["Confirm Primary DR replication is healthy."],
         lambda: check_replication(runner, primary, "primary", "running"),
         False),

        ("Primary", "Operator members (Primary)",
         "vault operator members -format=json",
         "5 members are listed and exactly 1 member is active.",
         ["Confirm active node and expected peers are listed."],
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
         ["Confirm version matches the approved AMI release."],
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
         ["Compare output with the approved DR configuration."],
         lambda: check_autopilot(runner, dr, context["dr_token"]), False),

        ("DR", "DR replication state (DR)",
         "vault read -format=json sys/replication/status",
         "Mode is secondary, state is stream-wals, and connection is ready.",
         ["Confirm last remote entry continues advancing."],
         lambda: check_replication(runner, dr, "secondary", "stream-wals"),
         False),

        ("DR", "Vault version (DR)",
         "vault status -format=json",
         "A DR Vault version is returned.",
         ["Confirm version matches the approved AMI release."],
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

    for index, item in enumerate(checks, 1):
        print("[{0}/{1}] {2}".format(index, len(checks), item[1]))

        execute(            results, item[0], item[1], item[2],
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
    selected = [
        item for item in results
        if item.section == section
    ]

    successful = [
        item for item in selected
        if item.outcome == "verified"
    ]

    return len(successful), len(selected)


def find_result(results, title):
    for result in results:
        if result.title == title:
            return result

    return None


def assessment(results, title, key, default="Not reported"):
    result = find_result(results, title)

    if not result or not isinstance(result.evidence, dict):
        return default

    values = result.evidence.get("assessment", {})

    if not isinstance(values, dict):
        return default

    return str(values.get(key, default))


def result_state(results, title):
    result = find_result(results, title)

    if result and result.outcome == "verified":
        return "Evidence captured"

    return "Manual review"


def overview_row(label, value, detail=""):
    return """
    <div class="overview-row">
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
            result_state(results, "Vault status (Primary)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment(results, "Vault status (Primary)", "initialized"),
                assessment(results, "Vault status (Primary)", "sealed")
            )
        ),
        overview_row(
            "Raft topology",
            result_state(results, "Raft list-peers (Primary)"),
            "{0} peers | {1} leader | {2} followers".format(
                assessment(results, "Raft list-peers (Primary)", "peer_count"),
                assessment(results, "Raft list-peers (Primary)", "leader_count"),
                assessment(results, "Raft list-peers (Primary)", "follower_count")
            )
        ),
        overview_row(
            "DR replication",
            result_state(results, "DR replication state (Primary)"),
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
            result_state(results, "Vault status (DR)"),
            "Initialized: {0} | Sealed: {1}".format(
                assessment(results, "Vault status (DR)", "initialized"),
                assessment(results, "Vault status (DR)", "sealed")
            )
        ),
        overview_row(
            "Raft topology",
            result_state(results, "Raft list-peers (DR)"),
            "{0} peers | {1} leader | {2} followers".format(
                assessment(results, "Raft list-peers (DR)", "peer_count"),
                assessment(results, "Raft list-peers (DR)", "leader_count"),
                assessment(results, "Raft list-peers (DR)", "follower_count")
            )
        ),
        overview_row(
            "DR replication",
            result_state(results, "DR replication state (DR)"),
            "Mode: {0} | State: {1}".format(
                assessment(results, "DR replication state (DR)", "mode"),
                assessment(results, "DR replication state (DR)", "state")
            )
        )
    ])

    return """
    <div class="cluster-grid">
      <article><header>Primary Cluster</header>{0}</article>
      <article><header>DR Cluster</header>{1}</article>
    </div>
    """.format(primary, dr)


def render_context(context):
    snapshot_validation = "Included"

    if context["profile"].get("provider") == "aws" and not context["aws_enabled"]:
        snapshot_validation = "Manual verification required"

    values = [
        ("Environment", context["environment"]),
        ("Provider", context["profile"].get("provider", "").upper()),
        ("Validation label", context["label"]),
        ("Generated EST", context["timestamp"]),
        ("Test secret path", context["test_path"]),
        ("Snapshot validation", snapshot_validation)
    ]

    return "".join([
        """
        <div class="context-item">
          <span>{0}</span>
          <strong>{1}</strong>
        </div>
        """.format(html.escape(label), html.escape(str(value)))
        for label, value in values
    ])


def render_card(result, number):
    state = "captured" if result.outcome == "verified" else "review"
    review_note = ""

    if result.outcome != "verified":
        review_note = """
        <div class="review-note">
          <b>Review note:</b> {0}
        </div>
        """.format(html.escape(result.error))

    return """
    <article class="validation-card {0}">
      <div class="validation-head">
        <span class="number">{1:02d}</span>
        <div>
          <h3>{2}</h3>
          <p>{3}</p>
        </div>
      </div>

      <div class="outcome-field">
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
        state,
        number,
        html.escape(result.title),
        html.escape(result.command),
        html.escape(result.condition),
        review_note,
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
        "title": "Snapshot runtime status retry validation",
        "command": (
            "vault read -format=json "
            "sys/storage/raft/snapshot-auto/status/s3 && break; "
        ),
        "reason": (
            "This is a permanent manual post-AMI validation. "
            "It is intentionally excluded from the automated score."
        ),
        "steps": [
            "Run the command from the approved Dojo terminal.",
            "Allow five attempts with a 60-second wait between attempts.",
            "Confirm the latest snapshot timestamp is after the AMI activity.",
            "Confirm a next snapshot timestamp is populated."
        ]
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

    items.append({
        "title": "Latest Raft Snapshot Timestamp",
        "command": "Manual Snapshot Validation",
        "reason": (
            "Permanent manual validation. Confirm that a new Raft "
            "snapshot was generated after the AMI upgrade."
        ),
        "steps": [
            (
                "Open the cloud console for the selected environment. "
                "Navigate to the configured primary Raft snapshot storage "
                "bucket and open `raft-snapshots/`. Identify the most "
                "recently modified object. Confirm that its timestamp is "
                "later than the AMI upgrade completion time and that the "
                "object has a non-zero size. Record the name, timestamp, "
                "and object size as change evidence."
            )
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
            command_html = "<code>{0}</code>".format(
                html.escape(str(command))
            )

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
            html.escape(str(item["title"])),
            command_html,
            html.escape(str(item["reason"])),
            steps
        )

    return output

HTML = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vault IVP/AVP Testing - $environment</title>
<style>
:root {
  --core-blue: #001871;
  --dark-blue: #001149;
  --cobalt: #1352DE;
  --pale-blue: #C7DBF4;
  --pale-gold: #EDD7A0;
  --pale-gold-soft: #F6EBCF;
  --blue-gray: #5D738D;
  --dark-gray: #343741;
  --light-gray: #EEEEEE;
  --white: #FFFFFF;
  --line: #D7E1EC;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  color: var(--dark-gray);
  background: var(--light-gray);
  font-family: "Source Sans 3", Arial, sans-serif;
}

.wrap {
  width: min(1220px, 94%);
  margin: 0 auto;
}

body > header {
  color: var(--white);
  background: var(--core-blue);
  border-bottom: 8px solid var(--pale-gold);
}

.header-inner {
  padding: 52px 0 42px;
}

.eyebrow {
  margin: 0 0 12px;
  color: var(--pale-gold);
  font: 700 11px Arial, sans-serif;
  letter-spacing: .18em;
  text-transform: uppercase;
}

h1 {
  max-width: 760px;
  margin: 0;
  color: var(--white);
  font: 500 42px "Futura PT", "Source Sans 3", Arial, sans-serif;
  line-height: 1.08;
}

.meta {
  margin: 16px 0 0;
  color: var(--pale-blue);
  font-size: 14px;
}

.score-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  margin-top: 34px;
}

.score-card {
  min-width: 240px;
  padding: 17px 20px;
  background: var(--dark-blue);
  border-top: 3px solid var(--pale-gold);
}

.score-card span {
  display: block;
  color: var(--pale-blue);
  font: 700 10px Arial, sans-serif;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.score-card strong {
  display: block;
  margin-top: 5px;
  color: var(--white);
  font: 500 38px "Futura PT", "Source Sans 3", Arial, sans-serif;
}

main {
  padding: 36px 0 58px;
}

.heading {
  display: flex;
  gap: 13px;
  align-items: baseline;
  margin: 42px 0 18px;
  padding-bottom: 11px;
  border-bottom: 3px solid var(--core-blue);
}

.heading h2 {
  margin: 0;
  color: var(--dark-blue);
  font: 500 29px "Futura PT", "Source Sans 3", Arial, sans-serif;
}

.heading span {
  color: var(--blue-gray);
  font: 700 10px Arial, sans-serif;
  letter-spacing: .14em;
  text-transform: uppercase;
}

.cluster-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 22px;
}

.cluster-grid article,
.context-grid,
.validation-card {
  background: var(--white);
  border: 1px solid var(--line);
}

.cluster-grid article {
  border-top: 6px solid var(--core-blue);
}

.cluster-grid article:nth-child(2) {
  border-top-color: var(--cobalt);
}

.cluster-grid header {
  padding: 17px 20px;
  color: var(--white);
  background: var(--dark-blue);
  font: 500 20px "Futura PT", "Source Sans 3", Arial, sans-serif;
}

.overview-row {
  display: flex;
  gap: 18px;
  justify-content: space-between;
  padding: 15px 20px;
  border-top: 1px solid var(--line);
}

.overview-row b,
.overview-row small {
  display: block;
}

.overview-row b {
  color: var(--dark-blue);
  font: 700 12px Arial, sans-serif;
}

.overview-row small {
  margin-top: 4px;
  color: var(--blue-gray);
  font-size: 11px;
}

.overview-row strong {
  max-width: 54%;
  color: var(--dark-gray);
  text-align: right;
  font-size: 12px;
  overflow-wrap: anywhere;
}

.context-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.context-item {
  min-height: 98px;
  padding: 19px 20px;
  border-right: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.context-item:nth-child(3n) {
  border-right: 0;
}

.context-item span {
  display: block;
  color: var(--blue-gray);
  font: 700 10px Arial, sans-serif;
  letter-spacing: .13em;
  text-transform: uppercase;
}

.context-item strong {
  display: block;
  margin-top: 8px;
  color: var(--dark-blue);
  font-size: 16px;
  overflow-wrap: anywhere;
}

.validation-card {
  margin: 15px 0;
  padding: 22px;
  border-left: 6px solid var(--core-blue);
}

.validation-card.review {
  border-left-color: #CE8E49;
}

.validation-head {
  display: flex;
  gap: 13px;
}

.number {
  padding-top: 3px;
  color: var(--cobalt);
  font: 700 12px Arial, sans-serif;
  letter-spacing: .1em;
}

.review .number {
  color: #CE8E49;
}

.validation-head h3 {
  margin: 0;
  color: var(--dark-blue);
  font: 500 21px "Futura PT", "Source Sans 3", Arial, sans-serif;
}

.validation-head p {
  margin: 8px 0 0;
  color: var(--blue-gray);
  font: 12px Consolas, "Courier New", monospace;
  overflow-wrap: anywhere;
}

.outcome-field {
  margin: 18px 0 0 25px;
  padding: 12px 14px;
  color: var(--dark-blue);
  background: var(--pale-blue);
  border-left: 4px solid var(--cobalt);
  font-size: 13px;
}

.review .outcome-field {
  background: var(--pale-gold-soft);
  border-left-color: #CE8E49;
}

.outcome-field span {
  margin-right: 10px;
  color: var(--blue-gray);
  font: 700 10px Arial, sans-serif;
  letter-spacing: .1em;
  text-transform: uppercase;
}

.review-note {
  margin: 16px 0;
  padding: 12px 14px;
  color: var(--dark-blue);
  background: var(--pale-gold-soft);
  border-left: 4px solid #CE8E49;
  font-size: 13px;
}

details {
  margin-top: 18px;
}

summary {
  cursor: pointer;
  color: var(--core-blue);
  font: 700 12px Arial, sans-serif;
}

pre {
  max-height: 350px;
  overflow: auto;
  margin: 12px 0 0;
  padding: 16px;
  color: var(--white);
  background: var(--dark-blue);
  border-top: 4px solid var(--cobalt);
  font: 12px/1.5 Consolas, "Courier New", monospace;
}

.manuals {
  padding: 26px;
  background: var(--pale-gold-soft);
  border-top: 6px solid var(--pale-gold);
}

.manual-card {
  padding: 20px 0;
  border-top: 1px solid #DEC98F;
}

.manual-card:first-child {
  padding-top: 0;
  border-top: 0;
}

.manual-label {
  color: var(--blue-gray);
  font: 700 10px Arial, sans-serif;
  letter-spacing: .13em;
  text-transform: uppercase;
}

.manual-card h3 {
  margin: 6px 0 0;
  color: var(--dark-blue);
  font: 500 20px "Futura PT", "Source Sans 3", Arial, sans-serif;
}

.manual-card code {
  display: block;
  margin: 11px 0;
  padding: 11px;
  color: var(--white);
  background: var(--dark-blue);
  font: 12px Consolas, "Courier New", monospace;
  overflow-wrap: anywhere;
}

.manual-card p,
.manual-card ol {
  color: var(--dark-gray);
  font-size: 13px;
}

.manual-card ol {
  padding-left: 21px;
}

@media (max-width: 760px) {
  .cluster-grid,
  .context-grid {
    grid-template-columns: 1fr;
  }

  .context-item,
  .context-item:nth-child(3n) {
    border-right: 0;
  }

  .overview-row {
    display: block;
  }

  .overview-row strong {
    display: block;
    max-width: 100%;
    margin-top: 7px;
    text-align: left;
  }
}

@media (max-width: 560px) {
  h1 {
    font-size: 32px;
  }

  .score-grid {
    display: block;
  }

  .score-card {
    margin: 10px 0;
  }
}
</style>
</head>
<body>
<header>
  <div class="wrap header-inner">
    <p class="eyebrow">Technology Operations | Vault IVP/AVP Testing</p>
    <h1>$environment Vault IVP/AVP Testing</h1>
    <p class="meta">Run label: $label | Generated: $timestamp</p>

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
  <div class="heading">
    <h2>Cluster Overview</h2>
    <span>Primary and DR posture</span>
  </div>
  $overview

  <div class="heading">
    <h2>Run Context</h2>
    <span>Execution details</span>
  </div>
  <div class="context-grid">$context</div>

  <div class="heading">
    <h2>Primary Validation Results</h2>
    <span>Command evidence</span>
  </div>
  $primary

  <div class="heading">
    <h2>DR Validation Results</h2>
    <span>Command evidence</span>
  </div>
  $dr

  <div class="heading">
    <h2>Manual Verification Required</h2>
    <span>Permanent and exception follow-up</span>
  </div>
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


def save_report(content, context):
    folder = os.path.join(REPORT_DIR, context["environment"])

    if not os.path.isdir(folder):
        os.makedirs(folder)

    path = os.path.join(
        folder,
        "vault_ivp_avp_testing_{0}_{1}.html".format(
            context["environment"],
            context["timestamp"]
        )
    )

    with open(path, "w") as output:
        output.write(content)

    return path


def print_summary(results):
    print("\n" + "=" * 72)
    print("VALIDATION SUMMARY")
    print("=" * 72)

    for section in ["Primary", "DR"]:
        print("\n{0}:".format(section))

        selected = [
            result for result in results
            if result.section == section
        ]

        for result in selected:
            if result.outcome == "verified":
                print("  [PASSED] {0}".format(result.title))
            else:
                print("  [FAILED] {0}".format(result.title))
                print("           Reason: {0}".format(
                    result.error or "Manual verification required."
                ))

        passed = len([
            result for result in selected
            if result.outcome == "verified"
        ])

        print("  Total: {0} passed, {1} failed".format(
            passed,
            len(selected) - passed
        ))

    print("=" * 72)


def main():
    print("Vault IVP/AVP Testing")
    print("Read-only except for one generated validation secret.")

    try:
        context = get_context()
        results = run_validations(context)
        report_path = save_report(create_report(results, context), context)

        print_summary(results)

        primary_score, primary_total = score(results, "Primary")
        dr_score, dr_total = score(results, "DR")

        print("\nReport created: {0}".format(report_path))
        print("Primary score: {0}/{1}".format(
            primary_score,
            primary_total
        ))
        print("DR score: {0}/{1}".format(
            dr_score,
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
