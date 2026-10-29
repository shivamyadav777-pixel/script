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
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "vault_env.json")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
IST_OFFSET = datetime.timedelta(hours=5, minutes=30)


class ValidationError(Exception):
    pass


class CommandError(Exception):
    pass


def utc_now():
    return datetime.datetime.utcnow()


def nth_sunday(year, month, occurrence):
    value = datetime.datetime(year, month, 1)
    offset = (6 - value.weekday()) % 7
    return value + datetime.timedelta(days=offset + 7 * (occurrence - 1))


def eastern_now(now_utc=None):
    now_utc = now_utc or utc_now()
    start = nth_sunday(now_utc.year, 3, 2).replace(hour=7)
    end = nth_sunday(now_utc.year, 11, 1).replace(hour=6)

    if start <= now_utc < end:
        return now_utc + datetime.timedelta(hours=-4), "EDT"

    return now_utc + datetime.timedelta(hours=-5), "EST"


def timestamp_bundle(now_utc=None):
    now_utc = now_utc or utc_now()
    eastern, eastern_label = eastern_now(now_utc)
    ist = now_utc + IST_OFFSET

    return {
        "ist": ist.strftime("%Y-%m-%d-%H%M%S"),
        "eastern": eastern.strftime("%Y-%m-%d-%H%M%S"),
        "eastern_zone": eastern_label
    }


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


def canonical_vault_address(value):
    parsed = urlparse(str(value or "").strip())
    hostname = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "https").lower()
    port = parsed.port

    if not hostname:
        raise ValidationError("VAULT_ADDR is not a valid Vault URL.")

    if port and not (
            (scheme == "https" and port == 443) or
            (scheme == "http" and port == 80)):
        return "{0}://{1}:{2}".format(scheme, hostname, port)

    return "{0}://{1}".format(scheme, hostname)


def detect_environment(config):
    vault_addr = os.environ.get("VAULT_ADDR", "").strip()

    if not vault_addr:
        raise ValidationError(
            "VAULT_ADDR must be set to determine the target environment."
        )

    current_address = canonical_vault_address(vault_addr)
    matches = []

    for name, profile in config["environments"].items():
        configured_address = str(profile.get("primary_addr", "")).strip()

        # Other profiles may intentionally remain placeholders; they must not
        # prevent detection of a fully configured target environment.
        if not configured_address or configured_address.startswith("<"):
            continue

        if canonical_vault_address(configured_address) == current_address:
            matches.append((name, profile))

    if len(matches) != 1:
        raise ValidationError(
            "VAULT_ADDR must match exactly one configured primary_addr; "
            "found {0} matches.".format(len(matches))
        )

    return matches[0]


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


def primary_token_from_environment():
    # `vault login` commonly stores this in the Vault CLI token helper rather
    # than exporting VAULT_TOKEN. An empty result lets the CLI use that helper.
    return os.environ.get("VAULT_TOKEN", "").strip()


def configured_secret_path(value, label):
    value = str(value or "").strip()

    if not value or value.startswith("<"):
        raise ValidationError("{0} is not configured.".format(label))

    return value


def retrieve_dr_token(primary_environment, profile, config):
    path = configured_secret_path(
        config.get("dr_token_secret_path"),
        "DR token Vault path"
    )
    key = configured_secret_path(
        profile.get("dr_token_key"),
        "DR token key"
    )

    payload = Runner().json(
        ["vault", "read", "-format=json", path],
        primary_environment
    )
    data = extract_data(payload)

    if not isinstance(data, dict):
        raise ValidationError("DR token secret has an invalid KV v1 response.")

    token = str(data.get(key, "")).strip()

    if not token:
        raise ValidationError(
            "DR token field is missing or empty for the detected environment."
        )

    return token


def get_label():
    while True:
        label = input(
            "Enter label (letters, numbers, hyphens, underscores): "
        ).strip()

        if re.match(r"^[A-Za-z0-9_-]{1,40}$", label):
            return label.lower()

        print("Invalid label.")


def get_validation_details():
    selected = choose(
        "Select validation type",
        ["Precheck", "Postcheck", "Custom"]
    )

    if selected == 2:
        return "custom", "", get_label()

    validation_type = "precheck" if selected == 0 else "postcheck"

    while True:
        change_number = input("Enter change number: ").strip().upper()

        if re.match(r"^[A-Z][A-Z0-9_-]{2,63}$", change_number):
            return validation_type, change_number, validation_type

        print("Invalid change number.")


def get_upload_choice():
    while True:
        value = input("Upload report to Artifactory? (y/n): ").strip().lower()

        if value == "y":
            return True

        if value == "n":
            return False

        print("Enter y or n.")


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

    name, profile = detect_environment(config)

    print("\nDetected target environment: {0}".format(name.upper()))

    for key in ["primary_addr", "dr_addr", "test_secret_prefix"]:
        value = str(profile.get(key, "")).strip()

        if not value or "VAULT-ADDRESS" in value:
            raise ValidationError(
                "Update {0} for {1} in vault_validation_config.json.".format(
                    key,
                    name
                )
            )

    validation_type, change_number, label = get_validation_details()
    upload_requested = get_upload_choice()

    print("\nVault authentication is read from VAULT_TOKEN or the existing "
          "Dojo Vault CLI login and is never saved by this script.")

    primary_token = primary_token_from_environment()

    aws_enabled = False
    aws_env = {}
    aws_skip_reason = ""

    if profile.get("provider") == "aws":
        aws_enabled, aws_env, aws_skip_reason = aws_options()

    timestamps = timestamp_bundle()
    timestamp = timestamps["eastern"].replace("-", "")

    test_path = "{0}/{1}-{2}-{3}".format(
        profile["test_secret_prefix"].strip("/"),
        timestamps["ist"][:10].replace("-", ""),
        label,
        timestamp
    )

    primary_env = {"VAULT_ADDR": profile["primary_addr"]}

    if primary_token:
        primary_env["VAULT_TOKEN"] = primary_token

    dr_token = retrieve_dr_token(primary_env, profile, config)

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
        "validation_type": validation_type,
        "change_number": change_number,
        "upload_requested": upload_requested,
        "artifactory": config.get("artifactory", {}),
        "artifactory_upload_status": (
            "Requested" if upload_requested else "Skipped by user"
        ),
        "artifactory_destination": "",
        "timestamp": timestamp,
        "timestamp_ist": timestamps["ist"],
        "timestamp_eastern": timestamps["eastern"],
        "timestamp_eastern_zone": timestamps["eastern_zone"],
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


def workflow_result(results, title, command, condition, outcome, message="",
                    progress=None, details=None):
    """Append a detailed workflow result and advance the shared counter."""
    result = Result(
        "Primary", title, command, condition,
        ["Review the change-specific validation evidence."], False
    )
    result.outcome = outcome
    result.error = clean_error(message)
    result.evidence = evidence({
        "status": outcome.upper(),
        "step": title,
        "message": clean_error(message) if message else "",
        "details": details or {}
    })
    results.append(result)

    if progress is not None:
        progress["current"] += 1
        print("[{0}/{1}] {2} - {3}".format(
            progress["current"], progress["total"], title,
            outcome.upper()
        ))


def change_mount_workflow(runner, context, results, progress=None):
    """Run the change-specific KV v2 workflow with a stable eight-step count.

    Every non-custom run records these eight steps exactly once, even when a
    step is skipped because a prerequisite failed or the mount already exists.
    Existing mounts are never reused or modified by this workflow.
    """
    if context["validation_type"] == "custom":
        workflow_result(
            results, "Change-specific KV v2 validation", "Not applicable",
            "Custom validation does not require a change-number mount.",
            "skipped", "Not applicable for custom validation.", progress
        )
        return

    mount = "kv-{0}".format(context["change_number"].lower())
    secret_path = "ivp-avp/{0}".format(context["timestamp"])
    metadata = {
        "environment": context["environment"],
        "validation_type": context["validation_type"],
        "change_number": context["change_number"],
        "timestamp_ist": context["timestamp_ist"],
        "timestamp_eastern": context["timestamp_eastern"]
    }

    commands = {
        "inspect": "vault secrets list -format=json",
        "enable": "vault secrets enable -path={0} -version=2 kv".format(mount),
        "write": "vault kv put -mount={0} {1}".format(mount, secret_path),
        "read": "vault kv get -mount={0} {1}".format(mount, secret_path),
        "verify": "Metadata comparison",
        "delete": "vault kv delete -mount={0} {1}".format(mount, secret_path),
        "verify_delete": "vault kv metadata get -mount={0} {1}".format(
            mount, secret_path
        ),
        "disable": "vault secrets disable {0}".format(mount)
    }

    conditions = {
        "inspect": "The mount is inspected before any change is attempted.",
        "enable": "A new KV v2 mount is created for this execution only.",
        "write": "Dedicated non-sensitive validation metadata is written.",
        "read": "The validation metadata written by this execution is read.",
        "verify": "Returned metadata exactly matches the written metadata.",
        "delete": "Only this execution's validation secret is soft-deleted.",
        "verify_delete": "KV v2 metadata confirms the secret was soft-deleted.",
        "disable": "Only the mount created by this execution is disabled."
    }

    def record(key, outcome, message="", details=None):
        titles = {
            "inspect": "Inspect validation KV v2 mount",
            "enable": "Enable validation KV v2 mount",
            "write": "Write validation secret",
            "read": "Read validation secret",
            "verify": "Verify validation secret content",
            "delete": "Delete validation secret",
            "verify_delete": "Verify validation secret deletion",
            "disable": "Disable validation KV v2 mount"
        }
        detail_payload = {
            "mount_path": mount,
            "secret_path": secret_path,
            "validation_type": context.get("validation_type"),
            "environment": context.get("environment")
        }
        if details:
            detail_payload.update(details)
        workflow_result(
            results, titles[key], commands[key], conditions[key], outcome,
            message, progress, detail_payload
        )

    def skip(keys, reason):
        for key in keys:
            record(key, "skipped", reason)

    # Step 1: Inspect. Never enable or reuse a mount if inspection fails.
    try:
        mounts = runner.json(
            ["vault", "secrets", "list", "-format=json"],
            context["primary_env"]
        )
    except Exception as exc:
        record("inspect", "review", clean_error(exc), {
            "inspection_completed": False,
            "safe_action": "No mount changes attempted"
        })
        skip(
            ["enable", "write", "read", "verify", "delete",
             "verify_delete", "disable"],
            "Skipped because the existing mount state could not be inspected safely."
        )
        return

    if mount + "/" in mounts:
        record(
            "inspect", "verified",
            "Mount already exists; it will not be reused or modified.", {
                "inspection_completed": True,
                "mount_exists": True,
                "safe_action": "Existing mount left untouched"
            }
        )
        skip(
            ["enable", "write", "read", "verify", "delete",
             "verify_delete", "disable"],
            "Skipped because the mount already existed and was not reused."
        )
        return

    record("inspect", "verified", "No conflicting mount exists.", {
        "inspection_completed": True,
        "mount_exists": False,
        "mount_count_returned": len(mounts) if isinstance(mounts, dict) else None,
        "safe_action": "Proceeding to create a dedicated mount"
    })

    # Step 2: Create a dedicated KV v2 mount.
    try:
        enable_output = runner.run(
            ["vault", "secrets", "enable", "-path={0}".format(mount),
             "-version=2", "kv"],
            context["primary_env"]
        )
    except Exception as exc:
        record("enable", "review", clean_error(exc), {
            "mount_created": False,
            "kv_version_requested": 2
        })
        skip(
            ["write", "read", "verify", "delete", "verify_delete", "disable"],
            "Skipped because the validation mount could not be created."
        )
        return
    record("enable", "verified", details={
        "mount_created": True,
        "mount_path": mount,
        "secret_engine": "kv",
        "kv_version_requested": 2,
        "command_response": clean_error(enable_output) if enable_output.strip() else "No command output"
    })

    # Step 3: Write only this run's non-sensitive metadata.
    write = ["vault", "kv", "put", "-mount={0}".format(mount), secret_path]
    write.extend(
        "{0}={1}".format(key, value)
        for key, value in metadata.items()
    )
    try:
        write_output = runner.run(write, context["primary_env"])
    except Exception as exc:
        record("write", "review", clean_error(exc), {
            "write_completed": False,
            "metadata_field_names": sorted(metadata.keys())
        })
        skip(
            ["read", "verify", "delete", "verify_delete", "disable"],
            "Skipped because writing the validation secret did not complete. "
            "The mount is left in place because safe cleanup was not confirmed."
        )
        return
    record("write", "verified", details={
        "write_completed": True,
        "metadata_written": metadata,
        "metadata_field_names": sorted(metadata.keys()),
        "command_response": clean_error(write_output) if write_output.strip() else "No command output"
    })

    # Step 4: Read the written secret.
    try:
        payload = runner.json(
            ["vault", "kv", "get", "-format=json",
             "-mount={0}".format(mount), secret_path],
            context["primary_env"]
        )
        returned = extract_data(payload)
        if isinstance(returned, dict) and isinstance(returned.get("data"), dict):
            returned = returned["data"]
    except Exception as exc:
        record("read", "review", clean_error(exc), {
            "read_completed": False,
            "expected_metadata_field_names": sorted(metadata.keys())
        })
        skip(
            ["verify", "delete", "verify_delete", "disable"],
            "Skipped because the validation secret could not be read. "
            "The mount is left in place because safe cleanup was not confirmed."
        )
        return
    record("read", "verified", details={
        "read_completed": True,
        "returned_metadata": returned,
        "returned_field_names": sorted(returned.keys()) if isinstance(returned, dict) else [],
        "expected_field_names": sorted(metadata.keys())
    })

    # Step 5: Compare the read-back content.
    if returned != metadata:
        record(
            "verify", "review",
            "Validation secret content mismatch; cleanup was not attempted.", {
                "comparison_passed": False,
                "expected_metadata": metadata,
                "returned_metadata": returned,
                "cleanup_attempted": False
            }
        )
        skip(
            ["delete", "verify_delete", "disable"],
            "Skipped because content verification failed; the mount is left "
            "in place for safe investigation."
        )
        return
    record("verify", "verified", details={
        "comparison_passed": True,
        "compared_field_names": sorted(metadata.keys()),
        "expected_field_count": len(metadata),
        "returned_field_count": len(returned)
    })

    # Step 6: Soft-delete the validation secret.
    try:
        delete_output = runner.run(
            ["vault", "kv", "delete", "-mount={0}".format(mount),
             secret_path],
            context["primary_env"]
        )
    except Exception as exc:
        record("delete", "review", clean_error(exc), {
            "delete_command_completed": False,
            "delete_type": "KV v2 soft delete",
            "mount_cleanup_allowed": False
        })
        skip(
            ["verify_delete", "disable"],
            "Skipped because secret deletion was not confirmed; the mount "
            "is left in place to avoid unsafe cleanup."
        )
        return
    record("delete", "verified", details={
        "delete_command_completed": True,
        "delete_type": "KV v2 soft delete (not permanent destroy)",
        "secret_path": secret_path,
        "command_response": clean_error(delete_output) if delete_output.strip() else "No command output",
        "deletion_timestamp_verified": False,
        "mount_cleanup_allowed_pending_verification": True
    })

    # Step 7: Confirm Vault records the deletion timestamp.
    try:
        delete_metadata = runner.json(
            ["vault", "kv", "metadata", "get", "-format=json",
             "-mount={0}".format(mount), secret_path],
            context["primary_env"]
        )
        deletion_time = find_first(delete_metadata, ["deletion_time"])
        expect(
            bool(deletion_time),
            "KV v2 deletion metadata did not include a deletion timestamp."
        )
    except Exception as exc:
        record("verify_delete", "review", clean_error(exc), {
            "deletion_metadata_read": False,
            "deletion_timestamp_present": False,
            "mount_cleanup_allowed": False
        })
        record(
            "disable", "skipped",
            "Skipped because secret deletion could not be verified; the mount "
            "is intentionally left in place."
        )
        return
    record("verify_delete", "verified", details={
        "deletion_metadata_read": True,
        "deletion_timestamp_present": True,
        "deletion_time": deletion_time,
        "mount_cleanup_allowed": True
    })

    # Step 8: Disable only the mount created by this execution, and only after
    # deletion has been confirmed.
    try:
        runner.run(
            ["vault", "secrets", "disable", mount],
            context["primary_env"]
        )
    except Exception as exc:
        record("disable", "review", clean_error(exc), {
            "mount_disabled": False,
            "reason_cleanup_failed": clean_error(exc),
            "secret_deletion_verified": True
        })
        return
    record("disable", "verified", details={
        "mount_disabled": True,
        "mount_path": mount,
        "secret_deletion_verified": True
    })


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

    # The change workflow records eight stable steps for Precheck/Postcheck,
    # or one not-applicable result for Custom validation.
    workflow_count = (
        1 if context["validation_type"] == "custom" else 8
    )
    progress = {"current": 0, "total": len(checks) + workflow_count}

    for item in checks:
        progress["current"] += 1
        print("[{0}/{1}] {2}".format(
            progress["current"], progress["total"], item[1]
        ))
        execute(
            results, item[0], item[1], item[2],
            item[3], item[4], item[5], item[6]
        )

    change_mount_workflow(runner, context, results, progress)

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
        if item.section == section and item.outcome != "skipped"
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


def display_environment_name(name):
    """Return a friendly environment name for report presentation only."""
    labels = {
        "awsle1": "AWS Inc (le1)",
        "awsxe1": "AWS Non-prod (xe1)",
        "awspe1": "AWS Prod (pe1)",
        "gcpxe1": "GCP Non-Prod",
        "gcppe1": "GCP Prod"
    }
    return labels.get(str(name).lower(), str(name))


def generated_timestamp_label(context):
    """Format the run timestamp in both IST and US Eastern time."""
    ist = context.get("timestamp_ist", "Pending")
    eastern = context.get("timestamp_eastern", "Pending")
    eastern_zone = context.get("timestamp_eastern_zone", "")
    if eastern_zone:
        eastern = "{0} {1}".format(eastern, eastern_zone)
    return "{0} IST | {1}".format(ist, eastern)


def render_context(context):
    snapshot_validation = "Included"

    if context["profile"].get("provider") == "aws" and not context["aws_enabled"]:
        snapshot_validation = "Manual verification required"

    values = [
        ("Environment", display_environment_name(context["environment"])),
        ("Provider", context["profile"].get("provider", "").upper()),
        ("Validation label", context["label"]),
        ("Execution start IST", context["timestamp_ist"]),
        ("Execution start Eastern", "{0} {1}".format(
            context["timestamp_eastern"],
            context["timestamp_eastern_zone"]
        )),
        ("Execution end IST", context.get("timestamp_end_ist", "Pending")),
        ("Execution end Eastern", context.get(
            "timestamp_end_eastern", "Pending"
        )),
        ("Validation type", context["validation_type"].title()),
        ("Change number", context["change_number"] or "Not applicable"),
        ("Snapshot validation", snapshot_validation),
        ("Artifactory upload", context.get(
            "artifactory_upload_status", "Not requested"
        )),
        ("Artifactory destination", context.get(
            "artifactory_destination", "Not applicable"
        ) or "Not applicable")
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
    if result.outcome == "verified":
        state = "captured"
    elif result.outcome == "skipped":
        state = "skipped"
    else:
        state = "review"

    review_note = ""

    if result.outcome == "review":
        review_note = """
        <div class="review-note">
          <b>Review note:</b> {0}
        </div>
        """.format(html.escape(result.error))
    elif result.outcome == "skipped":
        review_note = """
        <div class="skipped-note">
          <b>Skipped:</b> {0}
        </div>
        """.format(html.escape(
            result.error or "This action was not required."
        ))

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
        if result.outcome == "review":
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

.validation-card.skipped {
  border-left-color: #7E8C99;
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

.skipped .outcome-field {
  background: #F1F4F6;
  border-left-color: #7E8C99;
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

.skipped-note {
  margin: 16px 0;
  padding: 12px 14px;
  color: var(--dark-blue);
  background: #F1F4F6;
  border-left: 4px solid #7E8C99;
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
    <p class="eyebrow">Enterprise Platform Management | Vault IVP/AVP Testing</p>
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
        environment=html.escape(display_environment_name(context["environment"])),
        label=html.escape(context["label"]),
        timestamp=html.escape(generated_timestamp_label(context)),
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
        "vault_ivp_avp_testing_{0}_{1}_{2}_{3}.html".format(
            context["environment"],
            context["validation_type"],
            context["change_number"] or context["label"],
            context["timestamp"]
        )
    )

    with open(path, "w") as output:
        output.write(content)

    return path


def kv_v2_data(payload):
    data = extract_data(payload)

    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]

    return data if isinstance(data, dict) else {}


def artifactory_destination(base_url, repository, filename):
    parsed = urlparse(base_url)

    if parsed.scheme != "https" or not parsed.netloc:
        raise ValidationError("Artifactory URL must be a valid HTTPS URL.")

    repository = str(repository or "").strip("/")
    if not repository or ".." in repository.split("/"):
        raise ValidationError("Artifactory repository is not configured safely.")

    safe_repository = "/".join([
        quote(part, safe="") for part in repository.split("/")
    ])

    return "{0}/{1}/{2}".format(
        base_url.rstrip("/"), safe_repository, quote(filename, safe="")
    )


def upload_report_to_artifactory(report_path, context):
    settings = context.get("artifactory", {})

    try:
        secret_path = configured_secret_path(
            settings.get("secret_path"), "Artifactory Vault KV v2 path"
        )
        payload = Runner().json(
            ["vault", "kv", "get", "-format=json", secret_path],
            context["primary_env"]
        )
        credentials = kv_v2_data(payload)
        url = str(credentials.get(settings.get("url_field", "url"), "")).strip()
        repository = str(credentials.get(
            settings.get("repository_field", "repository"), ""
        )).strip()
        api_key = str(credentials.get(
            settings.get("api_key_field", "api_key"), ""
        )).strip()

        if not url or not repository or not api_key:
            raise ValidationError(
                "Artifactory Vault KV v2 secret is missing required fields."
            )

        destination = artifactory_destination(
            url, repository, os.path.basename(report_path)
        )

        with open(report_path, "rb") as report_file:
            request = Request(
                destination,
                data=report_file.read(),
                headers={
                    settings.get("api_key_header", "X-JFrog-Art-Api"): api_key,
                    "Content-Type": "text/html; charset=utf-8"
                }
            )
            response = urlopen(
                request, timeout=60, context=ssl.create_default_context()
            )
            status = response.getcode()
            response.close()

        if status < 200 or status >= 300:
            raise ValidationError(
                "Artifactory returned HTTP status {0}.".format(status)
            )

        return True, destination, ""

    except (ValidationError, CommandError, HTTPError, URLError,
            IOError, OSError, ssl.SSLError) as exc:
        return False, "", clean_error(exc)


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
            elif result.outcome == "skipped":
                print("  [SKIPPED] {0}".format(result.title))
            else:
                print("  [FAILED] {0}".format(result.title))
                print("           Reason: {0}".format(
                    result.error or "Manual verification required."
                ))

        passed = len([result for result in selected
                      if result.outcome == "verified"])
        failed = len([result for result in selected
                      if result.outcome == "review"])
        skipped = len([result for result in selected
                       if result.outcome == "skipped"])

        print("  Total: {0} passed, {1} failed, {2} skipped".format(
            passed, failed, skipped
        ))

    print("=" * 72)


def main():
    print("Vault IVP/AVP Testing")
    print("Read-only except for one generated validation secret.")

    try:
        context = get_context()
        results = run_validations(context)
        end_timestamps = timestamp_bundle()
        context["timestamp_end_ist"] = end_timestamps["ist"]
        context["timestamp_end_eastern"] = "{0} {1}".format(
            end_timestamps["eastern"],
            end_timestamps["eastern_zone"]
        )
        report_path = save_report(create_report(results, context), context)

        if context["upload_requested"]:
            context["artifactory_upload_status"] = "Upload in progress"
            report_path = save_report(create_report(results, context), context)
            uploaded, destination, error = upload_report_to_artifactory(
                report_path, context
            )

            if uploaded:
                context["artifactory_upload_status"] = "Uploaded"
                context["artifactory_destination"] = destination
                report_path = save_report(create_report(results, context), context)
                final_uploaded, unused_destination, final_error = (
                    upload_report_to_artifactory(report_path, context)
                )

                if not final_uploaded:
                    context["artifactory_upload_status"] = (
                        "Initial upload succeeded; final report upload failed: "
                        "{0}".format(final_error)
                    )
                    report_path = save_report(
                        create_report(results, context), context
                    )
            else:
                context["artifactory_upload_status"] = "Upload failed: {0}".format(
                    error or "Unknown error"
                )
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
        print("Artifactory upload: {0}".format(
            context["artifactory_upload_status"]
        ))

    except ValidationError as exc:
        print("\nUnable to start validation: {0}".format(exc))
        sys.exit(2)

    except KeyboardInterrupt:
        print("\nValidation cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
