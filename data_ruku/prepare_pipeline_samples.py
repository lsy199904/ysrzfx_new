#!/usr/bin/env python3
"""Prepare FortiGate samples for the live ingest pipeline.

The OpenSearch FortiGate pipeline parses key/value pairs from ``message``.
These samples intentionally keep only the input fields that the pipeline
needs, instead of pretending that already-normalized ECS fields are raw logs.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SCENARIO_FILES = (
    "account_security_samples.json",
    "brute_force_samples.json",
    "network_attack_samples.json",
    "system_security_samples.json",
)

DATA_DIR = Path(__file__).resolve().parent

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.:/+\-@]+$")


def get_field(document: dict[str, Any], *path: str, default: Any = None) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return default if value is None else value


def quote_value(value: Any) -> str:
    """Render a FortiGate KV value without breaking quoted messages."""
    text = "" if value is None else str(value)
    if _SAFE_VALUE.fullmatch(text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def kv(name: str, value: Any) -> str:
    if value is None or value == "":
        return ""
    return f"{name}={quote_value(value)}"


def raw_header(document: dict[str, Any]) -> list[str]:
    timestamp = str(document.get("@timestamp", ""))
    # The syslog header host is normalized into @host by the ingest pipeline.
    # Keep it as an IP; the device name belongs to observer.name/devname.
    host = (
        get_field(document, "source", "ip")
        or get_field(document, "destination", "ip")
        or "FortiGate"
    )
    return [timestamp, str(host)]


def build_account_message(document: dict[str, Any]) -> str:
    firewall = get_field(document, "fortinet", "firewall", default={})
    event_action = get_field(document, "event", "action", default="event")
    # FortiGate routes traffic records through a dedicated sub-pipeline. Keep
    # the raw type aligned with that routing rule instead of labeling traffic
    # as a generic event.
    log_type = get_field(firewall, "type")
    if not log_type:
        log_type = "traffic" if str(event_action).lower() == "traffic" else "event"
    source_ip = get_field(document, "source", "ip")
    username = get_field(document, "source", "user", "name")
    observer = get_field(document, "observer", "name", default="FortiGate")
    fields = [
        kv("date", str(document.get("@timestamp", ""))[:10]),
        kv("time", str(document.get("@timestamp", ""))[11:19]),
        kv("devname", observer),
        kv("devid", get_field(document, "observer", "serial_number")),
        kv("type", log_type),
        kv("subtype", get_field(firewall, "subtype", default="config")),
        kv("action", event_action),
        kv("reason", get_field(document, "event", "reason")),
        kv("user", username),
        kv("srcip", source_ip),
        kv("dstip", get_field(document, "destination", "ip")),
        kv("dstport", get_field(document, "destination", "port")),
        kv("policyid", get_field(document, "rule", "id")),
        kv("policyname", get_field(document, "rule", "name")),
        kv("status", get_field(firewall, "status", default="success")),
        kv("srccountry", get_field(firewall, "srccountry")),
        kv("cfgpath", get_field(firewall, "cfgpath")),
        kv("cfgobj", get_field(firewall, "cfgobj")),
        kv("ui", get_field(firewall, "ui")),
        kv("logdesc", get_field(document, "rule", "description")),
        kv("msg", document.get("message")),
    ]
    return " ".join([*raw_header({**document, "observer": {"name": observer}}), *filter(None, fields)])


def build_brute_force_document(document: dict[str, Any]) -> dict[str, Any]:
    # This scenario already contains a valid FortiGate KV message. Rewrite
    # only the syslog host column so @host is the source IP, while preserving
    # the login KV fields expected by the pipeline.
    message = document.get("message") or document.get("syslog5424_msg")
    if message:
        parts = str(message).split(maxsplit=2)
        if len(parts) == 3:
            timestamp, host = raw_header(document)
            message = f"{timestamp} {host} {parts[2]}"
    result: dict[str, Any] = {
        "@timestamp": document.get("@timestamp"),
        "@gid": str(document.get("@gid", "")),
        "message": message,
        "source": document.get("source", {}),
        # The login sub-pipeline does not normalize dstip, so preserve the
        # existing destination field for trace and generic-query consumers.
        "destination": document.get("destination", {}),
        "event": document.get("event", {}),
    }
    return result


def build_network_message(document: dict[str, Any]) -> str:
    firewall = get_field(document, "fortinet", "firewall", default={})
    observer = get_field(document, "observer", "name", default="FortiGate")
    action = get_field(document, "event", "action")
    status = get_field(firewall, "status")
    if status is None:
        status = {
            "blocked": "blocked",
            "quarantine": "blocked",
            "allowed": "success",
        }.get(action, "success")
    fields = [
        kv("date", str(document.get("@timestamp", ""))[:10]),
        kv("time", str(document.get("@timestamp", ""))[11:19]),
        kv("devname", observer),
        kv("devid", get_field(document, "observer", "serial_number")),
        kv("type", get_field(firewall, "type", default="utm")),
        kv("subtype", get_field(firewall, "subtype", default="ips")),
        kv("action", action),
        kv("attack", get_field(firewall, "attack")),
        # The network-attack PPL requires these fields after ECS normalization.
        kv("level", get_field(firewall, "level", default="alert")),
        kv("severity", get_field(firewall, "severity", default="high")),
        kv("srcip", get_field(document, "source", "ip")),
        kv("dstip", get_field(document, "destination", "ip")),
        kv("dstport", get_field(document, "destination", "port")),
        kv("policyid", get_field(document, "rule", "id")),
        kv("policyname", get_field(document, "rule", "name")),
        kv("url", get_field(document, "url", "original")),
        kv("status", status),
        kv("msg", document.get("message")),
    ]
    return " ".join([*raw_header({**document, "observer": {"name": observer}}), *filter(None, fields)])


def build_system_message(document: dict[str, Any]) -> str:
    firewall = get_field(document, "fortinet", "firewall", default={})
    observer = get_field(document, "observer", "name", default="FortiGate")
    fields = [
        kv("date", str(document.get("@timestamp", ""))[:10]),
        kv("time", str(document.get("@timestamp", ""))[11:19]),
        kv("devname", observer),
        kv("devid", get_field(document, "observer", "serial_number")),
        kv("type", get_field(firewall, "type", default="event")),
        kv("subtype", get_field(firewall, "subtype", default="system")),
        kv("action", get_field(document, "event", "action", default="system")),
        kv("user", get_field(document, "source", "user", "name")),
        kv("srcip", get_field(document, "source", "ip")),
        kv("status", get_field(firewall, "status", default="success")),
        kv("ui", get_field(firewall, "ui")),
        kv("logdesc", get_field(document, "rule", "description")),
        kv("msg", document.get("message")),
    ]
    return " ".join([*raw_header({**document, "observer": {"name": observer}}), *filter(None, fields)])


def prepare_document(document: dict[str, Any], scenario: str) -> dict[str, Any]:
    if scenario == "account_security":
        message = build_account_message(document)
        result = {
            "@timestamp": document.get("@timestamp"),
            "@gid": str(document.get("@gid", "")),
            "message": message,
            "event": document.get("event", {}),
        }
    elif scenario == "brute_force":
        result = build_brute_force_document(document)
    elif scenario == "network_attack":
        message = build_network_message(document)
        result = {
            "@timestamp": document.get("@timestamp"),
            "@gid": str(document.get("@gid", "")),
            "message": message,
            # UTM pipeline does not always set event.action from the raw KV.
            "event": document.get("event", {}),
        }
    elif scenario == "system_security":
        message = build_system_message(document)
        result = {
            "@timestamp": document.get("@timestamp"),
            "@gid": str(document.get("@gid", "")),
            "message": message,
            "event": document.get("event", {}),
        }
    else:
        raise ValueError(f"Unsupported scenario: {scenario}")

    if not result.get("message"):
        raise ValueError(f"Document has no message after conversion: {document}")
    return result


def scenario_name(path: Path) -> str:
    return path.name.removesuffix("_samples.json")


def prepare_file(source: Path, target: Path) -> int:
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"{source} must contain a JSON array")
    prepared = [prepare_document(item, scenario_name(source)) for item in payload]
    target.write_text(
        json.dumps(prepared, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(prepared)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=DATA_DIR / "raw_samples")
    parser.add_argument("--output-dir", type=Path, default=DATA_DIR)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    for filename in SCENARIO_FILES:
        source = args.source_dir / filename
        target = args.output_dir / filename
        count = prepare_file(source, target)
        total += count
        print(f"{source} -> {target}: {count} documents")
    print(f"Prepared documents: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
