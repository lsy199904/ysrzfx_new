#!/usr/bin/env python3
"""Generate an isolated, queryable sample set for gid 19935.

The source records represent 2026-03-25 in Asia/Shanghai.  All stored
``@timestamp`` values and FortiGate syslog timestamps are UTC.  The script
does not touch the existing ``data_ruku/*.json`` files for gid 19936.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
RAW = OUT / "raw_samples"
sys.path.insert(0, str(ROOT))

from data_ruku.prepare_pipeline_samples import prepare_document  # noqa: E402


UTC = timezone.utc
GID = "19935"
DEVICES = ("GuZ_BRANCH_100", "GuZ_OFFICE_500E", "GuZ_DC_2000E")


def utc_timestamp(minutes: int, seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp for 2026-03-25 CST."""
    # 2026-03-25 00:00:00+08:00 == 2026-03-24 16:00:00Z.
    value = datetime(2026, 3, 24, 16, 0, tzinfo=UTC) + timedelta(
        minutes=minutes, seconds=seconds
    )
    return value.isoformat().replace("+00:00", "Z")


def header(timestamp: str, host: str, fields: list[str]) -> str:
    return " ".join([timestamp, host, *[item for item in fields if item]])


def brute_force_records() -> list[dict[str, Any]]:
    ips = ("10.35.1.10", "10.35.1.11", "198.51.100.15")
    users = ("admin", "support", "backup_user", "db_admin", "service_api")
    reasons = ("wrong_password", "invalid_credentials", "auth_timeout", "account_locked")
    records = []
    for i in range(36):
        timestamp = utc_timestamp(8 + i * 31, (i * 17) % 60)
        ip = ips[0] if i < 15 else ips[1] if i < 27 else ips[2]
        user = users[i % len(users)]
        reason = reasons[i % len(reasons)]
        device = DEVICES[i % len(DEVICES)]
        if i % 6 == 0:
            subtype = "vpn"
            action = "login"
            status = "failed"
            msg = "SSL user failed to logged in"
            reason_field = "vpn_auth_failed"
        else:
            subtype = "system"
            action = "login"
            status = "failed"
            msg = f"Login failed for user {user}"
            reason_field = reason
        ts = timestamp
        raw = header(
            ts,
            ip,
            [
                f"date={ts[:10]}",
                f"time={ts[11:19]}",
                f'devname="{device}"',
                "devid=FGT19935",
                "type=logon",
                f"subtype={subtype}",
                "level=notice",
                "vd=root",
                f"action={action}",
                f'user="{user}"',
                f"reason={reason_field}",
                f"srcip={ip}",
                f"dstip={ip}",
                f'status="{status}"',
                f'msg="{msg}"',
            ],
        )
        records.append(
            {
                "@timestamp": ts,
                "@gid": GID,
                "source": {"ip": ip, "user": {"name": user}},
                "destination": {"ip": ip},
                "event": {"action": action, "reason": reason_field},
                "observer": {"name": device, "serial_number": "FGT19935"},
                "message": raw,
                "syslog5424_msg": raw,
                "fortinet": {"firewall": {"subtype": subtype, "status": status}},
            }
        )
    return records


def network_attack_records() -> list[dict[str, Any]]:
    # Public source addresses ensure the existing private-to-private exclusion
    # does not discard these records during the network-attack PPL query.
    sources = ("198.51.100.21", "203.0.113.22", "198.51.100.23")
    destinations = ("10.199.0.10", "10.199.0.11", "10.199.0.12")
    attacks = ("Trojan.Generic", "Backdoor.Agent", "Exploit.CVE-2026-1234", "Phishing.URL")
    actions = ("allowed", "warn", "log_only")
    records = []
    for i in range(30):
        timestamp = utc_timestamp(20 + i * 37, (i * 11) % 60)
        src = sources[i % len(sources)]
        dst = destinations[i % len(destinations)]
        device = DEVICES[i % len(DEVICES)]
        attack = attacks[i % len(attacks)]
        action = actions[i % len(actions)]
        severity = "high" if i % 3 else "medium"
        ts = timestamp
        raw = header(
            ts,
            src,
            [
                f"date={ts[:10]}",
                f"time={ts[11:19]}",
                f'devname="{device}"',
                "devid=FGT19935",
                "type=utm",
                "subtype=ips",
                f'action={action}',
                f'attack="{attack}"',
                "level=alert",
                f"severity={severity}",
                f"srcip={src}",
                f"dstip={dst}",
                f"dstport={443 if i % 2 == 0 else 8080}",
                f"policyid={10 + i % 4}",
                f'policyname="Policy {10 + i % 4}.0"',
                f'url="http://malicious-{i}.example.com/payload"',
                f'status="{action}"',
                f'msg="Network attack detected: {attack} from {src} to {dst}"',
            ],
        )
        records.append(
            {
                "fortinet": {
                    "firewall": {
                        "type": "utm",
                        "subtype": "ips",
                        "attack": attack,
                        "level": "alert",
                        "severity": severity,
                    }
                },
                "source": {"ip": src},
                "destination": {"ip": dst, "port": 443 if i % 2 == 0 else 8080},
                "url": {"original": f"http://malicious-{i}.example.com/payload"},
                "@timestamp": ts,
                "@gid": GID,
                "event": {"action": action},
                "observer": {"name": device, "serial_number": "FGT19935"},
                "rule": {"id": str(10 + i % 4), "name": f"Policy {10 + i % 4}.0"},
                "message": raw,
            }
        )
    return records


def account_security_records() -> list[dict[str, Any]]:
    operators = ("10.35.2.10", "10.35.2.11", "198.51.100.60")
    users = ("admin", "chen_ming", "li_si", "db_admin", "backup_user")
    records = []
    for i in range(24):
        timestamp = utc_timestamp(42 + i * 43, (i * 13) % 60)
        ip = operators[i % len(operators)]
        user = users[i % len(users)]
        action = "Add" if i % 2 == 0 else "Delete"
        device = DEVICES[i % len(DEVICES)]
        cfgobj = f"user_local_{user}_{i:02d}"
        description = "Local user added" if action == "Add" else "User account removed"
        verb = "added" if action == "Add" else "deleted"
        raw = header(
            timestamp,
            ip,
            [
                f"date={timestamp[:10]}",
                f"time={timestamp[11:19]}",
                f'devname="{device}"',
                "devid=FGT19935",
                "type=event",
                "subtype=config",
                f"action={action}",
                f'user="{user}"',
                f"srcip={ip}",
                "status=success",
                "srccountry=China",
                "cfgpath=user.local",
                f'cfgobj="{cfgobj}"',
                f'ui="Admin Console ({ip})"',
                f'logdesc="{description}"',
                f'msg="Local user {user} has been {verb}"',
            ],
        )
        records.append(
            {
                "fortinet": {
                    "firewall": {
                        "subtype": "config",
                        "cfgpath": "user.local",
                        "cfgobj": cfgobj,
                        "ui": f"Admin Console ({ip})",
                        "srccountry": "China",
                    }
                },
                "source": {"ip": ip, "user": {"name": user}},
                "@timestamp": timestamp,
                "@gid": GID,
                "event": {"action": action},
                "observer": {"name": device, "serial_number": "FGT19935"},
                "message": f"Local user {user} has been {verb}",
                "rule": {"description": description},
            }
        )
    return records


def system_security_records() -> list[dict[str, Any]]:
    operators = ("10.35.3.10", "10.35.3.11", "198.51.100.70")
    users = ("admin", "chen_ming", "ops_admin", "li_si")
    records = []
    for i in range(24):
        timestamp = utc_timestamp(55 + i * 47, (i * 7) % 60)
        ip = operators[i % len(operators)]
        user = users[i % len(users)]
        device = DEVICES[i % len(DEVICES)]
        description = "Device rebooted" if i % 2 == 0 else "Device shutdown"
        message = f"{description} by user {user}"
        raw = header(
            timestamp,
            ip,
            [
                f"date={timestamp[:10]}",
                f"time={timestamp[11:19]}",
                f'devname="{device}"',
                "devid=FGT19935",
                "type=event",
                "subtype=system",
                "action=system",
                f'user="{user}"',
                f"srcip={ip}",
                "status=success",
                f'ui="Admin Console ({ip})"',
                f'logdesc="{description}"',
                f'msg="{message}"',
            ],
        )
        records.append(
            {
                "fortinet": {"firewall": {"type": "event", "subtype": "system", "ui": f"Admin Console ({ip})"}},
                "event": {"action": "system"},
                "@timestamp": timestamp,
                "@gid": GID,
                "observer": {"name": device, "serial_number": "FGT19935"},
                "source": {"user": {"name": user}, "ip": ip},
                "message": message,
                "rule": {"description": description},
            }
        )
    return records


GENERATORS = {
    "brute_force": brute_force_records,
    "network_attack": network_attack_records,
    "account_security": account_security_records,
    "system_security": system_security_records,
}


def write_json(path: Path, payload: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def normalized_fields(document: dict[str, Any], scenario: str) -> dict[str, Any]:
    """Keep the fields consumed by the current PPL beside the raw message.

    The live FortiGate Pipeline normally derives these fields.  Including
    them in this isolated fixture also makes the sample deterministic when a
    test cluster uses a different Pipeline revision.
    """
    firewall = document.get("fortinet", {}).get("firewall", {})
    result: dict[str, Any] = {
        "@gid": GID,
        "@timestamp": document["@timestamp"],
        "event": document.get("event", {}),
        "source": document.get("source", {}),
        "observer": document.get("observer", {}),
    }
    if scenario == "brute_force":
        result["destination"] = document.get("destination", {})
        result["fortinet"] = {"firewall": {
            "subtype": firewall.get("subtype"),
            "status": firewall.get("status"),
        }}
    elif scenario == "network_attack":
        result.update({
            "destination": document.get("destination", {}),
            "url": document.get("url", {}),
            "rule": document.get("rule", {}),
            "log": {"level": "alert"},
            "fortinet": {"firewall": {
                "type": firewall.get("type", "utm"),
                "subtype": firewall.get("subtype", "ips"),
                "attack": firewall.get("attack"),
                "level": firewall.get("level", "alert"),
                "severity": firewall.get("severity", "high"),
            }},
        })
    elif scenario == "account_security":
        result.update({
            "rule": document.get("rule", {}),
            "fortinet": {"firewall": {
                "subtype": firewall.get("subtype", "config"),
                "cfgpath": firewall.get("cfgpath", "user.local"),
                "cfgobj": firewall.get("cfgobj"),
                "ui": firewall.get("ui"),
                "srccountry": firewall.get("srccountry", "China"),
                "status": "success",
            }},
        })
    elif scenario == "system_security":
        result.update({
            "rule": document.get("rule", {}),
            "fortinet": {"firewall": {
                "type": firewall.get("type", "event"),
                "subtype": firewall.get("subtype", "system"),
                "ui": firewall.get("ui"),
            }},
        })
    return result


def main() -> int:
    for scenario, generator in GENERATORS.items():
        raw = generator()
        raw_path = RAW / f"{scenario}_samples.json"
        prepared_path = OUT / f"{scenario}_samples.json"
        write_json(raw_path, raw)
        prepared = []
        for item in raw:
            document = prepare_document(item, scenario)
            document.update(normalized_fields(item, scenario))
            prepared.append(document)
        write_json(prepared_path, prepared)
        print(f"{scenario}: {len(raw)} raw -> {len(prepared)} prepared")
    print(f"Generated isolated gid {GID} data under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
