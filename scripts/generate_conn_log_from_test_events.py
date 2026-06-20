#!/usr/bin/env python3
"""Generate the replayed Zeek conn.log FROM test_events.json.

WHY THIS EXISTS:
    Live-replay enrichment (threat_engine.get_event_from_lookup) keys each
    replayed connection's `uid` against test_events.json's `event_id`. If the
    conn.log being replayed was generated from a different source (different
    uids/IPs), every lookup misses and the dashboard shows every event as
    `unknown / connection / <constant model score>`.

    This script emits dataset/zeek/conn.log directly from test_events.json with
    `uid = event_id`, so enrichment resolves every connection back to its real
    user + features, and the AI engine produces varied, meaningful scores.

Usage:
    python scripts/generate_conn_log_from_test_events.py

Output:
    dataset/zeek/conn.log   (the file the `replay` service streams)
    A timestamped backup of any existing conn.log is kept alongside it.
"""

import json
import math
import shutil
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_EVENTS = REPO_ROOT / "model_output" / "test_events.json"
OUTPUT_LOG = REPO_ROOT / "dataset" / "zeek" / "conn.log"

# Must match the layout the existing conn.log / filebeat pipeline expects.
FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
    "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]
TYPES = [
    "time", "string", "addr", "port", "addr", "port", "enum", "string",
    "interval", "count", "count", "string", "bool", "bool", "count", "string",
    "count", "count", "count", "count", "set[string]",
]

# action -> Zeek service. Dataset events are NOT auth_* (those are live portal
# logins), so they take the "connection" enrichment path in threat_engine.
SERVICE_MAP = {"read": "http", "write": "http", "delete": "http", "admin": "ssh"}


def _safe_float(v, default=0.0):
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


def _epoch(ts_str: str) -> float:
    s = str(ts_str).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        # Already an epoch?
        return _safe_float(ts_str, datetime.now(timezone.utc).timestamp())


def _resp_ip(workspace_id: str) -> str:
    try:
        suffix = int("".join(filter(str.isdigit, str(workspace_id)))[-2:])
    except (ValueError, IndexError):
        suffix = 1
    return f"192.168.0.{100 + (suffix % 100)}"


def _ports(event_id: str, service: str) -> tuple[int, int]:
    orig_p = 49152 + (abs(hash(event_id)) % 16000)
    resp_p = 22 if service == "ssh" else 80
    return orig_p, resp_p


def main() -> None:
    if not TEST_EVENTS.exists():
        raise FileNotFoundError(f"test_events.json not found: {TEST_EVENTS}")

    events = json.loads(TEST_EVENTS.read_text(encoding="utf-8"))
    if not isinstance(events, list) or not events:
        raise ValueError("test_events.json is empty or not a JSON array")

    OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT_LOG.exists():
        backup = OUTPUT_LOG.with_suffix(
            f".bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        )
        shutil.copy2(OUTPUT_LOG, backup)
        print(f"Backed up existing conn.log -> {backup.name}")

    now = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    rows_written = 0
    with OUTPUT_LOG.open("w", encoding="utf-8", newline="") as out:
        out.write("#separator \\x09\n")
        out.write("#set_separator\t,\n")
        out.write("#empty_field\t(empty)\n")
        out.write("#unset_field\t-\n")
        out.write("#path\tconn\n")
        out.write(f"#open\t{now}\n")
        out.write("#fields\t" + "\t".join(FIELDS) + "\n")
        out.write("#types\t" + "\t".join(TYPES) + "\n")

        for ev in events:
            event_id = ev.get("event_id")
            if not event_id:
                continue
            action = str(ev.get("action", "")).lower()
            service = SERVICE_MAP.get(action, "http")
            data_mb = _safe_float(ev.get("data_downloaded_mb", 0))
            orig_bytes = int(max(0, data_mb * 1024 * 1024))
            resp_bytes = int(orig_bytes * 0.2)
            success = str(ev.get("success", "")).strip().lower() in ("true", "1")
            orig_p, resp_p = _ports(event_id, service)

            row = [
                f"{_epoch(ev.get('timestamp')):.6f}",
                event_id,                              # uid == event_id (the fix)
                str(ev.get("source_ip", "-")),
                str(orig_p),
                _resp_ip(ev.get("workspace_id", "")),
                str(resp_p),
                "tcp",
                service,
                f"{max(0.01, min(3600.0, data_mb * 0.15)):.6f}",
                str(orig_bytes),
                str(resp_bytes),
                "SF" if success else "REJ",
                "-", "-", "0", "ShADF",
                str(max(1, math.ceil(orig_bytes / 1500))),
                str(orig_bytes),
                str(max(1, math.ceil(resp_bytes / 1500))),
                str(resp_bytes),
                "-",                                   # tunnel_parents
            ]
            out.write("\t".join(row) + "\n")
            rows_written += 1

        out.write(f"#close\t{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}\n")

    print(f"Wrote {rows_written} connections to {OUTPUT_LOG}")
    print("Every uid == its event_id, so live-replay enrichment now resolves.")


if __name__ == "__main__":
    main()
