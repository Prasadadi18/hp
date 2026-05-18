#!/usr/bin/env python3
"""Generate a Zeek-style conn.log from the CSV dataset.

Usage:
    python generate_conn_log.py

Output:
    conn.log              # Zeek-style connection log in the repository root
    dataset/conn.log      # Optional copy inside dataset/
"""

import csv
import math
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dataset"
INPUT_CSV = DATA_DIR / "updated_realistic_network_logs.csv"
OUTPUT_LOG = BASE_DIR / "conn.log"
OUTPUT_LOG_DATASET = DATA_DIR / "conn.log"

ZEEL_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
]

SERVICE_MAP = {
    "read": "http",
    "write": "http",
    "delete": "http",
    "admin": "ssh",
}

def safe_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def make_resp_ip(workspace_id: str) -> str:
    # Deterministic server IP based on workspace ID
    try:
        suffix = int(''.join(filter(str.isdigit, workspace_id))[-2:])
    except Exception:
        suffix = 1
    octet = 100 + (suffix % 100)
    return f"192.168.0.{octet}"


def make_ports(event_id: str, service: str) -> tuple[int, int]:
    if service == "ssh":
        return 49152 + (abs(hash(event_id)) % 1000), 22
    return 49152 + (abs(hash(event_id)) % 1000), 80


def format_timestamp(ts_str: str) -> str:
    dt = datetime.fromisoformat(ts_str)
    epoch = dt.timestamp()
    return f"{epoch:.6f}"


def make_duration(data_mb: float) -> float:
    return max(0.01, min(3600.0, data_mb * 0.15))


def make_bytes(data_mb: float) -> int:
    return int(max(0, data_mb * 1024 * 1024))


def main():
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Dataset not found: {INPUT_CSV}")

    print(f"Reading dataset: {INPUT_CSV}")
    with INPUT_CSV.open(newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        rows = list(reader)

    if not rows:
        raise ValueError("No rows found in dataset")

    print(f"Writing Zeek conn.log to: {OUTPUT_LOG}")
    with OUTPUT_LOG.open("w", encoding="utf-8", newline="") as out:
        out.write("#separator \x09\n")
        out.write("#set_separator ,\n")
        out.write("#empty_field (empty)\n")
        out.write("#unset_field -\n")
        out.write(f"#path {OUTPUT_LOG.name}\n")
        out.write(f"#open {datetime.utcnow().isoformat()}\n")
        out.write("#fields " + "\t".join(ZEEL_FIELDS) + "\n")
        out.write("#types " + "\t".join([
            "double",
            "string",
            "addr",
            "port",
            "addr",
            "port",
            "string",
            "string",
            "double",
            "count",
            "count",
            "string",
            "bool",
            "bool",
            "count",
            "string",
            "count",
            "count",
            "count",
            "count",
        ]) + "\n")

        for row in rows:
            service = SERVICE_MAP.get(row.get("action", "").lower(), "unknown")
            ts = format_timestamp(row["timestamp"])
            uid = row.get("event_id", "-")
            orig_h = row.get("source_ip", "-")
            resp_h = make_resp_ip(row.get("workspace_id", ""))
            proto = "tcp"
            duration = make_duration(safe_float(row.get("data_downloaded_mb", 0)))
            orig_bytes = make_bytes(safe_float(row.get("data_downloaded_mb", 0)))
            resp_bytes = int(orig_bytes * 0.2)
            conn_state = "SF" if row.get("success", "False").strip().lower() == "true" else "REJ"
            orig_p, resp_p = make_ports(uid, service)
            orig_pkts = max(1, math.ceil(orig_bytes / 1500))
            resp_pkts = max(1, math.ceil(resp_bytes / 1500))
            orig_ip_bytes = orig_bytes
            resp_ip_bytes = resp_bytes

            values = [
                ts,
                uid,
                orig_h,
                str(orig_p),
                resp_h,
                str(resp_p),
                proto,
                service,
                f"{duration:.6f}",
                str(orig_bytes),
                str(resp_bytes),
                conn_state,
                "-",
                "-",
                "0",
                "S",
                str(orig_pkts),
                str(orig_ip_bytes),
                str(resp_pkts),
                str(resp_ip_bytes),
            ]
            out.write("\t".join(values) + "\n")

    print(f"Generated {OUTPUT_LOG} ({len(rows)} connections)")

    # Copy into dataset/ for convenience
    with OUTPUT_LOG_DATASET.open("w", encoding="utf-8", newline="") as out_dataset:
        with OUTPUT_LOG.open("r", encoding="utf-8") as source:
            out_dataset.write(source.read())

    print(f"Copied conn.log to {OUTPUT_LOG_DATASET}")


if __name__ == "__main__":
    main()
