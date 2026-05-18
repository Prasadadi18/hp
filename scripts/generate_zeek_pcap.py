#!/usr/bin/env python3
"""Generate a synthetic PCAP from the dataset or capture live network traffic, and optionally run Zeek.

This script can operate in two modes:
1. Synthetic: Convert the current dataset into a synthetic TCP packet capture.
2. Live: Capture live network packets for a specified duration.

It writes PCAP to `dataset/conn.pcap` and creates `dataset/zeek/` for Zeek output.

Usage:
    python generate_zeek_pcap.py  # synthetic mode
    python generate_zeek_pcap.py --live --duration 60  # capture live for 60 seconds
    python generate_zeek_pcap.py --run-zeek

Requirements:
    - Python 3.11+
    - scapy for live capture
    - Zeek installed in PATH if using --run-zeek
"""

import argparse
import csv
import os
import shutil
import socket
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import sniff, wrpcap
except ImportError:
    sniff = None
    wrpcap = None

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dataset"
INPUT_CSV = DATA_DIR / "updated_realistic_network_logs.csv"
OUTPUT_PCAP = DATA_DIR / "conn.pcap"
ZEEK_OUTPUT_DIR = DATA_DIR / "zeek"

ETHERNET_HEADER = b"\xaa\xaa\xaa\xaa\xaa\xaa" + b"\xbb\xbb\xbb\xbb\xbb\xbb" + b"\x08\x00"

TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
}

SERVICE_MAP = {
    "read": (80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    "write": (80, b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\nhello=world\r\n"),
    "delete": (80, b"DELETE /resource/1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    "admin": (22, b"SSH-2.0-OpenSSH_8.0\r\n"),
}


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_ipv4_header(src_ip: bytes, dst_ip: bytes, total_length: int, ident: int = 0) -> bytes:
    version_ihl = 0x45
    tos = 0
    flags_frag = 0
    ttl = 64
    proto = 6
    header = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_length, ident, flags_frag, ttl, proto, 0, src_ip, dst_ip)
    chksum = checksum(header)
    return struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_length, ident, flags_frag, ttl, proto, chksum, src_ip, dst_ip)


def build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, window: int, payload: bytes, src_ip: bytes, dst_ip: bytes) -> bytes:
    data_offset = 5
    offset_reserved_flags = (data_offset << 12) | flags
    urg_ptr = 0
    tcp_header = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_reserved_flags, window, 0, urg_ptr)
    pseudo_header = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 6, len(tcp_header) + len(payload))
    chksum = checksum(pseudo_header + tcp_header + payload)
    return struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_reserved_flags, window, chksum, urg_ptr)


def build_packet(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    tcp = build_tcp_header(src_port, dst_port, seq, ack, flags, 65535, payload, src_ip, dst_ip)
    ip = build_ipv4_header(src_ip, dst_ip, 20 + len(tcp) + len(payload))
    return ETHERNET_HEADER + ip + tcp + payload


def pcap_global_header() -> bytes:
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)


def pcap_packet_header(ts: float, length: int) -> bytes:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1000000)
    return struct.pack("<IIII", ts_sec, ts_usec, length, length)


def capture_live_pcap(output_path: Path, duration: int = 60, interface: str = None) -> None:
    if sniff is None or wrpcap is None:
        raise ImportError("scapy is required for live capture. Install with: pip install scapy")
    
    print(f"Capturing live packets for {duration} seconds on interface {interface or 'default'}...")
    packets = sniff(timeout=duration, iface=interface)
    wrpcap(str(output_path), packets)
    print(f"Captured {len(packets)} packets to {output_path}")


def make_resp_ip(workspace_id: str) -> str:
    numeric = ''.join(filter(str.isdigit, workspace_id))
    if numeric:
        suffix = int(numeric[-2:])
    else:
        suffix = 1
    octet = 100 + (suffix % 100)
    return f"192.168.0.{octet}"


def make_ports(event_id: str, action: str) -> tuple[int, int]:
    service_port, _ = SERVICE_MAP.get(action.lower(), (80, b""))
    src_port = 49152 + (abs(hash(event_id)) % 16384)
    return src_port, service_port


def make_payload(action: str, data_mb: float) -> bytes:
    service_payload = SERVICE_MAP.get(action.lower(), (80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))[1]
    size = min(1200, max(0, int(data_mb * 1024 / 10)))
    if size <= len(service_payload):
        return service_payload
    return service_payload + b"X" * (size - len(service_payload))


def parse_timestamp(ts_str: str) -> float:
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc).timestamp()


def write_pcap(rows, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        f.write(pcap_global_header())
        for row in rows:
            ts = parse_timestamp(row["timestamp"])
            src_ip = ip_to_bytes(row["source_ip"])
            dst_ip = ip_to_bytes(make_resp_ip(row["workspace_id"]))
            src_port, dst_port = make_ports(row["event_id"], row.get("action", ""))
            payload = make_payload(row.get("action", ""), float(row.get("data_downloaded_mb", 0) or 0))
            seq = abs(hash(row["event_id"])) & 0xFFFFFFFF
            ack = 1

            packets = [
                (ts, build_packet(src_ip, dst_ip, src_port, dst_port, seq, 0, TCP_FLAGS["SYN"], b"")),
                (ts + 0.0005, build_packet(dst_ip, src_ip, dst_port, src_port, 1, seq + 1, TCP_FLAGS["SYN"] | TCP_FLAGS["ACK"], b"")),
                (ts + 0.001, build_packet(src_ip, dst_ip, src_port, dst_port, seq + 1, 2, TCP_FLAGS["ACK"], b"")),
            ]

            if payload:
                packets.append((ts + 0.002, build_packet(src_ip, dst_ip, src_port, dst_port, seq + 1, 2, TCP_FLAGS["PSH"] | TCP_FLAGS["ACK"], payload)))
            packets.append((ts + 0.003, build_packet(src_ip, dst_ip, src_port, dst_port, seq + 1 + len(payload), 2, TCP_FLAGS["FIN"] | TCP_FLAGS["ACK"], b"")))

            for packet_ts, packet_bytes in packets:
                f.write(pcap_packet_header(packet_ts, len(packet_bytes)))
                f.write(packet_bytes)


def run_zeek(pcap_path: Path, output_dir: Path) -> None:
    if not shutil.which("zeek"):
        print("Zeek binary not found in PATH. Install Zeek or use Docker Compose with the new zeek service.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["zeek", "-C", "-r", str(pcap_path)], cwd=output_dir, check=True)
    print(f"Zeek logs written to {output_dir}")


def load_rows(csv_path: Path):
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a synthetic PCAP or capture live traffic, and run Zeek over it.")
    parser.add_argument("--input", type=Path, default=INPUT_CSV,
                        help="Input CSV dataset path (for synthetic mode)")
    parser.add_argument("--output", type=Path, default=OUTPUT_PCAP,
                        help="Output PCAP file path")
    parser.add_argument("--zeek-output", type=Path, default=ZEEK_OUTPUT_DIR,
                        help="Directory for Zeek-generated logs")
    parser.add_argument("--run-zeek", action="store_true",
                        help="Run Zeek on the generated PCAP (requires Zeek in PATH)")
    parser.add_argument("--live", action="store_true",
                        help="Capture live network packets instead of generating synthetic PCAP")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration in seconds to capture live packets (default: 60)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface to capture on (default: scapy's default)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.live:
        try:
            capture_live_pcap(args.output, args.duration, args.interface)
        except ImportError as exc:
            print(f"Live capture failed: {exc}")
            return 1
    else:
        rows = load_rows(args.input)
        print(f"Loaded {len(rows):,} rows from {args.input}")
        write_pcap(rows, args.output)
        print(f"Created synthetic PCAP: {args.output}")

    if args.run_zeek:
        try:
            run_zeek(args.output, args.zeek_output)
        except Exception as exc:
            print(f"Zeek run failed: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    import shutil

    raise SystemExit(main())
