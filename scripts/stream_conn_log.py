#!/usr/bin/env python3
"""Stream the generated Zeek-style conn.log over TCP.

This helper can run in two modes:
  server  - listen for a client and stream conn.log lines
  client  - connect to a receiver and send conn.log lines

Example usage:
  python stream_conn_log.py --mode server --host 0.0.0.0 --port 9999 --rate 20
  python stream_conn_log.py --mode client --host localhost --port 9999 --rate 20
"""

import argparse
import socket
import sys
import time
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONN_LOG = BASE_DIR / "dataset" / "conn.log"


def read_conn_log_lines(path: Path, include_header: bool = True) -> Iterable[str]:
    if not path.exists():
        raise FileNotFoundError(f"Conn log not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    if not include_header:
        # skip the Zeek header block
        lines = [line for line in lines if not line.startswith("#")]

    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stream conn.log over TCP")
    parser.add_argument("--mode", choices=["server", "client"], required=True,
                        help="server listens for a connection; client sends to a receiver")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind or connect to")
    parser.add_argument("--port", type=int, default=9999,
                        help="TCP port to bind or connect to")
    parser.add_argument("--conn-log", type=Path, default=DEFAULT_CONN_LOG,
                        help="Path to the generated conn.log file")
    parser.add_argument("--rate", type=float, default=10.0,
                        help="Lines per second to stream (use 0 for as fast as possible)")
    parser.add_argument("--repeat", type=int, default=1,
                        help="How many times to repeat the stream; 0 means infinite")
    parser.add_argument("--no-header", action="store_true",
                        help="Do not send Zeek header lines during streaming")
    return parser


def send_lines(sock: socket.socket, lines: Iterable[str], rate: float) -> int:
    sent = 0
    interval = 1.0 / rate if rate and rate > 0 else 0.0
    for line in lines:
        data = line.encode("utf-8")
        try:
            sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            break
        sent += 1
        if interval:
            time.sleep(interval)
    return sent


def run_server(host: str, port: int, conn_log: Path, rate: float, repeat: int, include_header: bool) -> None:
    lines = read_conn_log_lines(conn_log, include_header=include_header)
    print(f"[server] Listening on {host}:{port} and streaming {len(lines):,} lines")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        conn, addr = listener.accept()
        with conn:
            print(f"[server] Client connected from {addr}")
            loop_count = 0
            while repeat == 0 or loop_count < repeat:
                line_count = send_lines(conn, lines, rate)
                print(f"[server] Sent {line_count} lines (loop {loop_count + 1})")
                loop_count += 1
            print("[server] Stream finished")


def run_client(host: str, port: int, conn_log: Path, rate: float, repeat: int, include_header: bool) -> None:
    lines = read_conn_log_lines(conn_log, include_header=include_header)
    print(f"[client] Connecting to {host}:{port}")

    with socket.create_connection((host, port), timeout=10) as sock:
        loop_count = 0
        while repeat == 0 or loop_count < repeat:
            line_count = send_lines(sock, lines, rate)
            print(f"[client] Sent {line_count} lines (loop {loop_count + 1})")
            loop_count += 1
    print("[client] Connection closed")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.conn_log.exists():
        print(f"ERROR: conn.log not found at {args.conn_log}", file=sys.stderr)
        return 1

    if args.mode == "server":
        run_server(args.host, args.port, args.conn_log, args.rate, args.repeat, not args.no_header)
    else:
        run_client(args.host, args.port, args.conn_log, args.rate, args.repeat, not args.no_header)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
