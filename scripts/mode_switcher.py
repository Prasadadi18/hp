#!/usr/bin/env python3
"""
mode_switcher.py — host-side agent to switch the pipeline between execution modes.

WHY THIS RUNS ON THE HOST (not in a container):
    Both docker-compose.yml (live-replay) and docker-compose.portal.yml (portal)
    include the backend + frontend. Switching modes tears that stack DOWN and
    brings the other UP. Anything inside the stack would kill itself mid-switch.
    This agent runs on the host, so it survives the restart and can drive it.

USAGE (run once on the host, alongside Docker):
    python scripts/mode_switcher.py
    # then leave it running; the dashboard Header button calls it.

ENDPOINTS (CORS-enabled, so the frontend on :5173 can call it):
    GET  /status          -> {"mode": "live-replay" | "portal" | "stopped", "busy": bool}
    POST /switch/live     -> down portal, up live-replay (docker-compose.yml)
    POST /switch/portal   -> down live-replay, up portal (docker-compose.portal.yml)

The compose commands run in a background thread (detached from the HTTP request)
and log to scripts/mode_switcher.log so the response returns immediately.
"""

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 9001
REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = REPO_ROOT / "scripts" / "mode_switcher.log"

COMPOSE_MAIN = "docker-compose.yml"            # live-replay (full stack)
COMPOSE_PORTAL = "docker-compose.portal.yml"   # portal-only

# Switch command sequences (down the other mode first, then up this one)
SWITCH_CMDS = {
    "live": [
        ["docker", "compose", "-f", COMPOSE_PORTAL, "down"],
        ["docker", "compose", "-f", COMPOSE_MAIN, "up", "-d", "--build"],
    ],
    "portal": [
        ["docker", "compose", "-f", COMPOSE_MAIN, "down"],
        ["docker", "compose", "-f", COMPOSE_PORTAL, "up", "-d", "--build"],
    ],
}

# Simple in-process state guard so two switches don't run at once.
_busy_lock = threading.Lock()
_busy = False


def _log(msg: str) -> None:
    line = f"[mode_switcher] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def current_mode() -> str:
    """Detect mode from running containers. hpe-zeek only exists in live-replay."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=10,
        ).stdout
        names = set(out.split())
        if "hpe-zeek" in names:
            return "live-replay"
        if "hpe-backend" in names:
            return "portal"
        return "stopped"
    except Exception as e:
        _log(f"status check failed: {e}")
        return "unknown"


def _run_switch(mode: str) -> None:
    """Run the down+up sequence for a mode. Executed in a background thread."""
    global _busy
    try:
        for cmd in SWITCH_CMDS[mode]:
            _log(f"running: {' '.join(cmd)}")
            proc = subprocess.run(
                cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=1200,
            )
            if proc.returncode != 0:
                _log(f"command failed ({proc.returncode}): {proc.stderr[-500:]}")
            else:
                _log(f"ok: {' '.join(cmd)}")
        _log(f"switch to '{mode}' complete")
    except Exception as e:
        _log(f"switch to '{mode}' errored: {e}")
    finally:
        with _busy_lock:
            _busy = False


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.rstrip("/") == "/status":
            self._json(200, {"mode": current_mode(), "busy": _busy})
        else:
            self._json(404, {"error": "not found", "try": ["/status"]})

    def do_POST(self):
        global _busy
        path = self.path.rstrip("/")
        mode = {"/switch/live": "live", "/switch/portal": "portal"}.get(path)
        if mode is None:
            self._json(404, {"error": "unknown route", "try": ["/switch/live", "/switch/portal"]})
            return

        with _busy_lock:
            if _busy:
                self._json(409, {"error": "a switch is already in progress"})
                return
            _busy = True

        threading.Thread(target=_run_switch, args=(mode,), daemon=True).start()
        target = "live-replay (docker-compose.yml)" if mode == "live" else "portal (docker-compose.portal.yml)"
        self._json(202, {
            "accepted": True,
            "switching_to": mode,
            "message": f"Switching to {target}. The stack is restarting (~30-90s, longer with --build). "
                       f"The dashboard will reconnect once it's back.",
        })

    def log_message(self, *args):
        pass  # silence default per-request stderr noise


def main():
    _log(f"mode switcher listening on http://localhost:{PORT}  (repo: {REPO_ROOT})")
    _log(f"current mode: {current_mode()}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
