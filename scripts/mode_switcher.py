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
    POST /switch/live     -> down portal, up live-replay   (fast, no rebuild)
    POST /switch/portal   -> down live-replay, up portal    (fast, no rebuild)
    POST /rebuild/live    -> same as /switch/live  but with --build
    POST /rebuild/portal  -> same as /switch/portal but with --build

A plain /switch is just a restart (images already built), so it's fast and avoids
the BuildKit snapshot corruption that --build-on-every-switch caused. Use /rebuild
only after changing code. The compose commands run in a background thread (detached
from the HTTP request) and log to scripts/mode_switcher.log.
"""

import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 9001
REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = REPO_ROOT / "scripts" / "mode_switcher.log"

COMPOSE_MAIN = "docker-compose.yml"            # live-replay (full stack)
COMPOSE_PORTAL = "docker-compose.portal.yml"   # portal-only

# Compose file for each mode, and the OTHER file to tear down first.
COMPOSE_FILE = {"live": COMPOSE_MAIN, "portal": COMPOSE_PORTAL}
OTHER_FILE = {"live": COMPOSE_PORTAL, "portal": COMPOSE_MAIN}

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
    """Detect mode from running containers. Both compose files share
    login-portal/ngrok, but only the live-replay (full) stack runs the
    ES->Kafka bridge (hpe-es-to-kafka). We key on that instead of hpe-zeek,
    which is now gated behind a profile and may not be running in live mode."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=10,
        ).stdout
        names = set(out.split())
        if "hpe-es-to-kafka" in names:
            return "live-replay"
        if "hpe-backend" in names:
            return "portal"
        return "stopped"
    except Exception as e:
        _log(f"status check failed: {e}")
        return "unknown"


def _run_switch(mode: str, rebuild: bool = False) -> None:
    """Down the other mode, then up this one. Executed in a background thread.

    By default we do a plain `up -d` (no --build) — images are already built, so
    a switch is just a fast restart. This avoids hammering the BuildKit snapshot
    store on every switch (the "parent snapshot does not exist" corruption). Pass
    rebuild=True (via /rebuild/*) only when the code actually changed.
    """
    global _busy
    try:
        down_cmd = ["docker", "compose", "-f", OTHER_FILE[mode], "down"]
        # NOTE: we deliberately do NOT enable the 'live-replay' compose profile.
        # The Zeek replay stream (replay/filebeat-live) carries no user identity
        # and floods the pipeline with unenrichable "unknown / 30.3%" events. The
        # dashboard's Simulate WebSocket already streams the labelled
        # test_events.json into Kafka (real users + varied scores), so live mode
        # = core stack + Simulate feed. Plain up; portal has no profiles either.
        up_cmd = ["docker", "compose", "-f", COMPOSE_FILE[mode], "up", "-d"]
        if rebuild:
            up_cmd.append("--build")

        _log(f"running: {' '.join(down_cmd)}")
        proc = subprocess.run(
            down_cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
        )
        if proc.returncode != 0:
            _log(f"down failed ({proc.returncode}): {proc.stderr[-500:]}")
        else:
            _log(f"ok: {' '.join(down_cmd)}")

        # Brief pause so the shared compose network is fully released before we
        # recreate it — avoids the "network <id> not found" race on a fast up.
        time.sleep(3)

        # Bring the target stack up, retrying once on the transient network race.
        for attempt in (1, 2):
            suffix = f" (attempt {attempt})" if attempt > 1 else ""
            _log(f"running: {' '.join(up_cmd)}{suffix}")
            proc = subprocess.run(
                up_cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=1200,
            )
            if proc.returncode == 0:
                _log(f"ok: {' '.join(up_cmd)}")
                break
            _log(f"up failed ({proc.returncode}): {proc.stderr[-500:]}")
            if attempt == 1:
                time.sleep(5)
        _log(f"switch to '{mode}'{' (rebuild)' if rebuild else ''} complete")
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
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Browser closed the poll connection mid-response (normal on page
            # refresh/navigation). Nothing to send to; drop it quietly.
            pass

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
        # (mode, rebuild) for each route. /switch/* is a fast restart (no build);
        # /rebuild/* rebuilds images first — use only after changing code.
        routes = {
            "/switch/live": ("live", False),
            "/switch/portal": ("portal", False),
            "/rebuild/live": ("live", True),
            "/rebuild/portal": ("portal", True),
        }
        entry = routes.get(path)
        if entry is None:
            self._json(404, {"error": "unknown route", "try": list(routes)})
            return
        mode, rebuild = entry

        with _busy_lock:
            if _busy:
                self._json(409, {"error": "a switch is already in progress"})
                return
            _busy = True

        threading.Thread(target=_run_switch, args=(mode, rebuild), daemon=True).start()
        target = "live-replay (docker-compose.yml)" if mode == "live" else "portal (docker-compose.portal.yml)"
        eta = "~1-3 min (rebuilding images)" if rebuild else "~30-90s"
        self._json(202, {
            "accepted": True,
            "switching_to": mode,
            "rebuild": rebuild,
            "message": f"Switching to {target}. The stack is restarting ({eta}). "
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
