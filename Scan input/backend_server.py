"""
FLASK BACKEND — Live Zero-Trust Engine + Data API
=============================================
Iss version mein backend ab sirf static JSON files serve nahi karta —
ye khud REAL network connections continuously capture karta hai
(psutil se), aur har cycle mein poora detection pipeline khud chalata hai:

    live capture (this file)
        -> risk_engine.run_risk_engine()
        -> policy_generator.generate_policies()
        -> alert_agent.build_notifications()

...sab kuch ek background thread mein, har `--interval` seconds mein.
Dashboard jab bhi /api/summary maangta hai, use hamesha abhi ki taaza,
real data milta hai — kisi manual script chalane ki zaroorat nahi.

Chalane ka tarika:
    pip install flask flask-cors psutil
    python3 backend_server.py

    (Full visibility ke liye — yaani doosre processes ki connections bhi
    dikhein — Linux/macOS pe 'sudo' se chalao, Windows pe Command Prompt
    ko "Run as Administrator" se kholo. Bina elevated permission ke bhi
    ye chalega, bas apni khud ki process ki connections dikhengi.)

Optional flags:
    --mode live|simulated   (default: live)
    --interval 2.0          (kitne second mein ek naya capture cycle)
    --retention 300         (kitne second purani connections yaad rakhni hain)
    --port 5000
    --host 127.0.0.1

'simulated' mode purane behaviour jaisa hai — sirf jo bhi JSON files
'output/' folder mein already maujood hain (network_simulator.py se) unhe
serve karta hai, koi live capture nahi karta. Ye demo/offline use ke liye hai.

API endpoints (dono modes mein same shape):
    http://localhost:5000/api/summary        <- dashboard yahi use karta hai
    http://localhost:5000/api/status         <- live capture health/state
    http://localhost:5000/api/devices
    http://localhost:5000/api/connections
    http://localhost:5000/api/alerts
    http://localhost:5000/api/policies
    http://localhost:5000/api/notifications
"""

import argparse
import json
import os
import sys
import threading
import time
import traceback
from datetime import datetime, timezone

from flask import Flask, jsonify
from flask_cors import CORS

import live_capture
import network_simulator
import risk_engine
import policy_generator
import alert_agent
import db_store

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app)  # taaki dashboard.html (jo alag origin/file se khulta hai) fetch() kar sake


# =====================================================================
# LIVE STATE — thread-safe store shared between the capture loop and
# the Flask request handlers.
# =====================================================================
class LiveState:
    def __init__(self):
        self.lock = threading.Lock()

        self.seen_devices = {}      # ip -> device dict (accumulates over the process lifetime)
        self.connections = []       # rolling window, pruned by retention
        self.conn_counter = [0]

        self.alerts = []
        self.policies = []
        self.notifications = []

        self.local_ip = None
        self.mode = "STARTING"      # STARTING | LIVE | SIMULATED | ERROR
        self.last_cycle_at = None
        self.cycle_count = 0
        self.last_error = None
        self.permission_limited = False

        # false-positive reduction: baseline learning for the fan-out rule
        self.baseline_destinations = {}  # src_ip -> set(dst_ip), frozen after the learning window
        self.baseline_until = None       # epoch seconds; None until capture_loop starts it

    def snapshot_dict(self):
        with self.lock:
            return {
                "devices": list(self.seen_devices.values()),
                "connections": list(self.connections),
                "generated_at": self.last_cycle_at,
                "mode": self.mode,
            }

    def public_status(self):
        with self.lock:
            baseline_active = bool(self.baseline_until and time.time() < self.baseline_until)
            baseline_seconds_remaining = max(0.0, self.baseline_until - time.time()) if self.baseline_until else 0.0
            return {
                "mode": self.mode,
                "local_ip": self.local_ip,
                "last_cycle_at": self.last_cycle_at,
                "cycle_count": self.cycle_count,
                "device_count": len(self.seen_devices),
                "connection_count": len(self.connections),
                "permission_limited": self.permission_limited,
                "last_error": self.last_error,
                "baseline_active": baseline_active,
                "baseline_seconds_remaining": round(baseline_seconds_remaining, 1),
            }


STATE = LiveState()


# =====================================================================
# LIVE CAPTURE LOOP
# =====================================================================
def _prune_old_connections(connections, retention_seconds):
    """Removes connection records older than the retention window so the
    in-memory list (and the risk-rule inputs) reflect *recent* activity,
    not everything ever seen since the process started."""
    if not connections:
        return connections
    cutoff = time.time() - retention_seconds
    kept = []
    for c in connections:
        try:
            ts = datetime.fromisoformat(c["timestamp"]).timestamp()
        except (KeyError, ValueError):
            ts = time.time()
        if ts >= cutoff:
            kept.append(c)
    return kept


MAX_CONNECTIONS_HARD_CAP = 8000  # safety valve regardless of retention window


def _run_detection_pipeline(snapshot, baseline_destinations=None, learning_mode=False):
    """Runs risk_engine -> policy_generator -> alert_agent on the given
    snapshot, and writes the same JSON files the standalone scripts would
    (so the files on disk stay usable for manual inspection / the old
    'simulated' workflow), while also returning the in-memory results."""
    alerts = risk_engine.run_risk_engine(
        snapshot, baseline_destinations=baseline_destinations, learning_mode=learning_mode
    )
    policies = policy_generator.generate_policies(alerts)
    notifications = alert_agent.build_notifications(alerts_data=alerts, policies_data=policies)

    with open(os.path.join(OUTPUT_DIR, "network_snapshot.json"), "w") as f:
        json.dump(snapshot, f, indent=2)
    with open(os.path.join(OUTPUT_DIR, "risk_alerts.json"), "w") as f:
        json.dump(alerts, f, indent=2)
    with open(os.path.join(OUTPUT_DIR, "generated_policies.json"), "w") as f:
        json.dump(policies, f, indent=2)
    with open(os.path.join(OUTPUT_DIR, "agent_notifications.json"), "w") as f:
        json.dump(notifications, f, indent=2)

    return alerts, policies, notifications


def capture_loop(interval_seconds, retention_seconds, baseline_seconds):
    STATE.local_ip = live_capture.get_local_ip()
    STATE.baseline_until = time.time() + baseline_seconds
    print(f"[*] LIVE mode — local IP detected as {STATE.local_ip}")
    print(f"[*] Capturing real active connections every {interval_seconds}s "
          f"(keeping the last {retention_seconds}s of activity)")
    print(f"[*] Learning normal traffic patterns for the first {baseline_seconds}s "
          f"(fan-out alerts are suppressed during this window so ordinary browsing "
          f"doesn't look like reconnaissance).")
    print(f"[*] Tip: run 'python3 port_scan_simulator.py' in another terminal "
          f"to see a live attack get caught in real time.\n")

    while True:
        try:
            live_capture.clear_process_cache()
            with STATE.lock:
                live_capture.capture_snapshot(
                    STATE.local_ip, STATE.seen_devices, STATE.connections, STATE.conn_counter
                )
                STATE.connections = _prune_old_connections(STATE.connections, retention_seconds)
                if len(STATE.connections) > MAX_CONNECTIONS_HARD_CAP:
                    STATE.connections = STATE.connections[-MAX_CONNECTIONS_HARD_CAP:]
                active_ips = {
                    ip
                    for connection in STATE.connections
                    for ip in (connection["src_ip"], connection["dst_ip"])
                }
                STATE.seen_devices = {
                    ip: device for ip, device in STATE.seen_devices.items()
                    if ip in active_ips
                }
                STATE.permission_limited = False
                STATE.last_error = None

                learning_mode = time.time() < STATE.baseline_until
                if learning_mode:
                    for c in STATE.connections:
                        STATE.baseline_destinations.setdefault(c["src_ip"], set()).add(c["dst_ip"])

            snapshot = STATE.snapshot_dict()
            snapshot["mode"] = "LIVE_CAPTURE"

            alerts, policies, notifications = _run_detection_pipeline(
                snapshot, baseline_destinations=STATE.baseline_destinations, learning_mode=learning_mode
            )

            with STATE.lock:
                STATE.alerts = alerts
                STATE.policies = policies
                STATE.notifications = notifications
                STATE.mode = "LIVE"
                STATE.cycle_count += 1
                STATE.last_cycle_at = datetime.now(timezone.utc).isoformat()

            db_store.record_cycle(
                alerts, policies,
                metrics={
                    "total_devices": len(snapshot["devices"]),
                    "total_connections": len(snapshot["connections"]),
                    "total_alerts": len(alerts),
                    "total_policies": len(policies),
                },
                retention_hours=HISTORY_RETENTION_HOURS,
            )

        except PermissionError:
            with STATE.lock:
                STATE.permission_limited = True
                STATE.last_error = (
                    "Permission denied reading some connections. Run with elevated "
                    "privileges (sudo on Linux/macOS, 'Run as Administrator' on "
                    "Windows) to see connections belonging to other processes."
                )
                STATE.mode = "LIVE"  # still running, just limited visibility
        except Exception as e:
            traceback.print_exc()
            with STATE.lock:
                STATE.last_error = f"{type(e).__name__}: {e}"
                STATE.mode = "ERROR"

        time.sleep(interval_seconds)


def start_live_capture_thread(interval_seconds, retention_seconds, baseline_seconds):
    t = threading.Thread(
        target=capture_loop, args=(interval_seconds, retention_seconds, baseline_seconds), daemon=True
    )
    t.start()
    return t


# =====================================================================
# SIMULATED MODE — old behaviour, serves whatever's already in output/
# =====================================================================
def load_json_file(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        return json.load(f)


# =====================================================================
# API ROUTES
# =====================================================================
def _get_current_data():
    """Single source of truth for every route below. In LIVE mode this
    reads the in-memory state (fast, always current). In SIMULATED mode
    it reads whatever JSON files exist in output/ (old behaviour)."""
    if APP_MODE == "simulated":
        snapshot = load_json_file("network_snapshot.json") or {"devices": [], "connections": []}
        alerts = load_json_file("risk_alerts.json") or []
        policies = load_json_file("generated_policies.json") or []
        notifications = load_json_file("agent_notifications.json") or []
        return snapshot["devices"], snapshot["connections"], alerts, policies, notifications

    with STATE.lock:
        devices = list(STATE.seen_devices.values())
        connections = list(STATE.connections)
        alerts = list(STATE.alerts)
        policies = list(STATE.policies)
        notifications = list(STATE.notifications)
        cycle_count = STATE.cycle_count

    return devices, connections, alerts, policies, notifications


@app.route("/api/status")
def get_status():
    status = STATE.public_status()
    status["backend_mode"] = APP_MODE
    return jsonify(status)


@app.route("/api/history/metrics")
def get_history_metrics():
    from flask import request
    minutes = request.args.get("minutes", default=60, type=float)
    return jsonify(db_store.get_metrics_history(minutes=minutes))


@app.route("/api/history/alerts")
def get_history_alerts():
    from flask import request
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(db_store.get_alerts_history(limit=limit))


@app.route("/api/history/policies")
def get_history_policies():
    from flask import request
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(db_store.get_policies_history(limit=limit))


def _chain_anchor_module():
    """Lazy import so a missing 'web3' package doesn't break the rest of
    the backend — the audit endpoints just report clearly that it's not
    installed instead of crashing the whole server on startup."""
    try:
        import chain_anchor
        return chain_anchor, None
    except ImportError:
        return None, ("'web3' isn't installed, so the on-chain audit log is unavailable. "
                       "Install it with: pip install \"web3[tester]\"")


@app.route("/api/audit/status")
def get_audit_status():
    chain_anchor, err = _chain_anchor_module()
    if err:
        return jsonify({"available": False, "error": err}), 200
    try:
        status = chain_anchor.get_status()
        status["available"] = True
        return jsonify(status)
    except Exception as e:
        return jsonify({"available": False, "error": str(e)}), 200


@app.route("/api/audit/anchor", methods=["POST"])
def post_audit_anchor():
    from flask import request
    chain_anchor, err = _chain_anchor_module()
    if err:
        return jsonify({"error": err}), 503
    label = None
    if request.is_json:
        label = (request.get_json(silent=True) or {}).get("label")
    try:
        record = chain_anchor.anchor_current_state(label=label)
        return jsonify(record)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit/history")
def get_audit_history():
    from flask import request
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(db_store.get_anchor_history(limit=limit))


@app.route("/api/audit/verify")
def get_audit_verify():
    from flask import request
    chain_anchor, err = _chain_anchor_module()
    if err:
        return jsonify({"error": err}), 503
    hex_hash = request.args.get("hash")
    try:
        if hex_hash:
            result = chain_anchor.verify_hash(hex_hash)
        else:
            result = chain_anchor.verify_current_state()
        return jsonify({"found": result is not None, "record": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/devices")
def get_devices():
    devices, _, _, _, _ = _get_current_data()
    return jsonify(devices)


@app.route("/api/connections")
def get_connections():
    _, connections, _, _, _ = _get_current_data()
    return jsonify(connections)


@app.route("/api/alerts")
def get_alerts():
    _, _, alerts, _, _ = _get_current_data()
    return jsonify(alerts)


@app.route("/api/policies")
def get_policies():
    _, _, _, policies, _ = _get_current_data()
    return jsonify(policies)


@app.route("/api/notifications")
def get_notifications():
    _, _, _, _, notifications = _get_current_data()
    return jsonify(notifications)


@app.route("/api/summary")
def get_summary():
    devices, connections, alerts, policies, notifications = _get_current_data()
    return jsonify({
        "devices": devices,
        "connections": connections,
        "alerts": alerts,
        "policies": policies,
        "notifications": notifications,
        "metrics": {
            "total_devices": len(devices),
            "total_connections": len(connections),
            "total_alerts": len(alerts),
            "total_policies": len(policies),
            "total_incidents": len(notifications),
        },
        "backend_mode": APP_MODE,
    })


# =====================================================================
# ENTRYPOINT
# =====================================================================
APP_MODE = "live"
HISTORY_RETENTION_HOURS = 24.0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Trust backend server")
    parser.add_argument("--mode", choices=["live", "simulated"], default="live",
                         help="'live' captures your real active connections continuously. "
                              "'simulated' just serves whatever is already in output/.")
    parser.add_argument("--interval", type=float, default=2.0,
                         help="Seconds between live-capture cycles.")
    parser.add_argument("--retention", type=float, default=300.0,
                         help="Seconds of connection history to keep in the rolling window.")
    parser.add_argument("--history-retention-hours", type=float, default=24.0,
                         help="Hours of metrics_history to keep in the SQLite DB for the trend chart.")
    parser.add_argument("--baseline-seconds", type=float, default=60.0,
                         help="Seconds to observe traffic before enabling the fan-out rule, "
                              "so ordinary browsing isn't mistaken for reconnaissance.")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    APP_MODE = args.mode
    HISTORY_RETENTION_HOURS = args.history_retention_hours
    db_store.init_db()
    print(f"[*] History DB ready at output/zerotrust_history.db "
          f"(metrics kept for {HISTORY_RETENTION_HOURS}h)")

    print("[*] Starting Zero-Trust backend server...")
    print(f"[*] Mode: {APP_MODE.upper()}")

    if APP_MODE == "live":
        try:
            import psutil  # noqa: F401
        except ImportError:
            print("[!] 'psutil' is required for live mode. Install it with:")
            print("      pip install psutil")
            sys.exit(1)
        start_live_capture_thread(args.interval, args.retention, args.baseline_seconds)
    else:
        snapshot_path = os.path.join(OUTPUT_DIR, "network_snapshot.json")
        if not os.path.exists(snapshot_path):
            print("[*] No existing data in output/ — generating a one-time simulated "
                  "network snapshot to bootstrap 'simulated' mode...")
            snapshot = network_simulator.generate_topology_snapshot()
            _run_detection_pipeline(snapshot)
            print("[*] Bootstrapped output/ from network_simulator.py. "
                  "Re-run backend_server.py --mode simulated any time to reuse it, "
                  "or run network_simulator.py yourself to regenerate.")
        else:
            print("[*] Serving whatever is currently in 'output/'. Run network_simulator.py "
                  "again yourself any time to refresh the simulated data.")
        STATE.mode = "SIMULATED"

    print("[*] API available at:")
    print(f"    http://{args.host}:{args.port}/api/summary")
    print(f"    http://{args.host}:{args.port}/api/status")
    print(f"    http://{args.host}:{args.port}/api/devices")
    print(f"    http://{args.host}:{args.port}/api/connections")
    print(f"    http://{args.host}:{args.port}/api/alerts")
    print(f"    http://{args.host}:{args.port}/api/policies")
    print(f"    http://{args.host}:{args.port}/api/notifications")

    app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)
