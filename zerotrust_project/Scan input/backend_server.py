from flask import Flask, jsonify
from flask_cors import CORS
import json
import os
import sys
import subprocess
import threading
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


CAPTURE_DURATION_SECONDS = 30   
PYTHON_EXE = sys.executable     

def load_json(filename, retries=3, delay=0.15):
    
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return None
    for attempt in range(retries):
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return None


# ============================================================
# BACKGROUND LOOP — continuous live-capture pipeline
# ============================================================
def run_script(script_name, extra_args=None):
    """Ek script ko subprocess se chalata hai aur poora hone ka wait karta hai."""
    cmd = [PYTHON_EXE, os.path.join(SCRIPT_DIR, script_name)]
    if extra_args:
        cmd.extend(extra_args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[LOOP] WARNING: {script_name} exited with error:\n{result.stderr[-500:]}")
    return result.returncode == 0


def live_capture_loop():
    """
    Ye function ek alag background-thread mein HAMESHA chalta rehta hai —
    jab tak backend server on hai. Har cycle mein: capture -> detect ->
    suggest-policy -> AI-agent, phir turant agla cycle.
    """
    cycle_num = 0
    while True:
        cycle_num += 1
        print(f"\n[LOOP] === Cycle {cycle_num} starting at {datetime.now().strftime('%H:%M:%S')} ===")

        ok = run_script("live_capture.py", ["--duration", str(CAPTURE_DURATION_SECONDS), "--interval", "0.5"])
        if ok:
            run_script("risk_engine.py")
            run_script("policy_generator.py")
            run_script("alert_agent.py")
            print(f"[LOOP] === Cycle {cycle_num} complete — dashboard has fresh data ===")
        else:
            print(f"[LOOP] Cycle {cycle_num} had an error during capture — retrying next cycle.")
            time.sleep(3)  # thoda ruk ke retry karo agar capture hi fail ho gaya


# ============================================================
# API ROUTES
# ============================================================
@app.route("/api/devices")
def get_devices():
    snapshot = load_json("network_snapshot.json")
    if snapshot is None:
        return jsonify({"error": "No data yet — first live-capture cycle is still running (~30-40s)."}), 404
    return jsonify(snapshot["devices"])


@app.route("/api/connections")
def get_connections():
    snapshot = load_json("network_snapshot.json")
    if snapshot is None:
        return jsonify({"error": "No data yet."}), 404
    return jsonify(snapshot["connections"])


@app.route("/api/alerts")
def get_alerts():
    alerts = load_json("risk_alerts.json")
    if alerts is None:
        return jsonify({"error": "No data yet."}), 404
    return jsonify(alerts)


@app.route("/api/policies")
def get_policies():
    policies = load_json("generated_policies.json")
    if policies is None:
        return jsonify({"error": "No data yet."}), 404
    return jsonify(policies)


@app.route("/api/notifications")
def get_notifications():
    notifications = load_json("agent_notifications.json")
    if notifications is None:
        return jsonify({"error": "No data yet."}), 404
    return jsonify(notifications)


@app.route("/api/summary")
def get_summary():
    snapshot = load_json("network_snapshot.json") or {"devices": [], "connections": []}
    alerts = load_json("risk_alerts.json") or []
    policies = load_json("generated_policies.json") or []
    notifications = load_json("agent_notifications.json") or []

    return jsonify({
        "devices": snapshot.get("devices", []),
        "connections": snapshot.get("connections", []),
        "alerts": alerts,
        "policies": policies,
        "notifications": notifications,
        "mode": snapshot.get("mode", "UNKNOWN"),
        "last_updated": snapshot.get("generated_at"),
        "metrics": {
            "total_devices": len(snapshot.get("devices", [])),
            "total_connections": len(snapshot.get("connections", [])),
            "total_alerts": len(alerts),
            "total_policies": len(policies),
            "total_incidents": len(notifications),
        }
    })


if __name__ == "__main__":
    print("[*] Starting backend server WITH continuous live-capture loop...")
    print(f"[*] Each cycle captures ~{CAPTURE_DURATION_SECONDS}s of REAL traffic, then re-runs detection.")
    print("[*] API available at http://localhost:5000/api/summary")
    print("[*] Pehla cycle poora hone mein ~30-40 second lagenge — dashboard tab tak")
    print("    'No data yet' dikha sakta hai, uske baad hamesha fresh data milega.\n")

    # Background thread mein infinite capture-loop shuru karo
    loop_thread = threading.Thread(target=live_capture_loop, daemon=True)
    loop_thread.start()

    # use_reloader=False zaroori hai — warna Flask ka debug-reloader is
    # process ko DUPLICATE kar dega, aur background-loop 2 baar chalne lagega
    app.run(debug=True, port=5000, use_reloader=False)
