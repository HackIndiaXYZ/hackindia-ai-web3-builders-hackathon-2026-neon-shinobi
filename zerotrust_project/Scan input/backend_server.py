"""
FLASK BACKEND — Stitch UI ke liye Data API
=============================================
Ye server tumhare 3 JSON files (network_snapshot, risk_alerts,
generated_policies) ko web-API endpoints se serve karta hai, taaki
Stitch se banaya hua frontend (HTML/CSS/JS) inhe fetch() se le sake.

Chalane ka tarika:
    pip install flask flask-cors
    python3 backend_server.py

Uske baad API available hogi:
    http://localhost:5000/api/devices
    http://localhost:5000/api/connections
    http://localhost:5000/api/alerts
    http://localhost:5000/api/policies
    http://localhost:5000/api/summary   (sab kuch ek saath, dashboard ke liye)
"""

from flask import Flask, jsonify
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app)  # ye zaroori hai taaki tumhara HTML file (jo alag se khulega browser mein)
           # is server se data maang sake bina "blocked by CORS" error ke

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")


def load_json(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        return json.load(f)


@app.route("/api/devices")
def get_devices():
    snapshot = load_json("network_snapshot.json")
    if snapshot is None:
        return jsonify({"error": "network_snapshot.json not found. Run network_simulator.py first."}), 404
    return jsonify(snapshot["devices"])


@app.route("/api/connections")
def get_connections():
    snapshot = load_json("network_snapshot.json")
    if snapshot is None:
        return jsonify({"error": "network_snapshot.json not found."}), 404
    return jsonify(snapshot["connections"])


@app.route("/api/alerts")
def get_alerts():
    alerts = load_json("risk_alerts.json")
    if alerts is None:
        return jsonify({"error": "risk_alerts.json not found. Run risk_engine.py first."}), 404
    return jsonify(alerts)


@app.route("/api/policies")
def get_policies():
    policies = load_json("generated_policies.json")
    if policies is None:
        return jsonify({"error": "generated_policies.json not found. Run policy_generator.py first."}), 404
    return jsonify(policies)


@app.route("/api/notifications")
def get_notifications():
    """
    AI Agent ka output — correlated, prioritized, explained incidents.
    Dashboard ka notification-bell isi endpoint se data lega (raw alerts
    ki jagah), taaki analyst ko clean, de-duplicated, reasoned notifications
    dikhein na ki raw noisy alerts.
    """
    notifications = load_json("agent_notifications.json")
    if notifications is None:
        return jsonify({"error": "agent_notifications.json not found. Run alert_agent.py first."}), 404
    return jsonify(notifications)


@app.route("/api/summary")
def get_summary():
    """
    Ek hi call mein sab kuch — Stitch UI ke liye sabse convenient endpoint.
    Dashboard load hote hi ye ek call kar sakta hai, sab data mil jaayega.
    """
    snapshot = load_json("network_snapshot.json") or {"devices": [], "connections": []}
    alerts = load_json("risk_alerts.json") or []
    policies = load_json("generated_policies.json") or []
    notifications = load_json("agent_notifications.json") or []

    return jsonify({
        "devices": snapshot["devices"],
        "connections": snapshot["connections"],
        "alerts": alerts,
        "policies": policies,
        "notifications": notifications,
        "metrics": {
            "total_devices": len(snapshot["devices"]),
            "total_connections": len(snapshot["connections"]),
            "total_alerts": len(alerts),
            "total_policies": len(policies),
            "total_incidents": len(notifications),
        }
    })


if __name__ == "__main__":
    print("[*] Starting backend server...")
    print("[*] API available at:")
    print("    http://localhost:5000/api/summary   <- Stitch UI ye use karega")
    print("    http://localhost:5000/api/devices")
    print("    http://localhost:5000/api/connections")
    print("    http://localhost:5000/api/alerts")
    print("    http://localhost:5000/api/policies")
    print("    http://localhost:5000/api/notifications   <- AI Agent output")
    app.run(debug=True, port=5000)
