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
<<<<<<< HEAD
import ai_security_analyst
=======
>>>>>>> aedc1db9c0a785e87c7499f58808919e6eb2e90c

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
        self.device_counter = [0]

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
    # Re-apply any previously recorded human decision to regenerated policies.
    for policy in policies:
        decision = db_store.get_policy_decision(policy.get("policy_id"))
        if decision:
            policy["status"] = decision["decision"]
            policy["reviewer"] = decision["reviewer"]
            policy["decided_at"] = decision["decided_at"]
        else:
            policy["status"] = "SUGGESTED"
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
                    STATE.local_ip, STATE.seen_devices, STATE.connections, STATE.conn_counter, STATE.device_counter
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
# ZERO-TRUST SEGMENTATION MODEL
# =====================================================================
# Explicit communication intent for the known simulated enterprise
# segments. LIVE traffic may contain "internet" / "local_network" roles;
# those are handled by the same deterministic policy table.
SEGMENT_POLICIES = [
    {"source": "guest", "destination": "server", "decision": "DENY", "reason": "Guest networks must not directly reach production servers."},
    {"source": "guest", "destination": "employee", "decision": "DENY", "reason": "Guest devices must not directly reach employee endpoints."},
    {"source": "guest", "destination": "iot", "decision": "DENY", "reason": "Guest devices must not administer IoT devices."},
    {"source": "guest", "destination": "internet", "decision": "ALLOW", "reason": "Guest users may access the internet."},
    {"source": "employee", "destination": "server", "decision": "ALLOW", "reason": "Employees may reach approved business servers."},
    {"source": "employee", "destination": "employee", "decision": "ALLOW", "reason": "Employee-to-employee communication is permitted."},
    {"source": "employee", "destination": "internet", "decision": "ALLOW", "reason": "Employees may access the internet."},
    {"source": "server", "destination": "server", "decision": "ALLOW", "reason": "Server-to-server service traffic is permitted."},
    {"source": "server", "destination": "employee", "decision": "RESTRICTED", "reason": "Servers should initiate endpoint traffic only for approved services."},
    {"source": "server", "destination": "internet", "decision": "RESTRICTED", "reason": "Server egress is restricted to approved destinations."},
    {"source": "iot", "destination": "server", "decision": "DENY", "reason": "IoT devices must not directly reach production servers."},
    {"source": "iot", "destination": "employee", "decision": "DENY", "reason": "IoT devices must not directly reach employee endpoints."},
    {"source": "iot", "destination": "iot", "decision": "ALLOW", "reason": "IoT-to-IoT communication is permitted where required."},
    {"source": "iot", "destination": "internet", "decision": "RESTRICTED", "reason": "IoT egress should be limited to required services."},
    {"source": "local_network", "destination": "employee", "decision": "RESTRICTED", "reason": "Unclassified LAN devices require explicit authorization before endpoint access."},
    {"source": "local_network", "destination": "server", "decision": "DENY", "reason": "Unclassified LAN devices must not directly reach production servers."},
    {"source": "internet", "destination": "employee", "decision": "DENY", "reason": "Unsolicited internet-to-endpoint access is denied."},
    {"source": "internet", "destination": "server", "decision": "DENY", "reason": "Unsolicited internet-to-server access is denied."},
]

SEGMENT_DEFAULT = {
    "guest": "DENY",
    "employee": "RESTRICTED",
    "server": "RESTRICTED",
    "iot": "DENY",
    "internet": "DENY",
    "local_network": "RESTRICTED",
}


def get_segment_policy(source_segment, destination_segment):
    """Return the deterministic communication decision for two segments."""
    source = str(source_segment or "unknown").lower()
    destination = str(destination_segment or "unknown").lower()
    for rule in SEGMENT_POLICIES:
        if rule["source"] == source and rule["destination"] == destination:
            return dict(rule)
    if source == destination and source in {"guest", "employee", "server", "iot"}:
        return {"source": source, "destination": destination, "decision": "ALLOW",
                "reason": "Same-segment traffic is permitted unless a more specific rule blocks it."}
    return {"source": source, "destination": destination, "decision": SEGMENT_DEFAULT.get(source, "DENY"),
            "reason": "No explicit trust relationship exists for this segment pair."}


def evaluate_segmentation(connections):
    """Evaluate observed connections against the segmentation policy model.

    This is intentionally advisory: it does not modify the host firewall.
    """
    evaluations = []
    for conn in connections:
        rule = get_segment_policy(conn.get("src_segment"), conn.get("dst_segment"))
        evaluations.append({
            "conn_id": conn.get("conn_id"),
            "src_ip": conn.get("src_ip"),
            "src_segment": conn.get("src_segment"),
            "dst_ip": conn.get("dst_ip"),
            "dst_segment": conn.get("dst_segment"),
            "dst_port": conn.get("dst_port"),
            "process_name": conn.get("process_name"),
            "decision": rule["decision"],
            "reason": rule["reason"],
        })
    return evaluations


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
        for policy in policies:
            decision = db_store.get_policy_decision(policy.get("policy_id"))
            if decision:
                policy["status"] = decision["decision"]
                policy["reviewer"] = decision["reviewer"]
                policy["decided_at"] = decision["decided_at"]
            else:
                policy["status"] = "SUGGESTED"
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


@app.route("/api/policies/<policy_id>/decision", methods=["POST"])
def post_policy_decision(policy_id):
    from flask import request

    payload = request.get_json(silent=True) or {}
    decision = str(payload.get("decision", "")).upper()
    reviewer = payload.get("reviewer", "Sys Admin")
    if decision not in {"APPROVED", "REJECTED"}:
        return jsonify({"error": "decision must be APPROVED or REJECTED"}), 400

    _, _, _, policies, _ = _get_current_data()
    policy = next((p for p in policies if p.get("policy_id") == policy_id), None)
    if policy is None:
        return jsonify({"error": "Policy not found in the current active policy set"}), 404

    try:
        db_store.set_policy_decision(policy_id, decision, reviewer=reviewer)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    decision_record = db_store.get_policy_decision(policy_id)
    policy["status"] = decision_record["decision"]
    policy["reviewer"] = decision_record["reviewer"]
    policy["decided_at"] = decision_record["decided_at"]
    with STATE.lock:
        for current in STATE.policies:
            if current.get("policy_id") == policy_id:
                current.update(policy)
                break
    return jsonify(policy)


@app.route("/api/policy-decisions")
def get_policy_decisions():
    from flask import request
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(db_store.get_policy_decisions(limit=limit))


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


@app.route("/api/segmentation")
def get_segmentation():
    """Return the configured segment-to-segment Zero-Trust policy model and
    a summary of how current observed connections evaluate against it."""
    devices, connections, _, _, _ = _get_current_data()
    evaluations = evaluate_segmentation(connections)
    counts = {"ALLOW": 0, "RESTRICTED": 0, "DENY": 0}
    for item in evaluations:
        counts[item["decision"]] = counts.get(item["decision"], 0) + 1
    violations = [item for item in evaluations if item["decision"] == "DENY"]
    segment_counts = {}
    for device in devices:
        segment = device.get("segment", "unknown")
        segment_counts[segment] = segment_counts.get(segment, 0) + 1
    return jsonify({
        "segments": segment_counts,
        "policies": SEGMENT_POLICIES,
        "default_decisions": SEGMENT_DEFAULT,
        "evaluation_summary": counts,
        "evaluated_connections": evaluations,
        "denied_connections": violations,
        "mode": APP_MODE,
    })


@app.route("/api/policy-simulation", methods=["POST"])
def policy_simulation():
    """Read-only what-if analysis for a proposed segment decision.

    The request never mutates the configured policy model, database decisions,
    or host firewall. Impact is calculated from the currently observed dataset.
    """
    from flask import request
    payload = request.get_json(silent=True) or {}
    source = str(payload.get("src_segment") or "").lower()
    destination = str(payload.get("dst_segment") or "").lower()
    proposed = str(payload.get("proposed_decision") or "").upper()
    if not source or not destination:
        return jsonify({"error": "src_segment and dst_segment are required"}), 400
    if proposed not in {"ALLOW", "RESTRICTED", "DENY"}:
        return jsonify({"error": "proposed_decision must be ALLOW, RESTRICTED, or DENY"}), 400

    devices, connections, _, _, _ = _get_current_data()
    current_rule = get_segment_policy(source, destination)
    source_assets = {d.get("ip") for d in devices if str(d.get("segment", "")).lower() == source}
    destination_assets = {d.get("ip") for d in devices if str(d.get("segment", "")).lower() == destination}
    affected = [c for c in connections
                if str(c.get("src_segment", "")).lower() == source
                and str(c.get("dst_segment", "")).lower() == destination]
    services = sorted({str(c.get("dst_port")) for c in affected if c.get("dst_port") is not None})

    current = current_rule["decision"]
    if current == proposed:
        policy_change = "No change — proposed decision matches the current model."
    else:
        policy_change = f"{current} → {proposed}"

    if proposed == "DENY":
        security_effect = "High — the proposed deny blocks this segment path."
        service_exposure = f"{len(services)} observed destination port(s) would be blocked" if services else "No destination ports observed"
    elif proposed == "RESTRICTED":
        security_effect = "Medium — communication remains conditional on explicit service authorization."
        service_exposure = f"{len(services)} observed destination port(s) would require review" if services else "No destination ports observed"
    else:
        security_effect = "Low — the proposed allow permits this segment path."
        service_exposure = f"{len(services)} observed destination port(s) would be permitted" if services else "No destination ports observed"

    return jsonify({
        "source": source, "destination": destination,
        "current_decision": current, "proposed_decision": proposed,
        "reason": current_rule["reason"], "policy_change": policy_change,
        "affected_connections": len(affected),
        "affected_assets": len(source_assets | destination_assets),
        "source_assets": len(source_assets),
        "destination_assets": len(destination_assets),
        "services": services[:25],
        "security_effect": security_effect,
        "service_exposure": service_exposure,
        "mode": APP_MODE, "advisory_only": True
    })


@app.route("/api/segmentation/evaluate", methods=["POST"])
def evaluate_segmentation_request():
    """Evaluate one hypothetical connection without changing any state."""
    from flask import request
    payload = request.get_json(silent=True) or {}
    source = payload.get("src_segment")
    destination = payload.get("dst_segment")
    if not source or not destination:
        return jsonify({"error": "src_segment and dst_segment are required"}), 400
    return jsonify(get_segment_policy(source, destination))


@app.route("/api/devices")
def get_devices():
    devices, _, _, _, _ = _get_current_data()
    return jsonify(devices)


def _build_device_profile(ip, devices, connections, alerts, policies):
    """Build a security-oriented asset profile from currently observed data.

    The profile is derived from the live rolling window rather than invented
    metadata: observed ports/processes/connections, alert counts and risk are
    all calculated from the same data exposed to the dashboard.
    """
    device = next((d for d in devices if d.get("ip") == ip), None)
    if device is None:
        return None

    related_connections = [
        c for c in connections
        if c.get("src_ip") == ip or c.get("dst_ip") == ip
    ]
    outbound = [c for c in related_connections if c.get("src_ip") == ip]
    inbound = [c for c in related_connections if c.get("dst_ip") == ip]

    observed_ports = sorted({
        c.get("dst_port") for c in outbound
        if isinstance(c.get("dst_port"), int)
    })
    processes = sorted({
        c.get("process_name") for c in outbound
        if c.get("process_name")
    })
    destinations = sorted({
        c.get("dst_ip") for c in outbound if c.get("dst_ip")
    })
    sources = sorted({
        c.get("src_ip") for c in inbound if c.get("src_ip")
    })

    related_alerts = [
        a for a in alerts
        if a.get("src_ip") == ip or a.get("dst_ip") == ip
    ]
    risk_levels = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 100}
    risk_score = max(
        [risk_levels.get(str(a.get("risk_level", "")).upper(), 0) for a in related_alerts]
        or [0]
    )

    related_policies = [
        p for p in policies
        if p.get("target", {}).get("src_ip") == ip
        or p.get("target", {}).get("dst_ip") == ip
    ]

    timestamps = [c.get("timestamp") for c in related_connections if c.get("timestamp")]
    timestamps.sort()

    return {
        "device_id": device.get("device_id"),
        "ip": ip,
        "mac": device.get("mac", "unknown"),
        "segment": device.get("segment"),
        "device_type": device.get("device_type"),
        "status": "ACTIVE" if related_connections else "OBSERVED",
        "is_local": ip == STATE.local_ip or ip == "127.0.0.1",
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "active_connections": len(related_connections),
        "outbound_connections": len(outbound),
        "inbound_connections": len(inbound),
        "unique_destinations": len(destinations),
        "unique_sources": len(sources),
        "observed_ports": observed_ports,
        "processes": processes,
        "alert_count": len(related_alerts),
        "highest_risk": max((str(a.get("risk_level", "")).upper() for a in related_alerts),
                            key=lambda x: risk_levels.get(x, 0), default="NONE"),
        "risk_score": risk_score,
        "policy_count": len(related_policies),
        "policy_statuses": sorted({str(p.get("status", "SUGGESTED")).upper() for p in related_policies}),
    }


@app.route("/api/devices/<path:ip>")
def get_device_profile(ip):
    devices, connections, alerts, policies, _ = _get_current_data()
    profile = _build_device_profile(ip, devices, connections, alerts, policies)
    if profile is None:
        return jsonify({"error": "Device not found in the current active device set"}), 404
    return jsonify(profile)


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


<<<<<<< HEAD
@app.route("/api/ai/analysis")
def get_ai_analysis():
    """Run real LLM analysis when OPENAI_API_KEY is configured; otherwise show a clearly labelled fallback."""
    try:
        devices, connections, alerts, policies, _ = _get_current_data()
        result = ai_security_analyst.generate_analysis(alerts, policies, devices, connections)
        result["mode"] = APP_MODE
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"AI analysis failed: {exc}"}), 500


@app.route("/api/summary")
def get_summary():
    from flask import request
    devices, connections, alerts, policies, notifications = _get_current_data()
    # The dashboard does not need thousands of repeated socket records to draw
    # the topology. Keep the API's total metric accurate while allowing the UI
    # to request a bounded connection sample for smooth live operation.
    limit = request.args.get("connection_limit", default=450, type=int)
    limit = max(50, min(limit, 1000))
    if len(connections) > limit:
        connections_for_ui = connections[:limit]
    else:
        connections_for_ui = connections
    return jsonify({
        "devices": devices,
        "connections": connections_for_ui,
=======
@app.route("/api/summary")
def get_summary():
    devices, connections, alerts, policies, notifications = _get_current_data()
    return jsonify({
        "devices": devices,
        "connections": connections,
>>>>>>> aedc1db9c0a785e87c7499f58808919e6eb2e90c
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
    print(f"    http://{args.host}:{args.port}/api/policy-decisions")
    print(f"    http://{args.host}:{args.port}/api/notifications")

    app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)
