"""
RISK ENGINE
============
Ye script network_snapshot.json padhta hai aur risky connections detect
karta hai — bina "label" dekhe, sirf pattern/rules se.

3 RULES abhi implement hain:
1. CROSS-SEGMENT ACCESS: Guest/IoT segment se Server segment tak direct
   connection — high risk (guest/IoT ko server se baat karne ki zaroorat
   nahi honi chahiye)
2. UNEXPECTED SERVICE ACCESS: Ek device jo apni "normal role" ke bahar
   ka port try kar raha hai (jaise printer SSH try kare)
3. FAN-OUT (LATERAL MOVEMENT PATTERN): Ek source device agar bahut saare
   ALAG destination devices se connect ho raha hai thodi der mein
"""

import json
from datetime import datetime
from collections import defaultdict

# ---- RISK RULES CONFIG ----

# Kaunse segments "low trust" hain (in se server tak jaana risky hai)
LOW_TRUST_SEGMENTS = {"guest", "iot"}
HIGH_VALUE_SEGMENTS = {"server"}

# Kis device-type ko kaunse ports use karna "normal" hai — agar isse
# bahar ka port try kare, to suspicious
EXPECTED_PORTS_BY_TYPE = {
    "printer": [9100, 80],
    "ip_camera": [554, 80],
    "laptop": [22, 445, 80, 443],
    "workstation": [3389, 80, 443],
    "database_server": [3306, 22],
    "finance_server": [443, 22],
    "file_server": [445, 22],
    "smartphone": [80, 443],
}

FAN_OUT_THRESHOLD = 6  # itne alag destinations = suspicious lateral movement
# NOTE: Ye threshold tumhare demo ke "num_normal" connections count ke hisaab se
# tune karna padega — jitni zyada normal traffic generate karoge, threshold utna
# zyada rakhna hoga taaki normal business-use false-positive na bane.


def load_snapshot(filepath="network_snapshot.json"):
    with open(filepath, "r") as f:
        return json.load(f)


def build_device_lookup(devices):
    """IP -> device info ka quick lookup table banata hai."""
    return {d["ip"]: d for d in devices}


def rule_cross_segment_access(connections, device_lookup):
    """
    RULE 1: Agar koi LOW_TRUST segment (guest/iot) ka device seedha
    HIGH_VALUE segment (server) se connect ho raha hai — flag karo.
    """
    alerts = []
    for conn in connections:
        src_seg = conn["src_segment"]
        dst_seg = conn["dst_segment"]

        if src_seg in LOW_TRUST_SEGMENTS and dst_seg in HIGH_VALUE_SEGMENTS:
            alerts.append({
                "timestamp": conn["timestamp"],
                "conn_id": conn["conn_id"],
                "risk_type": "CROSS_SEGMENT_ACCESS",
                "risk_level": "HIGH",
                "confidence_score": 0.9,
                "evidence": f"Device in '{src_seg}' segment ({conn['src_ip']}) directly "
                             f"contacted '{dst_seg}' segment device ({conn['dst_ip']}) "
                             f"on port {conn['dst_port']} — this segment should never "
                             f"reach production servers directly.",
                "src_ip": conn["src_ip"],
                "dst_ip": conn["dst_ip"],
            })
    return alerts


def rule_unexpected_service_access(connections, device_lookup):
    """
    RULE 2: Agar ek device (jaise printer) apne "normal" ports ke bahar
    ka port try kar raha hai kisi dusre device pe — flag karo.
    (Yahan hum SOURCE device ka type check karte hain — jaise ek printer
    ko kabhi bhi SSH client ki tarah kaam nahi karna chahiye)
    """
    alerts = []
    for conn in connections:
        src_device = device_lookup.get(conn["src_ip"])
        if not src_device:
            continue

        device_type = src_device["device_type"]
        expected_ports = EXPECTED_PORTS_BY_TYPE.get(device_type, [])
        actual_port = conn["dst_port"]

        # Agar ye device-type IoT/embedded hai aur woh admin-style port (22, 3389, 3306)
        # try kar raha hai jo uski "normal role" mein nahi aata — suspicious
        admin_ports = {22, 3389, 3306, 445}
        if device_type in ("printer", "ip_camera") and actual_port in admin_ports:
            alerts.append({
                "timestamp": conn["timestamp"],
                "conn_id": conn["conn_id"],
                "risk_type": "UNEXPECTED_SERVICE_ACCESS",
                "risk_level": "HIGH",
                "confidence_score": 0.85,
                "evidence": f"Device '{conn['src_ip']}' (type: {device_type}) attempted "
                             f"port {actual_port} on {conn['dst_ip']} — this is an "
                             f"administrative port that a {device_type} should never use. "
                             f"Possible sign of compromise/lateral movement.",
                "src_ip": conn["src_ip"],
                "dst_ip": conn["dst_ip"],
            })
    return alerts


def rule_fan_out_lateral_movement(connections):
    """
    RULE 3: Agar ek source IP bahut saare ALAG destination IPs se
    connect ho raha hai — ye lateral-movement/reconnaissance ka sign hai.
    """
    alerts = []
    src_to_destinations = defaultdict(set)
    src_last_conn = {}

    sorted_conns = sorted(connections, key=lambda c: c["timestamp"])

    for conn in sorted_conns:
        src = conn["src_ip"]
        src_to_destinations[src].add(conn["dst_ip"])
        src_last_conn[src] = conn

    for src, destinations in src_to_destinations.items():
        if len(destinations) >= FAN_OUT_THRESHOLD:
            conn = src_last_conn[src]
            alerts.append({
                "timestamp": conn["timestamp"],
                "conn_id": conn["conn_id"],
                "risk_type": "FAN_OUT_LATERAL_MOVEMENT",
                "risk_level": "MEDIUM",
                "confidence_score": 0.7,
                "evidence": f"Source {src} connected to {len(destinations)} distinct "
                             f"destination devices — unusually broad access pattern, "
                             f"possible reconnaissance or lateral movement.",
                "src_ip": src,
                "dst_ip": None,
            })
    return alerts


def run_risk_engine(snapshot):
    devices = snapshot["devices"]
    connections = snapshot["connections"]
    device_lookup = build_device_lookup(devices)

    all_alerts = []
    all_alerts.extend(rule_cross_segment_access(connections, device_lookup))
    all_alerts.extend(rule_unexpected_service_access(connections, device_lookup))
    all_alerts.extend(rule_fan_out_lateral_movement(connections))

    return all_alerts


if __name__ == "__main__":
    print("[*] Loading network snapshot...")
    snapshot = load_snapshot()
    print(f"[*] Loaded {len(snapshot['devices'])} devices, {len(snapshot['connections'])} connections")

    print("[*] Running risk engine (3 rules)...\n")
    alerts = run_risk_engine(snapshot)

    if alerts:
        print(f"[!] {len(alerts)} RISK ALERT(S) DETECTED:\n")
        for a in alerts:
            print(json.dumps(a, indent=2))
            print()
    else:
        print("[✓] No risky connections detected.")

    with open("risk_alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[✓] Alerts saved to 'risk_alerts.json'")
