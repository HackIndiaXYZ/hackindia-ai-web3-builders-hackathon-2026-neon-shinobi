"""
RISK ENGINE
============
Ye script network_snapshot.json padhta hai aur risky connections detect
karta hai — bina "label" dekhe, sirf pattern/rules se.

4 RULES abhi implement hain:
1. CROSS-SEGMENT ACCESS: Guest/IoT segment se Server segment tak direct
   connection — high risk (guest/IoT ko server se baat karne ki zaroorat
   nahi honi chahiye)
2. UNEXPECTED SERVICE ACCESS: Ek device jo apni "normal role" ke bahar
   ka port try kar raha hai (jaise printer SSH try kare)
3. FAN-OUT (LATERAL MOVEMENT PATTERN): Ek source device agar bahut saare
   ALAG destination devices se connect ho raha hai thodi der mein
4. PORT SCANNING: Ek source, ek hi destination ke bahut saare ALAG ports
   thodi der mein try kar raha hai — classic reconnaissance pattern.
   (Ye rule especially LIVE-CAPTURE data ke liye zaroori hai, jahan
   "segments" nahi hote lekin real port-scanning attack detect karni hai.)
"""

import json
import os
import ipaddress

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
ALLOWLIST_PATH = os.path.join(SCRIPT_DIR, "allowlist.json")
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

FAN_OUT_THRESHOLD = 20  # require a broader burst before flagging normal app traffic
# NOTE: Ye threshold tumhare demo ke "num_normal" connections count ke hisaab se
# tune karna padega — jitni zyada normal traffic generate karoge, threshold utna
# zyada rakhna hoga taaki normal business-use false-positive na bane.

PORT_SCAN_THRESHOLD = 5   # itne alag ports ek hi destination pe = port scan
PORT_SCAN_WINDOW_SECONDS = 30  # itni der ke andar


def load_allowlist(path=None):
    """Reads allowlist.json — destinations here are excluded from every
    rule below. Missing/invalid file just means an empty allowlist
    (nothing is silently over-permissive by default)."""
    path = path or ALLOWLIST_PATH
    empty = {"ips": set(), "cidrs": [], "ports": set()}
    if not os.path.exists(path):
        return empty
    try:
        with open(path, "r") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError):
        return empty

    cidrs = []
    for c in raw.get("cidrs", []):
        try:
            cidrs.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue  # skip malformed entries rather than crash the whole engine

    return {
        "ips": set(raw.get("ips", [])),
        "cidrs": cidrs,
        "ports": set(raw.get("ports", [])),
    }


def is_allowlisted(dst_ip, dst_port, allowlist):
    if dst_ip in allowlist["ips"]:
        return True
    if dst_port in allowlist["ports"]:
        return True
    if allowlist["cidrs"]:
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            for net in allowlist["cidrs"]:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
    return False


def load_snapshot(filepath=None):
    if filepath is None:
        filepath = os.path.join(OUTPUT_DIR, "network_snapshot.json")
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
                "src_process": conn.get("process_name"),
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
                "src_process": conn.get("process_name"),
            })
    return alerts


def rule_fan_out_lateral_movement(connections, baseline_destinations=None, learning_mode=False):
    """
    RULE 3: Agar ek source IP bahut saare ALAG destination IPs se
    connect ho raha hai — ye lateral-movement/reconnaissance ka sign hai.

    False-positive reduction: real traffic (browser, background apps)
    normally fans out to many IPs — that alone isn't suspicious. So:
      - during `learning_mode` (backend's baseline window), this rule is
        fully suppressed — no alerts, only the caller is meant to be
        building up `baseline_destinations` during this time.
      - afterwards, only destinations NOT already in the source's
        baseline count towards the threshold. Revisiting known-normal
        destinations doesn't trip this; a sudden burst of brand-new
        destinations still does.
    """
    alerts = []
    if learning_mode:
        return alerts

    baseline_destinations = baseline_destinations or {}
    src_to_destinations = defaultdict(set)
    src_last_conn = {}

    sorted_conns = sorted(connections, key=lambda c: c["timestamp"])

    for conn in sorted_conns:
        src = conn["src_ip"]
        dst = conn["dst_ip"]
        known = baseline_destinations.get(src, set())
        if dst in known:
            continue  # already-established-as-normal destination, doesn't count
        src_to_destinations[src].add(dst)
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
                             f"destinations it hadn't contacted before this session's "
                             f"baseline — unusually broad access pattern, possible "
                             f"reconnaissance or lateral movement.",
                "src_ip": src,
                "dst_ip": None,
                "src_process": conn.get("process_name"),
            })
    return alerts


def rule_port_scanning(connections):
    """
    RULE 4: PORT SCANNING
    Agar ek source, ek hi destination ke bahut saare ALAG ports thodi
    der (PORT_SCAN_WINDOW_SECONDS) ke andar try kar raha hai — classic
    reconnaissance/port-scan pattern (bilkul jaisa Nmap karta hai).

    Ye rule especially important hai LIVE-CAPTURE data ke liye — jahan
    "network segments" nahi hote (ek hi laptop hai), lekin agar koi
    us laptop ke ports scan kare, tab bhi ye pakda jaana chahiye.
    """
    alerts = []
    # key = (src_ip, dst_ip) -> list of (timestamp, port)
    pair_activity = defaultdict(list)
    already_alerted = set()

    sorted_conns = sorted(connections, key=lambda c: c["timestamp"])

    for conn in sorted_conns:
        key = (conn["src_ip"], conn["dst_ip"])
        # Loopback traffic is intentionally included. The safe port-scan simulator
        # targets 127.0.0.1, and the same port-scan heuristic (5+ unique ports
        # within 30 seconds) is specific enough to avoid treating ordinary
        # single-port localhost application traffic as reconnaissance.
        ts = datetime.fromisoformat(conn["timestamp"])
        pair_activity[key].append((ts, conn["dst_port"]))

        # window ke bahar ki purani entries hata do
        cutoff = ts.timestamp() - PORT_SCAN_WINDOW_SECONDS
        pair_activity[key] = [(t, p) for (t, p) in pair_activity[key] if t.timestamp() >= cutoff]

        unique_ports = set(p for (t, p) in pair_activity[key])

        if len(unique_ports) >= PORT_SCAN_THRESHOLD and key not in already_alerted:
            confidence = min(0.5 + (len(unique_ports) - PORT_SCAN_THRESHOLD) * 0.05, 0.97)
            alerts.append({
                "timestamp": conn["timestamp"],
                "conn_id": conn["conn_id"],
                "risk_type": "PORT_SCANNING",
                "risk_level": "HIGH",
                "confidence_score": round(confidence, 2),
                "evidence": f"Source {key[0]} contacted {len(unique_ports)} unique ports on "
                             f"{key[1]} within {PORT_SCAN_WINDOW_SECONDS} seconds — classic "
                             f"reconnaissance/port-scan pattern.",
                "src_ip": key[0],
                "dst_ip": key[1],
                "src_process": conn.get("process_name"),
            })
            already_alerted.add(key)

    return alerts


def run_risk_engine(snapshot, baseline_destinations=None, learning_mode=False, allowlist=None):
    devices = snapshot["devices"]
    device_lookup = build_device_lookup(devices)

    if allowlist is None:
        allowlist = load_allowlist()

    # Allowlisted destinations (e.g. your own DNS server, known update
    # servers) are excluded from every rule below, not just one — if
    # you've decided a destination is fine, it should stay quiet everywhere.
    connections = [
        c for c in snapshot["connections"]
        if not is_allowlisted(c["dst_ip"], c.get("dst_port"), allowlist)
    ]

    all_alerts = []
    all_alerts.extend(rule_cross_segment_access(connections, device_lookup))
    all_alerts.extend(rule_unexpected_service_access(connections, device_lookup))
    all_alerts.extend(rule_fan_out_lateral_movement(
        connections, baseline_destinations=baseline_destinations, learning_mode=learning_mode
    ))
    all_alerts.extend(rule_port_scanning(connections))

    return all_alerts


if __name__ == "__main__":
    print("[*] Loading network snapshot...")
    snapshot = load_snapshot()
    print(f"[*] Loaded {len(snapshot['devices'])} devices, {len(snapshot['connections'])} connections")

    print("[*] Running risk engine (4 rules)...\n")
    alerts = run_risk_engine(snapshot)

    if alerts:
        print(f"[!] {len(alerts)} RISK ALERT(S) DETECTED:\n")
        for a in alerts:
            print(json.dumps(a, indent=2))
            print()
    else:
        print("[✓] No risky connections detected.")

    with open(os.path.join(OUTPUT_DIR, "risk_alerts.json"), "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"[✓] Alerts saved to 'risk_alerts.json'")
