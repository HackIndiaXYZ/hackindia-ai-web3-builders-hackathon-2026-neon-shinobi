"""
LIVE CAPTURE MODE
===================
Ye script tumhare APNE laptop ki REAL, ACTIVE network connections capture
karta hai (psutil se) — network_simulator.py ki jagah, taaki risk_engine.py,
policy_generator.py, aur dashboard BINA KISI CHANGE ke real data pe chal sakein.

Kaise kaam karta hai:
1. Tumhara laptop ka local IP nikalta hai
2. Har `--interval` second baad, saari active TCP connections snapshot leta hai
3. Har connection ko wahi schema mein likhta hai jo network_simulator.py
   deta hai (devices + connections) — isliye downstream sab kuch same rehta hai
4. `--duration` second tak chalta hai, phir network_snapshot.json save karta hai

IMPORTANT: Real laptop pe "guest/employee/server" jaisi segments naturally
nahi hoti (ek hi device hai) — isliye CROSS_SEGMENT_ACCESS rule yahan
zyada fire nahi hogi. Ye normal hai. PORT_SCANNING aur FAN_OUT rules
yahan sabse relevant hain — ye genuinely kaam karengi real data pe.

Usage:
    python3 live_capture.py --duration 30 --interval 0.5
"""

import psutil
import socket
import json
import os
import time
import argparse
import ipaddress
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Ye connection-states psutil mein include karni hain — sirf ESTABLISHED
# nahi, kyunki port-scan attempts aksar SYN_SENT/TIME_WAIT jaisi transient
# states mein hi dikhti hain (poori tarah connect nahi hoti)
RELEVANT_STATUSES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "TIME_WAIT", "CLOSE_WAIT"}


def get_local_ip():
    """Laptop ka apna real IP address nikalta hai (outbound-route trick se)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # koi data nahi bhejta, sirf route check karta hai
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def classify(ip, local_ip):
    """
    Real IP ko segment + device-type mein classify karta hai.
    Ye heuristic hai (real network mein exact device-type pata nahi hota).
    """
    if ip == local_ip or ip == "127.0.0.1":
        return "employee", "laptop"  # ye tumhara apna laptop hai
    try:
        if ipaddress.ip_address(ip).is_private:
            return "local_network", "lan_device"  # tumhare ghar/office ke network ka koi device
    except ValueError:
        pass
    return "internet", "external_host"  # public internet ka koi endpoint


def capture_snapshot(local_ip, seen_devices, connections, conn_counter):
    """Ek snapshot leta hai abhi ke saare active connections ka."""
    now = datetime.now()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        print("[!] Permission denied — Windows pe Command Prompt ko 'Run as Administrator' se")
        print("    kholo taaki saari connections dikh sakein (kuch OS security-restriction hai).")
        return 0

    count = 0
    for c in conns:
        if c.status not in RELEVANT_STATUSES:
            continue
        if not c.laddr or not c.raddr:
            continue  # sirf established/connecting sockets chahiye, listening nahi

        src_ip = c.laddr.ip
        dst_ip = c.raddr.ip
        dst_port = c.raddr.port

        for ip in (src_ip, dst_ip):
            if ip not in seen_devices:
                segment, device_type = classify(ip, local_ip)
                seen_devices[ip] = {
                    "device_id": f"D{len(seen_devices)+1:03d}",
                    "ip": ip,
                    "mac": "unknown",  # real MAC nikalna extra permissions maangta hai, skip kiya
                    "segment": segment,
                    "device_type": device_type,
                    "open_ports": [],
                    "services": [],
                }

        conn_counter[0] += 1
        connections.append({
            "conn_id": f"C{conn_counter[0]:04d}",
            "src_ip": src_ip,
            "src_segment": seen_devices[src_ip]["segment"],
            "dst_ip": dst_ip,
            "dst_segment": seen_devices[dst_ip]["segment"],
            "dst_port": dst_port,
            "timestamp": now.isoformat(),
            "label": "live_capture",  # real data, koi ground-truth label nahi
        })
        count += 1
    return count


def run(duration_seconds, interval_seconds):
    local_ip = get_local_ip()
    print(f"[*] Ye laptop ka local IP: {local_ip}")
    print(f"[*] LIVE CAPTURE shuru — {duration_seconds}s tak, har {interval_seconds}s mein snapshot")
    print(f"[*] Is dauraan tum doosre terminal mein 'port_scan_simulator.py' chala sakte ho")
    print(f"    taaki live attack simulate ho aur real-time mein pakda jaaye.\n")

    seen_devices = {}
    connections = []
    conn_counter = [0]

    t_end = time.time() + duration_seconds
    tick = 0
    while time.time() < t_end:
        n = capture_snapshot(local_ip, seen_devices, connections, conn_counter)
        tick += 1
        print(f"  [{tick}] {n} active connection(s) captured so far... "
              f"(total so far: {len(connections)}, devices: {len(seen_devices)})")
        time.sleep(interval_seconds)

    snapshot = {
        "devices": list(seen_devices.values()),
        "connections": connections,
        "generated_at": datetime.now().isoformat(),
        "mode": "LIVE_CAPTURE",  # dashboard/agent isko dikha sakta hai "REAL DATA" badge ke roop mein
    }

    out_path = os.path.join(OUTPUT_DIR, "network_snapshot.json")
    with open(out_path, "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"\n[\u2713] Captured {len(seen_devices)} REAL devices, {len(connections)} REAL connections")
    print(f"[\u2713] Saved to '{out_path}'")
    print(f"[\u2713] Ab isi REAL data pe chalao: risk_engine.py -> policy_generator.py -> alert_agent.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live network capture (real data mode)")
    parser.add_argument("--duration", type=int, default=25, help="Kitne second capture karna hai")
    parser.add_argument("--interval", type=float, default=0.5, help="Har kitne second baad snapshot")
    args = parser.parse_args()
    run(args.duration, args.interval)
