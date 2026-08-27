"""
NETWORK TOPOLOGY SIMULATOR
============================
Ye script ek fake company/home network ka "snapshot" generate karta hai —
bilkul jaisa `nmap` scan real network mein deta.

Ye 2 cheezein banata hai:
1. DEVICES — network mein kaun-kaun se devices hain (IP, MAC, open ports, device-type)
2. CONNECTIONS — kaun kis se baat kar raha hai (jaise psutil live traffic dikhata)

Ismein hum jaan-boojh kar kuch RISKY connections bhi daalenge (jaise "guest"
device ka "database server" se direct connect hona) — taaki risk-engine
ko test kar sakein.
"""

import random
import json
import os
from datetime import datetime, timedelta

# ---- OUTPUT PATH SETUP ----
# Ye script "Scan input" folder mein rehta hai, aur output "output/" folder
# mein jaana chahiye (jo sibling folder hai). Isse chahe tum kahin se bhi
# command chalao, file hamesha sahi jagah (zerotrust_project/output/) jaayegi.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ---- NETWORK SEGMENTS (jaise real company mein hote hain) ----
SEGMENTS = {
    "guest": "192.168.10",       # guest WiFi — kam trusted
    "employee": "192.168.20",    # employee laptops — normal trust
    "server": "192.168.30",      # servers (database, finance) — high value target
    "iot": "192.168.40",         # IoT devices (printers, cameras) — often vulnerable
}


def random_mac():
    """Fake MAC address banata hai."""
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def generate_devices():
    """
    Har segment mein kuch devices banata hai, unke open ports aur
    device-type ke saath — bilkul jaisa nmap -sV scan dikhata.
    """
    devices = []
    device_id = 1

    device_templates = {
        "guest": [
            {"type": "laptop", "ports": [], "services": []},
            {"type": "smartphone", "ports": [], "services": []},
        ],
        "employee": [
            {"type": "laptop", "ports": [22, 445], "services": ["ssh", "smb"]},
            {"type": "laptop", "ports": [445], "services": ["smb"]},
            {"type": "workstation", "ports": [3389], "services": ["rdp"]},
        ],
        "server": [
            {"type": "database_server", "ports": [3306, 22], "services": ["mysql", "ssh"]},
            {"type": "finance_server", "ports": [443, 22], "services": ["https", "ssh"]},
            {"type": "file_server", "ports": [445, 22], "services": ["smb", "ssh"]},
        ],
        "iot": [
            {"type": "printer", "ports": [9100, 80], "services": ["jetdirect", "http"]},
            {"type": "ip_camera", "ports": [554, 80], "services": ["rtsp", "http"]},
        ],
    }

    for segment_name, subnet_prefix in SEGMENTS.items():
        templates = device_templates[segment_name]
        num_devices = random.randint(2, 3)

        for i in range(num_devices):
            template = random.choice(templates)
            device = {
                "device_id": f"D{device_id:03d}",
                "ip": f"{subnet_prefix}.{random.randint(10, 250)}",
                "mac": random_mac(),
                "segment": segment_name,
                "device_type": template["type"],
                "open_ports": template["ports"],
                "services": template["services"],
            }
            devices.append(device)
            device_id += 1

    return devices


def generate_connections(devices, num_normal=30):
    """
    Devices ke beech connections generate karta hai — zyaadatar NORMAL
    (jaise employee apne segment ke andar hi rehte hain), aur kuch
    jaan-boojh kar RISKY (cross-segment access) taaki risk-engine test ho.
    """
    connections = []
    conn_id = 1
    current_time = datetime.now()

    by_segment = {}
    for d in devices:
        by_segment.setdefault(d["segment"], []).append(d)

    # ---- NORMAL CONNECTIONS: usually same-segment ya employee->server (legit) ----
    for _ in range(num_normal):
        src = random.choice(by_segment["employee"])
        # employees legitimately server se baat karte hain (normal business use)
        dst = random.choice(by_segment["server"] + by_segment["employee"])
        if dst["open_ports"]:
            port = random.choice(dst["open_ports"])
        else:
            port = random.choice([80, 443])

        connections.append({
            "conn_id": f"C{conn_id:04d}",
            "src_ip": src["ip"],
            "src_segment": src["segment"],
            "dst_ip": dst["ip"],
            "dst_segment": dst["segment"],
            "dst_port": port,
            "timestamp": current_time.isoformat(),
            "label": "normal"
        })
        conn_id += 1
        current_time += timedelta(seconds=random.uniform(1, 10))

    # ---- RISKY CONNECTION #1: Guest device directly hitting a Server (cross-segment) ----
    guest_device = random.choice(by_segment["guest"])
    server_device = random.choice(by_segment["server"])
    risky_port = server_device["open_ports"][0] if server_device["open_ports"] else 3306
    connections.append({
        "conn_id": f"C{conn_id:04d}",
        "src_ip": guest_device["ip"],
        "src_segment": guest_device["segment"],
        "dst_ip": server_device["ip"],
        "dst_segment": server_device["segment"],
        "dst_port": risky_port,
        "timestamp": current_time.isoformat(),
        "label": "risky_cross_segment"   # ground-truth, sirf validation ke liye
    })
    conn_id += 1
    current_time += timedelta(seconds=2)

    # ---- RISKY CONNECTION #2: IoT device (e.g. printer) doing lateral movement to Server ----
    iot_device = random.choice(by_segment["iot"])
    server_device2 = random.choice(by_segment["server"])
    connections.append({
        "conn_id": f"C{conn_id:04d}",
        "src_ip": iot_device["ip"],
        "src_segment": iot_device["segment"],
        "dst_ip": server_device2["ip"],
        "dst_segment": server_device2["segment"],
        "dst_port": 22,   # IoT device SSH try kar raha hai server pe — bahut suspicious
        "timestamp": current_time.isoformat(),
        "label": "risky_lateral_movement"
    })
    conn_id += 1

    return connections


def generate_topology_snapshot():
    """Poora ek network-snapshot banata hai — devices + connections."""
    print("[*] Generating network devices across segments (guest, employee, server, iot)...")
    devices = generate_devices()
    print(f"    -> {len(devices)} devices created")

    print("[*] Generating connections (normal + risky)...")
    connections = generate_connections(devices)
    print(f"    -> {len(connections)} connections created")

    snapshot = {
        "devices": devices,
        "connections": connections,
        "generated_at": datetime.now().isoformat()
    }
    return snapshot


if __name__ == "__main__":
    snapshot = generate_topology_snapshot()

    output_file = os.path.join(OUTPUT_DIR, "network_snapshot.json")
    with open(output_file, "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"\n[✓] Saved network snapshot to '{output_file}'")
    print(f"[✓] Devices: {len(snapshot['devices'])}, Connections: {len(snapshot['connections'])}")
    print("[✓] Ab 'risk_engine.py' isko padh kar risky connections detect karega")
