"""
PORT SCAN SIMULATOR (Live Demo Attack)
=========================================
Ye script SAFE hai — sirf tumhare APNE laptop (127.0.0.1) pe hi kaam karta
hai, kisi doosre device/network ko touch nahi karta.

Kya karta hai:
1. Pehle 15 chhote "listener" ports khud kholta hai (background mein)
   taaki connect karne ke liye kuch real ho
2. Fir bahut jaldi-jaldi un sab ports se connect karta hai — bilkul
   jaisa ek port-scanner (Nmap) karta hai

Isse `live_capture.py` (agar wo dusre terminal mein chal raha ho) ye
"scan" pattern REAL data ke roop mein capture kar lega, aur risk_engine.py
ka naya PORT_SCANNING rule ise turant pakad lega.

DEMO KE LIYE:
1. Terminal 1: python3 live_capture.py --duration 30
2. Terminal 2 (turant, 5 second ke andar): python3 port_scan_simulator.py
3. Terminal 1 khatam hone do, phir risk_engine.py chalao — PORT_SCANNING
   alert dikhna chahiye, REAL captured data se!
"""

import socket
import threading
import time
import random

TARGET_IP = "127.0.0.1"   # sirf apna hi laptop — safe
NUM_PORTS = 15
BASE_PORT = 51000


def start_listener(port):
    """Ek chhota server jo sirf connections accept karta hai, kuch nahi karta."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((TARGET_IP, port))
        s.listen(5)
        while True:
            try:
                conn, _ = s.accept()
                conn.close()
            except OSError:
                break
    except OSError:
        pass  # port already in use ho sakta hai, skip


def run_scan():
    ports = list(range(BASE_PORT, BASE_PORT + NUM_PORTS))

    print(f"[*] Starting {NUM_PORTS} listener ports on {TARGET_IP}...")
    threads = []
    for p in ports:
        t = threading.Thread(target=start_listener, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    time.sleep(1)  # listeners ko ready hone do

    print(f"[*] Ab '{TARGET_IP}' pe {NUM_PORTS} ports ko jaldi-jaldi scan kar rahe hain "
          f"(port-scan simulate)...")
    random.shuffle(ports)
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((TARGET_IP, port))
            s.close()
            print(f"    -> connected to port {port}")
        except Exception as e:
            print(f"    -> port {port} failed ({e})")
        time.sleep(0.15)  # thoda fast, lekin capture ke liye enough gap

    print(f"\n[\u2713] Scan simulation complete — {NUM_PORTS} ports touched on {TARGET_IP}")
    print(f"[\u2713] Agar 'live_capture.py' chal raha tha, isko capture kar liya hoga")
    print(f"[\u2713] Ab risk_engine.py chalao — PORT_SCANNING alert dikhna chahiye")


if __name__ == "__main__":
    run_scan()
