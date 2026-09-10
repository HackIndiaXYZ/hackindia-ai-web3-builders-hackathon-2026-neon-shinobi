"""
POLICY GENERATOR
==================
Ye script 'risk_alerts.json' padhta hai aur har HIGH/MEDIUM risk alert
ke liye ek DEPLOYABLE firewall rule generate karta hai (iptables format).

Idea simple hai: risk-engine ne bataya "ye connection risky hai",
ab hum bolte hain "toh ise BLOCK karne ke liye ye exact command chalao."

Ye poora process READ-ONLY hai is script mein — hum khud koi rule
APPLY nahi kar rahe (jaan-boojh kar), sirf SUGGEST kar rahe hain.
Real deployment ke liye ek human admin ko review karke apply karna chahiye
— ye responsible security-tooling design hai.
"""

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
from datetime import datetime


def load_alerts(filepath=None):
    if filepath is None:
        filepath = os.path.join(OUTPUT_DIR, "risk_alerts.json")
    with open(filepath, "r") as f:
        return json.load(f)


def generate_iptables_rule(alert):
    """
    Ek alert ke liye iptables DROP rule banata hai.
    Agar dst_ip nahi hai (jaise fan-out alerts mein), toh source-based
    rate-limiting rule suggest karta hai instead of a hard block.
    """
    src_ip = alert["src_ip"]
    dst_ip = alert.get("dst_ip")

    if dst_ip:
        # Specific source -> destination block
        rule = f"iptables -A FORWARD -s {src_ip} -d {dst_ip} -j DROP"
        explanation = f"Blocks all traffic from {src_ip} to {dst_ip} specifically."
    else:
        # Fan-out jaise cases mein specific destination nahi hai —
        # is source ko rate-limit karna zyada practical hai poora block karne se
        rule = f"iptables -A FORWARD -s {src_ip} -m limit --limit 5/min -j ACCEPT\n" \
               f"iptables -A FORWARD -s {src_ip} -j DROP"
        explanation = f"Rate-limits {src_ip} to 5 connections/min (blocks excessive fan-out), " \
                       f"since no single destination was implicated."

    return rule, explanation


def generate_nftables_rule(alert):
    """Same logic, lekin newer 'nftables' syntax mein (modern Linux systems)."""
    src_ip = alert["src_ip"]
    dst_ip = alert.get("dst_ip")

    if dst_ip:
        rule = f"nft add rule inet filter forward ip saddr {src_ip} ip daddr {dst_ip} drop"
    else:
        rule = f"nft add rule inet filter forward ip saddr {src_ip} limit rate 5/minute accept"

    return rule


def generate_policies(alerts):
    """Har alert ke liye ek policy-object banata hai (rules + metadata)."""
    policies = []

    for alert in alerts:
        iptables_rule, explanation = generate_iptables_rule(alert)
        nftables_rule = generate_nftables_rule(alert)

        policy = {
            "policy_id": f"POL-{alert['conn_id']}",
            "generated_at": datetime.now().isoformat(),
            "based_on_alert": alert["risk_type"],
            "risk_level": alert["risk_level"],
            "target": {
                "src_ip": alert["src_ip"],
                "dst_ip": alert.get("dst_ip"),
            },
            "action": "BLOCK" if alert.get("dst_ip") else "RATE_LIMIT",
            "iptables_rule": iptables_rule,
            "nftables_rule": nftables_rule,
            "explanation": explanation if alert.get("dst_ip") else
                           f"Rate-limits source due to {alert['risk_type']} pattern (no single destination).",
            "evidence": alert["evidence"],
            "status": "SUGGESTED — requires human review before deployment"
        }
        policies.append(policy)

    return policies


if __name__ == "__main__":
    print("[*] Loading risk alerts...")
    alerts = load_alerts()
    print(f"[*] Loaded {len(alerts)} alerts")

    print("[*] Generating deployable policies...\n")
    policies = generate_policies(alerts)

    for p in policies:
        print(f"--- {p['policy_id']} ({p['risk_level']}) ---")
        print(f"Based on: {p['based_on_alert']}")
        print(f"Action: {p['action']}")
        print(f"iptables command:\n  {p['iptables_rule']}")
        print(f"Explanation: {p['explanation']}")
        print(f"Status: {p['status']}")
        print()

    with open(os.path.join(OUTPUT_DIR, "generated_policies.json"), "w") as f:
        json.dump(policies, f, indent=2)

    print(f"[✓] {len(policies)} policies saved to 'generated_policies.json'")
    print("[✓] IMPORTANT: These are SUGGESTIONS only — a human admin should")
    print("    review and manually apply these before real deployment.")
