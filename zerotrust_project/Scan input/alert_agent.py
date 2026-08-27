"""
ALERT TRIAGE & NOTIFICATION AGENT
====================================
Ye "agent" raw risk-alerts ko padhta hai aur khud se decide karta hai:
1. CORRELATE  -- kaunse alerts ek hi "incident" ka hissa hain (same source,
                 thodi der ke andar)
2. PRIORITIZE -- kaunsa incident sabse pehle analyst ko dikhna chahiye
3. EXPLAIN    -- har incident ke liye ek human-readable summary + reasoning
                 trace banata hai (isliye explainable hai, black-box nahi)
4. NOTIFY     -- final output ek 'notification' list hai jo dashboard ke
                 notification-bell mein seedha feed hoti hai

Design choice: Ye agent RULE-BASED hai, cloud LLM pe depend nahi karta --
isliye poora system "fully offline, no cloud dependency" wala claim
intact rehta hai. Agent apna reasoning explicitly explain karta hai,
isliye analyst trust kar sakta hai ki decision kaise bana.
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---- CONFIG ----
CORRELATION_WINDOW_SECONDS = 300  # 5 minute — isi window ke andar wale
                                    # alerts ek hi source se aayen to
                                    # ek incident maana jaayega

RISK_LEVEL_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def load_json(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def correlate_alerts(alerts):
    """
    STEP 1: CORRELATION
    Same src_ip se aaye alerts, agar CORRELATION_WINDOW ke andar hain,
    to unko ek 'incident group' mein daal do -- alag-alag mat dikhao.
    """
    sorted_alerts = sorted(alerts, key=lambda a: a["timestamp"])
    incidents = []
    # har src_ip ke liye: last incident jisme naya alert fit ho sakta hai
    open_incidents = {}

    for alert in sorted_alerts:
        src = alert.get("src_ip")
        if not src:
            # kuch alerts (jaise fan-out) mein dst_ip nahi hota, src hi
            # primary identifier hai; agar wo bhi nahi hai to standalone
            src = f"unknown-{alert.get('conn_id', 'x')}"

        ts = datetime.fromisoformat(alert["timestamp"])

        if src in open_incidents:
            last_ts = open_incidents[src]["last_ts"]
            if (ts - last_ts).total_seconds() <= CORRELATION_WINDOW_SECONDS:
                # existing incident mein add karo
                open_incidents[src]["alerts"].append(alert)
                open_incidents[src]["last_ts"] = ts
                continue

        # naya incident shuru karo
        new_incident = {"src_ip": src, "alerts": [alert], "last_ts": ts}
        open_incidents[src] = new_incident
        incidents.append(new_incident)

    return incidents


def prioritize(incident):
    """
    STEP 2: PRIORITIZATION
    Score = highest risk-level involved + bonus for multiple alerts
    (escalating pattern) + average confidence.
    """
    alerts = incident["alerts"]
    max_risk = max(RISK_LEVEL_SCORE.get(a["risk_type_level"], 1) for a in alerts) \
        if "risk_type_level" in alerts[0] else \
        max(RISK_LEVEL_SCORE.get(a.get("risk_level", "LOW"), 1) for a in alerts)
    avg_confidence = sum(a.get("confidence_score", 0) for a in alerts) / len(alerts)
    escalation_bonus = min(len(alerts) - 1, 3) * 0.5  # multiple alerts = more urgent

    score = max_risk + avg_confidence + escalation_bonus
    return round(score, 2)


def explain(incident):
    """
    STEP 3: EXPLANATION
    Har incident ke liye ek reasoning-trace aur human-readable summary
    banata hai -- taaki analyst turant samajh sake AGENT NE YE DECISION
    KAISE LIYA (explainability).
    """
    alerts = incident["alerts"]
    src = incident["src_ip"]
    risk_types = list(dict.fromkeys(a["risk_type"] for a in alerts))  # unique, ordered
    max_level = max(alerts, key=lambda a: RISK_LEVEL_SCORE.get(a.get("risk_level", "LOW"), 1))["risk_level"]

    reasoning_steps = []
    reasoning_steps.append(
        f"Detected {len(alerts)} alert(s) from source {src} within a "
        f"{CORRELATION_WINDOW_SECONDS//60}-minute window \u2192 correlated into one incident."
    )
    if len(alerts) > 1:
        reasoning_steps.append(
            f"Multiple alerts from the same source \u2192 treated as an escalating "
            f"pattern, not isolated noise \u2192 priority increased."
        )
    reasoning_steps.append(
        f"Highest severity among grouped alerts: {max_level} \u2192 base priority set accordingly."
    )
    reasoning_steps.append(
        f"Threat types involved: {', '.join(risk_types)}."
    )

    if len(risk_types) == 1:
        summary = f"{risk_types[0].replace('_', ' ').title()} detected from {src} ({len(alerts)} event(s))."
    else:
        summary = f"Multiple threat types ({', '.join(t.replace('_',' ').title() for t in risk_types)}) from {src} \u2014 possible coordinated activity."

    return summary, reasoning_steps, max_level, risk_types


def attach_policy(incident, policies_by_conn_id):
    """Agar is incident ke kisi alert ka ready-made policy hai, use link karo."""
    for alert in incident["alerts"]:
        conn_id = alert.get("conn_id") or alert.get("flow_id")
        if conn_id in policies_by_conn_id:
            return policies_by_conn_id[conn_id]
    return None


def build_notifications(alerts_file=None, policies_file=None):
    if alerts_file is None:
        alerts_file = os.path.join(OUTPUT_DIR, "risk_alerts.json")
    if policies_file is None:
        policies_file = os.path.join(OUTPUT_DIR, "generated_policies.json")
    alerts = load_json(alerts_file)
    policies = load_json(policies_file)

    # policies ko conn_id ke through lookup karne layak banao
    policies_by_conn_id = {}
    for p in policies:
        cid = p.get("policy_id", "").replace("POL-", "")
        policies_by_conn_id[cid] = p

    incidents = correlate_alerts(alerts)

    notifications = []
    for i, incident in enumerate(incidents, 1):
        summary, reasoning, max_level, risk_types = explain(incident)
        priority_score = prioritize(incident)
        policy = attach_policy(incident, policies_by_conn_id)

        notification = {
            "notification_id": f"N{i:03d}",
            "timestamp": incident["last_ts"].isoformat(),
            "src_ip": incident["src_ip"],
            "alert_count": len(incident["alerts"]),
            "risk_types": risk_types,
            "severity": max_level,
            "priority_score": priority_score,
            "summary": summary,
            "agent_reasoning": reasoning,
            "recommended_policy": policy["iptables_rule"] if policy else None,
            "status": "AWAITING_ANALYST_REVIEW",
        }
        notifications.append(notification)

    # sabse urgent sabse upar
    notifications.sort(key=lambda n: n["priority_score"], reverse=True)
    return notifications


if __name__ == "__main__":
    print("[*] Agent starting: reading alerts + policies...")
    notifications = build_notifications()

    print(f"[*] Correlated into {len(notifications)} incident(s)\n")
    for n in notifications:
        print(f"--- {n['notification_id']} | Priority Score: {n['priority_score']} | {n['severity']} ---")
        print(f"Summary: {n['summary']}")
        print("Agent reasoning:")
        for step in n["agent_reasoning"]:
            print(f"   \u2192 {step}")
        if n["recommended_policy"]:
            print(f"Recommended policy: {n['recommended_policy']}")
        print(f"Status: {n['status']}\n")

    with open(os.path.join(OUTPUT_DIR, "agent_notifications.json"), "w") as f:
        json.dump(notifications, f, indent=2)
    print(f"[\u2713] Saved to 'agent_notifications.json' \u2014 dashboard notification-bell ab isko consume karega")
