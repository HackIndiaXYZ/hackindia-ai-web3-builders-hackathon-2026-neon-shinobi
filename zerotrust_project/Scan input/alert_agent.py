"""
ALERT TRIAGE & NOTIFICATION AGENT (Production Scalable Edition)
==============================================================
Fully offline, rule-based, explainable alert triage engine.

Key Features & Enhancements:
1. CORRELATE  -- Extensible sliding-window correlation (Source IP / Multi-Vector).
2. PRIORITIZE -- Multi-factor scoring (Max Risk Severity + Velocity Bonus + Asset Criticality + Multi-vector Bonus + Confidence).
3. EXPLAIN    -- Human-auditable reasoning steps + natural language incident summary.
4. MATCH      -- Canonical O(1) remediation policy index lookup.
5. NOTIFY     -- Outputs structured notification list for SOC dashboard bell feed.
"""

import json
import os
import sys
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

# ---- CONFIGURATION ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CORRELATION_WINDOW_SECONDS = 300  # 5-minute sliding window

RISK_LEVEL_SCORE = {
    "CRITICAL": 4.0,
    "HIGH": 3.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
    "INFO": 0.5
}

# ---- DATA MODELS ----
class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    risk_type: str
    risk_level: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    conn_id: Optional[str] = None
    flow_id: Optional[str] = None
    confidence_score: float = 0.5
    asset_criticality: int = 1  # Tier 1 (Low) to 5 (Critical)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        ts_raw = data.get("timestamp")
        if isinstance(ts_raw, str):
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        elif isinstance(ts_raw, datetime):
            ts = ts_raw
        else:
            ts = datetime.now()

        severity = data.get("risk_type_level") or data.get("risk_level", "LOW")
        severity = str(severity).upper()
        if severity not in RISK_LEVEL_SCORE:
            severity = "LOW"

        return cls(
            alert_id=data.get("alert_id") or data.get("conn_id") or f"alt_{hash(str(data))}",
            timestamp=ts,
            risk_type=data.get("risk_type", "unknown_threat"),
            risk_level=severity,
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            conn_id=data.get("conn_id"),
            flow_id=data.get("flow_id"),
            confidence_score=float(data.get("confidence_score", 0.5)),
            asset_criticality=int(data.get("asset_criticality", 1)),
            raw_data=data
        )

@dataclass
class Incident:
    incident_id: str
    src_ip: str
    alerts: List[Alert] = field(default_factory=list)
    first_ts: datetime = field(default_factory=datetime.now)
    last_ts: datetime = field(default_factory=datetime.now)

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
        if alert.timestamp > self.last_ts:
            self.last_ts = alert.timestamp
        if alert.timestamp < self.first_ts:
            self.first_ts = alert.timestamp

# ---- UTILITIES ----
def load_json(filepath: str) -> List[Dict[str, Any]]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

# ---- CORE AGENT ENGINES ----
def correlate_alerts(alerts_raw: List[Dict[str, Any]], window_seconds: int = CORRELATION_WINDOW_SECONDS) -> List[Incident]:
    """
    STEP 1: CORRELATION
    Sliding-window correlation grouped by source IP (or fallback unknown identifier).
    """
    if not alerts_raw:
        return []

    alerts = [Alert.from_dict(a) for a in alerts_raw]
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    
    incidents: List[Incident] = []
    open_incidents: Dict[str, Incident] = {}
    incident_counter = 1

    for alert in sorted_alerts:
        src = alert.src_ip or f"unknown-{alert.conn_id or alert.alert_id}"

        if src in open_incidents:
            last_ts = open_incidents[src].last_ts
            if (alert.timestamp - last_ts).total_seconds() <= window_seconds:
                open_incidents[src].add_alert(alert)
                continue

        # Start new incident
        inc_id = f"INC-{incident_counter:03d}"
        incident_counter += 1
        new_inc = Incident(
            incident_id=inc_id,
            src_ip=src,
            alerts=[alert],
            first_ts=alert.timestamp,
            last_ts=alert.timestamp
        )
        open_incidents[src] = new_inc
        incidents.append(new_inc)

    return incidents


def prioritize(incident: Incident) -> float:
    """
    STEP 2: PRIORITIZATION
    Multi-factor scoring algorithm:
    Score = Max Severity Score + Avg Confidence + Velocity Bonus + Asset Criticality + Multi-Vector Bonus
    """
    alerts = incident.alerts
    max_risk_score = max(RISK_LEVEL_SCORE.get(a.risk_level, 1.0) for a in alerts)
    avg_confidence = sum(a.confidence_score for a in alerts) / len(alerts)
    
    # Velocity/Frequency escalation multiplier
    escalation_bonus = min((len(alerts) - 1) * 0.5, 1.5)
    
    # Target Asset Criticality bonus
    max_asset_crit = max(a.asset_criticality for a in alerts)
    asset_bonus = max_asset_crit * 0.5
    
    # Multi-vector attack bonus
    unique_types = {a.risk_type for a in alerts}
    multi_vector_bonus = 1.0 if len(unique_types) > 1 else 0.0

    score = max_risk_score + avg_confidence + escalation_bonus + asset_bonus + multi_vector_bonus
    return round(score, 2)


def explain(incident: Incident) -> Tuple[str, List[str], str, List[str]]:
    """
    STEP 3: EXPLANATION
    Generates an auditable reasoning trace and natural language summary.
    """
    alerts = incident.alerts
    src = incident.src_ip
    risk_types = list(dict.fromkeys(a.risk_type for a in alerts))
    
    highest_alert = max(alerts, key=lambda a: RISK_LEVEL_SCORE.get(a.risk_level, 1.0))
    max_level = highest_alert.risk_level

    reasoning_steps = []
    reasoning_steps.append(
        f"Detected {len(alerts)} alert(s) from source {src} within a "
        f"{CORRELATION_WINDOW_SECONDS // 60}-minute window -> correlated into one incident."
    )
    if len(alerts) > 1:
        reasoning_steps.append(
            f"Multiple alerts from same source -> treated as escalating threat velocity -> priority score increased."
        )
    reasoning_steps.append(
        f"Highest severity among grouped alerts: {max_level} -> base priority score established."
    )
    reasoning_steps.append(
        f"Threat signatures involved: {', '.join(risk_types)}."
    )

    max_crit = max(a.asset_criticality for a in alerts)
    if max_crit > 1:
        reasoning_steps.append(
            f"Target asset criticality tier ({max_crit}/5) -> boosted priority weight."
        )

    formatted_types = [t.replace("_", " ").title() for t in risk_types]
    if len(risk_types) == 1:
        summary = f"{formatted_types[0]} detected from {src} ({len(alerts)} event(s))."
    else:
        summary = f"Multiple threat types ({', '.join(formatted_types)}) from {src} — possible coordinated activity."

    return summary, reasoning_steps, max_level, risk_types


def attach_policy(incident: Incident, policies: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    STEP 4: POLICY MATCHING
    O(1) indexed lookup for matching remediation policies.
    """
    policy_lookup = {}
    for p in policies:
        pol_id = p.get("policy_id", "")
        conn_key = pol_id.replace("POL-", "") if "POL-" in pol_id else pol_id
        policy_lookup[conn_key] = p
        if "conn_id" in p:
            policy_lookup[p["conn_id"]] = p

    for alert in incident.alerts:
        cid = alert.conn_id or alert.flow_id or alert.alert_id
        if cid and cid in policy_lookup:
            return policy_lookup[cid]
    return None


def build_notifications(alerts_file=None, policies_file=None) -> List[Dict[str, Any]]:
    if alerts_file is None:
        alerts_file = os.path.join(OUTPUT_DIR, "risk_alerts.json")
    if policies_file is None:
        policies_file = os.path.join(OUTPUT_DIR, "generated_policies.json")

    raw_alerts = load_json(alerts_file)
    raw_policies = load_json(policies_file)

    incidents = correlate_alerts(raw_alerts)

    notifications = []
    for i, incident in enumerate(incidents, start=1):
        summary, reasoning, max_level, risk_types = explain(incident)
        priority_score = prioritize(incident)
        policy = attach_policy(incident, raw_policies)

        notification = {
            "notification_id": f"N{i:03d}",
            "timestamp": incident.last_ts.isoformat(),
            "src_ip": incident.src_ip,
            "alert_count": len(incident.alerts),
            "risk_types": risk_types,
            "severity": max_level,
            "priority_score": priority_score,
            "summary": summary,
            "agent_reasoning": reasoning,
            "recommended_policy": policy.get("iptables_rule") if policy else None,
            "status": "AWAITING_ANALYST_REVIEW",
        }
        notifications.append(notification)

    # Sort notifications by priority score descending
    notifications.sort(key=lambda n: n["priority_score"], reverse=True)
    return notifications


# ---- CLI / ENTRYPOINT ----
if __name__ == "__main__":
    print("[*] Agent starting: reading alerts + policies...")
    notifications = build_notifications()

    print(f"[*] Correlated into {len(notifications)} incident(s)\n")
    for n in notifications:
        print(f"--- {n['notification_id']} | Priority Score: {n['priority_score']} | Severity: {n['severity']} ---")
        print(f"Summary: {n['summary']}")
        print("Agent reasoning:")
        for step in n["agent_reasoning"]:
            print(f"   -> {step}")
        if n["recommended_policy"]:
            print(f"Recommended policy: {n['recommended_policy']}")
        print(f"Status: {n['status']}\n")

    output_path = os.path.join(OUTPUT_DIR, "agent_notifications.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(notifications, f, indent=2)
    print(f"[+] Saved to '{output_path}' — dashboard notification-bell ab isko consume karega")