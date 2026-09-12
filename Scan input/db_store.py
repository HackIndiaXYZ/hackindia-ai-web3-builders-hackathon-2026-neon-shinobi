"""
DB STORE — SQLite persistence for history & trends
===================================================
Purana behaviour: sab kuch sirf in-memory tha, backend restart hote hi
sab data gayab. Ye module teen cheezein persist karta hai (SQLite mein,
ek single file `zerotrust_history.db`):

  1. alerts_history    — har unique alert pattern (risk_type + src/dst)
                          ka ek row, first_seen/last_seen/occurrence_count
                          ke saath. Same alert baar-baar insert nahi hota,
                          bas last_seen/count update hota hai — isliye
                          table bloat nahi hoti aur "ye alert kab se chal
                          raha hai" jaisa sawaal answer ho sakta hai.
  2. policies_history   — same idea, generated policies ke liye.
  3. metrics_history    — har capture cycle ka ek snapshot (device/
                          connection/alert/policy counts) — isse trend
                          chart banta hai dashboard mein.

Retention: metrics_history bahut fast badhti hai (har cycle ek row), isliye
purani rows (default: >24h) automatically prune ho jaati hain. alerts/
policies history discrete events hain (noise nahi), isliye wo persist
rehte hain, bas ek hard row-count cap ke saath (safety valve).
"""

import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "..", "output", "zerotrust_history.db")

MAX_HISTORY_ROWS = 5000  # safety cap for alerts_history / policies_history

_lock = threading.Lock()
_conn = None


def _get_conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db():
    with _lock:
        conn = _get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedup_key TEXT UNIQUE NOT NULL,
                risk_type TEXT NOT NULL,
                risk_level TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                latest_confidence REAL,
                latest_evidence TEXT,
                latest_process TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS policies_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dedup_key TEXT UNIQUE NOT NULL,
                action TEXT,
                iptables_rule TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device_count INTEGER,
                connection_count INTEGER,
                alert_count INTEGER,
                policy_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id TEXT UNIQUE NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN ('APPROVED', 'REJECTED')),
                reviewer TEXT NOT NULL,
                decided_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_policy_decisions_at ON policy_decisions(decided_at);

            CREATE TABLE IF NOT EXISTS chain_anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content_hash TEXT NOT NULL,
                tx_hash TEXT,
                block_number INTEGER,
                chain_id INTEGER,
                contract_address TEXT,
                network_label TEXT,
                label TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts_history(last_seen);
        """)
        conn.commit()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def record_cycle(alerts, policies, metrics, retention_hours=24.0):
    """Called once per capture cycle. Upserts alerts/policies into their
    history tables (dedup'd) and appends one metrics_history row."""
    now = _now_iso()
    with _lock:
        conn = _get_conn()
        cur = conn.cursor()

        for a in alerts:
            dedup_key = f"{a.get('risk_type')}|{a.get('src_ip')}|{a.get('dst_ip')}"
            cur.execute("SELECT id, occurrence_count FROM alerts_history WHERE dedup_key = ?", (dedup_key,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    """UPDATE alerts_history
                       SET last_seen = ?, occurrence_count = ?, latest_confidence = ?,
                           latest_evidence = ?, latest_process = ?, risk_level = ?
                       WHERE id = ?""",
                    (now, row["occurrence_count"] + 1, a.get("confidence_score"),
                     a.get("evidence"), a.get("src_process"), a.get("risk_level"), row["id"])
                )
            else:
                cur.execute(
                    """INSERT INTO alerts_history
                       (dedup_key, risk_type, risk_level, src_ip, dst_ip, latest_confidence,
                        latest_evidence, latest_process, first_seen, last_seen, occurrence_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (dedup_key, a.get("risk_type"), a.get("risk_level"), a.get("src_ip"),
                     a.get("dst_ip"), a.get("confidence_score"), a.get("evidence"),
                     a.get("src_process"), now, now)
                )

        for p in policies:
            dedup_key = f"{p.get('action')}|{p.get('iptables_rule')}"
            cur.execute("SELECT id, occurrence_count FROM policies_history WHERE dedup_key = ?", (dedup_key,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE policies_history SET last_seen = ?, occurrence_count = ? WHERE id = ?",
                    (now, row["occurrence_count"] + 1, row["id"])
                )
            else:
                cur.execute(
                    """INSERT INTO policies_history
                       (dedup_key, action, iptables_rule, first_seen, last_seen, occurrence_count)
                       VALUES (?, ?, ?, ?, ?, 1)""",
                    (dedup_key, p.get("action"), p.get("iptables_rule"), now, now)
                )

        cur.execute(
            """INSERT INTO metrics_history
               (timestamp, device_count, connection_count, alert_count, policy_count)
               VALUES (?, ?, ?, ?, ?)""",
            (now, metrics.get("total_devices", 0), metrics.get("total_connections", 0),
             metrics.get("total_alerts", 0), metrics.get("total_policies", 0))
        )

        # prune old metrics rows (this table grows every single cycle)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=retention_hours)).isoformat()
        cur.execute("DELETE FROM metrics_history WHERE timestamp < ?", (cutoff,))

        # safety cap on the history tables regardless of age
        for table in ("alerts_history", "policies_history"):
            cur.execute(f"SELECT COUNT(*) AS c FROM {table}")
            count = cur.fetchone()["c"]
            if count > MAX_HISTORY_ROWS:
                cur.execute(
                    f"""DELETE FROM {table} WHERE id IN (
                            SELECT id FROM {table} ORDER BY last_seen ASC LIMIT ?
                        )""",
                    (count - MAX_HISTORY_ROWS,)
                )

        conn.commit()


def get_metrics_history(minutes=60):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """SELECT timestamp, device_count, connection_count, alert_count, policy_count
               FROM metrics_history WHERE timestamp >= ? ORDER BY timestamp ASC""",
            (cutoff,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_alerts_history(limit=100):
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """SELECT risk_type, risk_level, src_ip, dst_ip, latest_confidence, latest_evidence,
                      latest_process, first_seen, last_seen, occurrence_count
               FROM alerts_history ORDER BY last_seen DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_policies_history(limit=100):
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """SELECT action, iptables_rule, first_seen, last_seen, occurrence_count
               FROM policies_history ORDER BY last_seen DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def set_policy_decision(policy_id, decision, reviewer="Sys Admin"):
    """Persist a human review decision for a generated policy.

    Decisions are keyed by policy_id so a policy regenerated on later live
    capture cycles keeps the analyst's decision instead of resetting to
    SUGGESTED. This records the decision but deliberately does not execute
    the firewall command.
    """
    decision = str(decision).upper()
    if decision not in {"APPROVED", "REJECTED"}:
        raise ValueError("decision must be APPROVED or REJECTED")
    reviewer = (str(reviewer).strip() or "Sys Admin")[:120]
    with _lock:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO policy_decisions (policy_id, decision, reviewer, decided_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(policy_id) DO UPDATE SET
                   decision = excluded.decision,
                   reviewer = excluded.reviewer,
                   decided_at = excluded.decided_at""",
            (policy_id, decision, reviewer, _now_iso())
        )
        conn.commit()


def get_policy_decisions(limit=100):
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """SELECT policy_id, decision, reviewer, decided_at
               FROM policy_decisions ORDER BY decided_at DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_policy_decision(policy_id):
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            "SELECT policy_id, decision, reviewer, decided_at FROM policy_decisions WHERE policy_id = ?",
            (policy_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None


def record_anchor(content_hash, tx_hash, block_number, chain_id, contract_address, network_label, label):
    with _lock:
        conn = _get_conn()
        conn.execute(
            """INSERT INTO chain_anchors
               (content_hash, tx_hash, block_number, chain_id, contract_address,
                network_label, label, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (content_hash, tx_hash, block_number, chain_id, contract_address,
             network_label, label, _now_iso())
        )
        conn.commit()


def get_anchor_history(limit=50):
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """SELECT content_hash, tx_hash, block_number, chain_id, contract_address,
                      network_label, label, created_at
               FROM chain_anchors ORDER BY id DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]
