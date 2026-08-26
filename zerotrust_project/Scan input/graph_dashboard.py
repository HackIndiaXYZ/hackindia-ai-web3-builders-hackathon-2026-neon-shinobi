"""
NETWORK GRAPH VISUALIZER (Dashboard)
=====================================
Ye script teen files padhta hai:
  - network_snapshot.json (devices + connections)
  - risk_alerts.json (risky connections)
  - generated_policies.json (suggested firewall rules)

Aur ek interactive graph + tables dikhata hai — jaise judges ke demo
mein "live network map" dikhta hai.

Chalane ka tarika:
    streamlit run graph_dashboard.py
"""

import streamlit as st
import json
import pandas as pd
import os
import plotly.graph_objects as go
import networkx as nx

st.set_page_config(page_title="Zero-Trust Network Visualizer", layout="wide")

st.title("🛡️ Zero-Trust Micro-Segmentation Visualizer")
st.caption("Live network topology, risk detection & auto-generated policies")

# ---- LOAD DATA ----
def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r") as f:
        return json.load(f)

snapshot = load_json("network_snapshot.json")
risk_alerts = load_json("risk_alerts.json") or []
policies = load_json("generated_policies.json") or []

if snapshot is None:
    st.error("network_snapshot.json nahi mili. Pehle network_simulator.py, "
             "risk_engine.py, aur policy_generator.py chalao.")
    st.stop()

devices = snapshot["devices"]
connections = snapshot["connections"]

# risky connection IDs ka set bana lo, quick lookup ke liye
risky_conn_ids = {a["conn_id"] for a in risk_alerts}

# ---- TOP METRICS ----
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Devices", len(devices))
col2.metric("Total Connections", len(connections))
col3.metric("Risk Alerts", len(risk_alerts))
col4.metric("Policies Generated", len(policies))

st.divider()

# ---- BUILD GRAPH ----
st.subheader("🕸️ Live Network Topology")

SEGMENT_COLORS = {
    "guest": "#94a3b8",      # grey
    "employee": "#3b82f6",   # blue
    "server": "#ef4444",     # red (high value)
    "iot": "#f59e0b",        # orange
}

G = nx.spring_layout  # we'll use networkx just for layout computation
graph = nx.Graph()

for d in devices:
    graph.add_node(d["ip"], **d)

for c in connections:
    graph.add_edge(c["src_ip"], c["dst_ip"], conn_id=c["conn_id"], risky=(c["conn_id"] in risky_conn_ids))

pos = nx.spring_layout(graph, seed=42, k=0.8)

# ---- EDGES (draw risky ones on top, in red) ----
edge_traces = []

normal_x, normal_y = [], []
risky_x, risky_y = [], []

for u, v, data in graph.edges(data=True):
    x0, y0 = pos[u]
    x1, y1 = pos[v]
    if data.get("risky"):
        risky_x += [x0, x1, None]
        risky_y += [y0, y1, None]
    else:
        normal_x += [x0, x1, None]
        normal_y += [y0, y1, None]

normal_edge_trace = go.Scatter(
    x=normal_x, y=normal_y, mode="lines",
    line=dict(width=1, color="#475569"),
    hoverinfo="none", showlegend=False
)

risky_edge_trace = go.Scatter(
    x=risky_x, y=risky_y, mode="lines",
    line=dict(width=3, color="#ef4444"),
    hoverinfo="none", showlegend=False
)

# ---- NODES ----
node_x, node_y, node_color, node_text = [], [], [], []
for d in devices:
    x, y = pos[d["ip"]]
    node_x.append(x)
    node_y.append(y)
    node_color.append(SEGMENT_COLORS.get(d["segment"], "#999999"))
    node_text.append(f"{d['device_id']}<br>{d['ip']}<br>{d['device_type']}<br>segment: {d['segment']}")

node_trace = go.Scatter(
    x=node_x, y=node_y, mode="markers+text",
    marker=dict(size=22, color=node_color, line=dict(width=2, color="white")),
    text=[d["device_type"] for d in devices],
    textposition="bottom center",
    hovertext=node_text, hoverinfo="text",
    showlegend=False
)

fig = go.Figure(data=[normal_edge_trace, risky_edge_trace, node_trace])
fig.update_layout(
    showlegend=False,
    margin=dict(l=10, r=10, t=10, b=10),
    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    height=500,
    plot_bgcolor="rgba(0,0,0,0)",
)

st.plotly_chart(fig, use_container_width=True)

st.caption("🔴 Red edges = risky connections flagged by the Risk Engine | "
           "Node colors: 🔵 Employee · 🔴 Server · 🟠 IoT · ⚪ Guest")

st.divider()

# ---- RISK ALERTS TABLE ----
st.subheader("🚨 Risk Alerts")
if risk_alerts:
    df_alerts = pd.DataFrame(risk_alerts)
    st.dataframe(
        df_alerts[["risk_type", "risk_level", "confidence_score", "src_ip", "dst_ip", "evidence"]],
        use_container_width=True, hide_index=True
    )
else:
    st.info("Koi risk alert nahi mila.")

st.divider()

# ---- SUGGESTED POLICIES TABLE ----
st.subheader("🛠️ Auto-Generated Policies (Suggested — Human Review Required)")
if policies:
    df_policies = pd.DataFrame(policies)
    st.dataframe(
        df_policies[["policy_id", "based_on_alert", "risk_level", "action", "iptables_rule", "status"]],
        use_container_width=True, hide_index=True
    )
else:
    st.info("Koi policy generate nahi hui.")
