# 🛡️ Zero-Trust Micro-segmentation Visualizer

> **Visualize. Detect. Segment. Secure.**

A real-time cybersecurity platform that maps network communication, detects risky lateral-movement paths, and automatically recommends Zero-Trust micro-segmentation policies.

---

## 🚨 Problem Statement

Traditional enterprise networks are often too **flat**.

Once an attacker compromises a single device, they may be able to move laterally across the network and reach sensitive systems such as:

* 💻 Employee/Developer laptops
* 🗄️ Databases
* 💰 Finance servers
* 👥 HR systems
* ☁️ Cloud resources

The core problem is:

> **Organizations often don't have a clear, real-time view of which systems are communicating with each other and whether those communication paths are actually necessary.**

Existing enterprise micro-segmentation solutions can also be expensive and complex for smaller organizations.

---

## 💡 Our Solution

**Zero-Trust Micro-segmentation Visualizer** provides a lightweight way to discover, visualize, analyze, and secure network communication.

The system:

1. **Discovers active network connections**
2. **Builds a live network topology**
3. **Identifies risky communication paths**
4. **Detects potential lateral movement**
5. **Recommends segmentation policies**
6. **Generates deployable firewall rules**

### Zero-Trust Principle

> **Never Trust. Always Verify.**

A device being inside the corporate network does **not** automatically mean it should be allowed to communicate with every other device.

---

# 🎯 Key Features

## 1. 🔍 Live Network Discovery

Lightweight agents collect active connection information from hosts.

Collected information may include:

* Source IP
* Destination IP
* Source/Destination Port
* Protocol
* Connection state
* Host information
* Timestamp

Technologies:

`Python` · `psutil` · `scapy`

---

## 2. 🌐 Live Network Visualization

Network communication is represented as an interactive graph.

### Graph Components

**Nodes**

Represent:

* Users
* Laptops
* Servers
* Databases
* Cloud resources

**Edges**

Represent active communication between nodes.

Example:

```text
Developer Laptop
       │
       ▼
Application Server
       │
       ▼
Finance Database
```

The graph updates as network communication changes.

---

## 3. 🚨 Risk Detection

The system analyzes communication paths and identifies potentially dangerous connections.

### Example

```text
Developer Laptop ───────────► Finance DB
       ⚠️ HIGH RISK
```

Possible risk factors:

* Sensitive server reachable from unauthorized host
* Unusual communication
* Unexpected port usage
* Cross-zone communication
* Direct database access
* Potential lateral movement path

---

## 4. 🕵️ Lateral Movement Detection

The system identifies paths that could allow an attacker to move from a compromised machine toward sensitive infrastructure.

### Attack Scenario

```text
Compromised Laptop
       │
       ▼
Internal Server
       │
       ▼
Finance Database
       │
       ▼
Sensitive Data
```

The visualizer highlights the risky path and generates a security alert.

Example:

```text
⚠️ Suspicious Lateral Movement Detected

Source: DEV-LAPTOP
Destination: FINANCE-DB
Risk: HIGH
Reason: Unauthorized direct database communication
```

---

# 🔐 Zero-Trust Policy Engine

The policy engine evaluates observed communication against predefined security rules.

Example:

```text
ALLOW
Finance-Laptop → Finance-DB : TCP/5432

DENY
Developer-Laptop → Finance-DB : TCP/5432
```

Policies can be based on:

* Host identity
* Network zone
* IP address
* Port
* Protocol
* Resource sensitivity
* Communication history

---

# ⚙️ Automatic Policy Recommendation

Instead of only reporting a problem, the system recommends an action.

### Example

Detected:

```text
DEV-LAPTOP → FINANCE-DB : TCP/5432
```

Recommended:

```text
DENY DEV-LAPTOP → FINANCE-DB : TCP/5432
```

The recommendation can be converted into firewall/security-group configurations.

---

# 🧱 Firewall Rule Generation

The system can generate rules for common environments.

### Linux iptables

```bash
iptables -A OUTPUT -d <FINANCE_DB_IP> -p tcp --dport 5432 -j DROP
```

### nftables

```bash
ip daddr <FINANCE_DB_IP> tcp dport 5432 drop
```

### Cloud Security Groups

The system can generate equivalent allow/deny policy configurations for cloud environments.

> **Note:** Generated policies should be reviewed and tested before production deployment.

---

# 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │     Network Hosts   │
                    │                     │
                    │ Laptop │ Server │ DB│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Lightweight Agent  │
                    │   psutil / Scapy    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │      Backend        │
                    │    FastAPI/Flask    │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
       ┌─────────────────┐        ┌─────────────────┐
       │  Risk Detection │        │  Policy Engine  │
       └────────┬────────┘        └────────┬────────┘
                │                          │
                └────────────┬─────────────┘
                             ▼
                    ┌─────────────────┐
                    │  Graph / API    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ React Dashboard │
                    │   D3.js/Graph   │
                    └─────────────────┘
```

---

# 🖥️ Dashboard

The dashboard provides:

### Network Overview

* Total devices
* Active connections
* High-risk connections
* Network zones
* Detected anomalies

### Live Graph

```text
        [Developer]
             │
             │
             ▼
        [App Server]
          ╱       ╲
         ╱         ╲
        ▼           ▼
 [Finance DB]    [Web Server]
     🔴
```

### Security Alerts

```text
⚠ HIGH RISK
Unauthorized database access detected

Source: DEV-01
Target: FINANCE-DB
Port: 5432
Action: Block recommended
```

---

# 🧪 Demo Scenario

Our hackathon demonstration simulates a realistic enterprise attack.

### Step 1 — Normal Network

```text
Employee → Web Server
Finance Team → Finance DB
Developer → Development Server
```

Everything appears normal.

### Step 2 — Compromise Simulation

A developer machine is simulated as compromised.

### Step 3 — Lateral Movement

The compromised machine attempts to communicate with:

```text
Developer Laptop → Internal Server → Finance DB
```

### Step 4 — Detection

The system detects the suspicious path.

```text
🚨 LATERAL MOVEMENT DETECTED
Risk Level: HIGH
```

### Step 5 — Visualization

The suspicious path is highlighted on the live graph.

### Step 6 — Mitigation

The system recommends:

```text
BLOCK

Developer Laptop
        ↓
Finance Database
TCP/5432
```

### Step 7 — Rule Generation

A firewall/security-group rule is generated automatically.

---

# 🛠️ Technology Stack

## Backend

* Python
* FastAPI / Flask
* REST API
* WebSocket

## Network Monitoring

* `psutil`
* `scapy`
* `ss` / `netstat`

## Frontend

* React
* D3.js / Force Graph
* JavaScript
* HTML/CSS

## Security Engine

* Rule-based risk detection
* Network segmentation logic
* Lateral movement analysis

## Deployment

* Linux
* Docker
* Git/GitHub

---

# 📁 Project Structure

```text
zero-trust-visualizer/
│
├── backend/
│   ├── main.py
│   ├── api/
│   ├── models/
│   ├── services/
│   ├── risk_engine/
│   └── policy_engine/
│
├── agent/
│   ├── collector.py
│   ├── network_monitor.py
│   └── config.py
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── graph/
│   │   └── services/
│   └── package.json
│
├── policies/
│   ├── rules.json
│   └── templates/
│
├── simulation/
│   └── attack_scenarios/
│
├── tests/
│
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone <repository-url>
cd zero-trust-visualizer
```

## Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
```

## Frontend

```bash
cd frontend
npm install
npm run dev
```

## Agent

Run the monitoring agent on the authorized test machine:

```bash
python agent/collector.py
```

---

# 🔄 Data Flow

```text
Host
 ↓
Connection Collector
 ↓
Network Event
 ↓
Backend API
 ↓
Risk Analysis
 ↓
Policy Engine
 ↓
Graph Visualization
 ↓
Security Recommendation
```

---

# 📊 Risk Scoring

Each communication path can receive a risk score based on factors such as:

| Factor                  | Example           |
| ----------------------- | ----------------- |
| Destination sensitivity | Finance DB        |
| Source trust level      | Guest/Developer   |
| Port                    | Database port     |
| Communication frequency | Unusual spike     |
| Network zone            | Cross-zone        |
| Historical behavior     | Previously unseen |

Example:

```text
Risk Score: 87/100
Risk Level: HIGH
```

---

# 🔮 Future Scope

* ML-based anomaly detection
* Kubernetes micro-segmentation
* AWS/Azure/GCP security-group integration
* Identity-based policies
* eBPF-based monitoring
* Automated policy deployment
* SIEM integration
* Threat-intelligence enrichment
* Continuous Zero-Trust posture scoring

---

# 🔒 Security & Ethics

This project is designed for **authorized networks and controlled environments only**.

The attack scenarios used in the demonstration are simulated to demonstrate detection and mitigation capabilities.

The project does not attempt to gain unauthorized access to systems.

---

# 🏆 Why This Project?

Traditional network monitoring tells you:

> **"Something happened."**

Our system aims to tell you:

> **"This device can reach this sensitive resource, this path is risky, and here's the segmentation rule you should consider."**

### Our Core Value

**Visibility → Detection → Recommendation → Mitigation**

---

# 👥 Team Roles

| Role             | Responsibility                                     |
| ---------------- | -------------------------------------------------- |
| Network/Security | Network monitoring, threat detection, segmentation |
| Backend          | APIs, data processing, risk engine                 |
| Frontend         | Live graph and dashboard                           |
| Policy Engine    | Firewall/security-group rule generation            |
| Integration      | Connecting all components and demo                 |

---

# 📌 Project Status

**Current Stage:** Hackathon Prototype

### Planned MVP

* [ ] Host connection discovery
* [ ] Backend API
* [ ] Live network graph
* [ ] Risk detection
* [ ] Lateral movement simulation
* [ ] Policy recommendation
* [ ] iptables/nftables rule generation
* [ ] End-to-end demo

---

# ⭐ Expected Impact

The project aims to make Zero-Trust micro-segmentation more:

**Visible → Understandable → Affordable → Actionable**

Instead of manually analyzing complex network relationships, security teams can visually understand their attack surface and identify where segmentation should be applied.
