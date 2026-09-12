# Aegis --- Zero-Trust Micro-Segmentation Visualizer

> **Real-time network visibility, threat detection, risk intelligence,
> micro-segmentation, policy generation, audit history, and optional
> AI-assisted security analysis.**

Aegis is a local-first security operations dashboard designed to
demonstrate how a Zero-Trust security workflow can move from **observed
network activity → device discovery → behavioral analysis → threat
detection → risk scoring → interpretable alerts → policy recommendations
→ human review → historical auditability**.

It is built as a practical hackathon-grade prototype with a live Windows
network capture mode and a simulated/offline mode.

------------------------------------------------------------------------

## Overview

Traditional network monitoring often presents large amounts of traffic
without clearly connecting that telemetry to security decisions.

Aegis turns observed connection metadata into a security workflow:

``` text
REAL NETWORK ACTIVITY
        │
        ▼
LIVE CONNECTION CAPTURE
        │
        ▼
DEVICE / ASSET DISCOVERY
        │
        ▼
SEGMENT CLASSIFICATION
        │
        ▼
BEHAVIOR & RISK ANALYSIS
        │
        ▼
THREAT DETECTION
        │
        ▼
INTERPRETABLE ALERT
        │
        ▼
POLICY GENERATION
        │
        ▼
HUMAN REVIEW / DECISION
        │
        ▼
HISTORY & AUDIT TRAIL
        │
        ▼
DASHBOARD / SECURITY ANALYST
```

The project is intentionally designed so that **observed telemetry and
deterministic security logic remain authoritative**. Optional AI
assistance explains and prioritizes security findings; it does not
autonomously enforce firewall changes.

------------------------------------------------------------------------

## Key Capabilities

### 1. Real-Time Network Monitoring

In live mode, the backend continuously reads active network connection
metadata from the local machine using `psutil`.

The dashboard provides:

-   Live device/endpoint discovery
-   Connection counts
-   Local host identification
-   Process/application context where available
-   Continuous security-state updates
-   Live capture status
-   Historical persistence

For full visibility into system-wide connections on Windows, running the
backend from an **Administrator PowerShell** is recommended.

> The system observes network connection metadata. It is not designed to
> inspect personal files or automatically modify the firewall.

------------------------------------------------------------------------

### 2. Stable Network Topology

The Network Map provides a deterministic radial/spiral visualization of
observed assets.

Design goals:

-   Stable positioning
-   Clear hub-and-spoke presentation
-   Pinned nodes
-   Interactive node selection
-   Zoom/drag interaction
-   Bounded visual connection rendering for performance
-   No uncontrolled force-layout "hairball"

The topology is a visualization of observed telemetry. It does not
itself execute network changes.

------------------------------------------------------------------------

### 3. Threat Detection

The backend processes captured connections through deterministic
detection and risk logic.

The dashboard can surface findings such as:

-   `PORT SCANNING`
-   `FAN OUT LATERAL MOVEMENT`

Detection output is connected to the risk and policy workflow rather
than being a purely visual alert.

The system also includes baseline/allowlist concepts to reduce
unnecessary fan-out noise from normal application traffic.

------------------------------------------------------------------------

### 4. Risk Intelligence

The Asset Intelligence view ranks observed assets using available
telemetry and security signals.

It provides:

-   Asset inventory
-   Segment classification
-   Risk score
-   Alert count
-   Connection count
-   Policy exposure
-   Investigation/monitoring priority

This gives an analyst a way to move from "something happened" to "which
asset should I investigate first?"

------------------------------------------------------------------------

### 5. Zero-Trust Micro-Segmentation

The Segmentation view presents a deterministic communication policy
model between logical segments such as:

-   Guest
-   Employee
-   Server
-   IoT
-   Internet
-   Local network

The matrix represents communication decisions such as:

-   `ALLOW`
-   `RESTRICTED`
-   `DENY`

Observed traffic can then be evaluated against the segmentation model to
identify policy violations.

The system does **not** claim that every observed connection is
malicious merely because a segmentation rule is restrictive.

------------------------------------------------------------------------

### 6. Policy Generation

Detected security conditions can produce policy recommendations.

Policies are treated as **recommendations**, not automatic enforcement.

A reviewer can:

-   Inspect a generated policy
-   Approve it
-   Reject it
-   Review the resulting decision history

Policy decisions are persisted in SQLite.

> A policy shown by the dashboard does not mean the corresponding
> firewall rule has been automatically applied.

This human-in-the-loop design is intentional and avoids unsafe
autonomous network enforcement.

------------------------------------------------------------------------

### 7. Policy Impact Simulation

The Policy Impact view allows analysts to reason about the effect of a
proposed policy before making a decision.

The simulator is intended to answer questions such as:

-   Which traffic would be affected?
-   Which segments would be restricted?
-   What assets could be impacted?
-   What security benefit is expected?

Simulation is advisory and does not directly change the operating system
firewall.

------------------------------------------------------------------------

### 8. Attack Path & Lateral Movement Analysis

The Attack Path view uses already observed connections to explore
possible movement between assets and segments.

It provides:

-   Starting asset selection
-   Observed hops
-   Segment transitions
-   Priority paths
-   Observed movement paths

This view is based on existing telemetry. It does not execute attacks or
perform network exploitation.

------------------------------------------------------------------------

### 9. History & Auditability

The History view uses a local SQLite database to retain security
telemetry and decision history.

It supports:

-   Connection/metric trends
-   Recurring alert patterns
-   First/last seen information
-   Alert occurrence counts
-   Policy history
-   Persisted policy decisions

This makes the dashboard useful beyond a single refresh cycle and
provides an audit-oriented record of the security workflow.

------------------------------------------------------------------------

### 10. Optional AI Security Analyst

Aegis includes an optional **real LLM-powered security analyst**
integration.

The architecture deliberately separates:

``` text
DETERMINISTIC SECURITY ENGINE
            │
            ├── authoritative detection
            ├── risk calculation
            └── security evidence
                    │
                    ▼
              OPTIONAL LLM
                    │
                    ▼
          Analyst explanation
          + prioritization
          + recommended actions
```

The AI layer can provide:

-   Security posture assessment
-   Incident prioritization
-   Why the finding matters
-   Evidence-oriented reasoning
-   Recommended next actions
-   Confidence information

The AI layer **does not**:

-   Modify firewall rules
-   Execute containment automatically
-   Override deterministic detections
-   Replace human approval

To enable the optional AI integration, configure an OpenAI API key
through an environment variable or `.env` file. Never commit a real API
key to GitHub.

Example:

``` env
OPENAI_API_KEY=YOUR_API_KEY
OPENAI_MODEL=gpt-5.6-luna
```

If the API key is not configured, the deterministic security analysis
remains available.

------------------------------------------------------------------------

## Architecture

``` text
┌─────────────────────────────────────────────────────────────┐
│                        WEB DASHBOARD                         │
│                                                             │
│ Network Map │ Alerts │ Policies │ Assets │ Segmentation     │
│ Attack Path │ Policy Impact │ AI Analyst │ History          │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     FLASK BACKEND API                       │
│                                                             │
│ Live Capture │ Detection │ Risk │ Policy │ Segmentation     │
│ History │ Audit │ AI Analysis │ Device/Connection APIs      │
└───────────────┬──────────────┬──────────────┬───────────────┘
                │              │              │
                ▼              ▼              ▼
        Network Capture   Security Engine   SQLite History
                │              │              │
                │              ├── Alerts     ├── Metrics
                │              ├── Risk        ├── Alerts
                │              └── Policies    └── Decisions
                │
                ▼
          Local OS Network
          Connection Metadata
```

------------------------------------------------------------------------

## Project Structure

``` text
final_implementation_final_final_no_web3/
│
├── dashboard.html
├── tailwind.css
├── requirements.txt
├── .env.example
├── .gitignore
│
├── README.md
├── README_FIXED_TOPOLOGY.md
├── HOW_TO_RUN.md
├── LICENSE
│
├── output/
│   ├── *.json
│   └── zerotrust_history.db
│
└── Scan input/
    ├── backend_server.py
    ├── live_capture.py
    ├── network_simulator.py
    ├── port_scan_simulator.py
    ├── risk_engine.py
    ├── policy_generator.py
    ├── alert_agent.py
    ├── ai_security_analyst.py
    ├── db_store.py
    ├── chain_anchor.py
    ├── allowlist.json
    │
    └── contracts/
        ├── AuditAnchor.vy
        └── AuditAnchor.json
```

### Core components

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  `dashboard.html`                    Complete dashboard UI and
                                      client-side application logic

  `backend_server.py`                 Flask API, orchestration,
                                      live/simulated serving

  `live_capture.py`                   Live network connection collection

  `network_simulator.py`              Offline/simulated network data

  `risk_engine.py`                    Deterministic threat/risk detection

  `policy_generator.py`               Security policy recommendations

  `alert_agent.py`                    Alert generation/processing

  `db_store.py`                       SQLite persistence

  `ai_security_analyst.py`            Optional LLM-based analyst layer

  `chain_anchor.py`                   Audit/blockchain-related backend
                                      component

  `port_scan_simulator.py`            Controlled localhost scan
                                      demonstration

  `allowlist.json`                    Known-safe network exceptions

  `contracts/`                        Audit contract artifacts retained
                                      with the project
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## API Surface

The Flask backend exposes endpoints for the major dashboard workflows.

  -------------------------------------------------------------------------------
  Endpoint                                    Purpose
  ------------------------------------------- -----------------------------------
  `GET /api/status`                           Backend/live-mode status

  `GET /api/summary`                          Main dashboard summary

  `GET /api/devices`                          Observed devices/assets

  `GET /api/devices/<ip>`                     Details for a specific asset

  `GET /api/connections`                      Observed network connections

  `GET /api/alerts`                           Current alerts

  `GET /api/policies`                         Generated policies

  `POST /api/policies/<policy_id>/decision`   Approve/reject a policy

  `GET /api/policy-decisions`                 Policy decision history

  `GET /api/notifications`                    Security notifications

  `GET /api/segmentation`                     Segmentation model

  `POST /api/segmentation/evaluate`           Evaluate observed traffic against
                                              segmentation

  `POST /api/policy-simulation`               Simulate policy impact

  `GET /api/history/metrics`                  Historical metrics

  `GET /api/history/alerts`                   Historical alerts

  `GET /api/history/policies`                 Historical policies

  `GET /api/ai/analysis`                      AI/security analyst result

  `GET /api/audit/status`                     Audit subsystem status

  `POST /api/audit/anchor`                    Audit anchoring endpoint

  `GET /api/audit/history`                    Audit history

  `GET /api/audit/verify`                     Audit verification
  -------------------------------------------------------------------------------

------------------------------------------------------------------------

## Running the Project

### Requirements

Recommended environment:

-   Windows 10/11
-   Python 3.11+ / 3.13-compatible environment
-   Administrator PowerShell for maximum network visibility
-   Modern web browser
-   Optional: OpenAI API key for the AI analyst

### Install dependencies

From the project root:

``` powershell
pip install flask flask-cors psutil openai python-dotenv
```

The repository also contains `requirements.txt` for the project's
dependency set.

### Start the live backend

From the project root:

``` powershell
cd "Scan input"
python backend_server.py --mode live --port 5000
```

Keep this terminal running.

### Start the dashboard server

Open a second terminal in the project root:

``` powershell
python -m http.server 8000
```

Open:

``` text
http://127.0.0.1:8000/dashboard.html
```

------------------------------------------------------------------------

## Live vs Simulated Mode

### Live mode

Live mode reads actual active connection metadata from the local
machine.

``` powershell
python backend_server.py --mode live --port 5000
```

Use this mode when demonstrating real-time monitoring.

### Simulated mode

Simulated mode provides controlled/offline network data for
demonstrations where real network activity is not required.

``` powershell
python backend_server.py --mode simulated --port 5000
```

Always distinguish simulated telemetry from real telemetry during a
presentation.

------------------------------------------------------------------------

## Controlled Port-Scan Demonstration

The project includes a localhost-only port-scan simulator for controlled
testing.

Run the backend first, then from `Scan input`:

``` powershell
python port_scan_simulator.py
```

The simulator targets the local host rather than an external system.

This can be used to demonstrate the path:

``` text
LOCAL SCAN
    ↓
OBSERVED CONNECTIONS
    ↓
PORT-SCANNING DETECTION
    ↓
RISK SCORE
    ↓
ALERT
    ↓
POLICY RECOMMENDATION
```

Only use the simulator against systems you own or are explicitly
authorized to test.

------------------------------------------------------------------------

## Live Refresh Model

The dashboard is designed for continuous monitoring without forcing a
full browser reload.

The frontend periodically requests fresh backend state while:

-   preserving the current dashboard section
-   updating live metrics
-   updating alerts/policies
-   updating topology data
-   maintaining the live-capture indicator
-   updating the learning/countdown state without requiring manual page
    reloads

This separates **backend capture** from **frontend rendering** so the
application can continue collecting telemetry while the analyst moves
between dashboard views.

------------------------------------------------------------------------

## False-Positive Controls

Real applications naturally communicate with many destinations.

Aegis therefore uses mechanisms intended to reduce noisy detections:

### Baseline learning

The live detector can observe normal traffic before applying fan-out
detection thresholds.

### Allowlist

Known-safe IPs/CIDRs/ports can be represented in:

``` text
Scan input/allowlist.json
```

These controls are intended to reduce false positives rather than
classify all high-volume traffic as malicious.

------------------------------------------------------------------------

## Security Model

Aegis follows a human-in-the-loop security model.

### Deterministic engine

The deterministic detection/risk pipeline is authoritative for security
findings.

### AI analyst

The optional LLM provides explanation and prioritization based on
security context supplied by the application.

### Policy layer

Generated policies are recommendations.

### Enforcement

The dashboard does **not** autonomously modify the host firewall.

This is intentional: security decisions remain reviewable and
demonstrable rather than silently executing potentially disruptive
network changes.

------------------------------------------------------------------------

## Data & Privacy

The live collector is focused on network connection metadata.

Depending on the operating system and available permissions, observed
metadata can include information such as:

-   Local/remote IP addresses
-   Ports
-   Connection state
-   Process/application information
-   Connection timestamps

The application is not intended to inspect personal documents or
arbitrary file contents.

The local SQLite database stores application telemetry/history required
by the dashboard.

If using the optional AI integration, only the compact security context
assembled by the AI analysis component should be sent to the configured
model provider.

**Never commit `.env` or a real API key to the repository.**

------------------------------------------------------------------------

## Demo Workflow

A strong presentation flow is:

### 1. Start with Network Map

Show:

-   Live capture
-   Discovered assets
-   Connection volume
-   Stable topology

### 2. Open Alerts

Explain how observed behavior becomes an interpretable security finding.

### 3. Open Asset Intelligence

Show how risk helps prioritize the asset requiring investigation.

### 4. Open Attack Path

Explain observed connectivity and possible movement paths.

### 5. Open Segmentation

Show the Zero-Trust communication matrix and observed policy evaluation.

### 6. Open Policy Impact

Explain what a recommended policy would affect before approval.

### 7. Open Policies

Demonstrate human approval/rejection and persistence.

### 8. Open History

Show recurring alerts, trends, and historical decisions.

### 9. Open AI Security Analyst

With a configured API key, demonstrate how the optional LLM layer turns
security telemetry into an analyst-oriented explanation and recommended
next actions.

------------------------------------------------------------------------

## Design Principles

The project follows several important principles:

1.  **Visibility before enforcement**
2.  **Deterministic detection before AI interpretation**
3.  **Human approval before policy action**
4.  **Observed telemetry before assumptions**
5.  **Clear separation between live and simulated data**
6.  **Stable visualization over uncontrolled animation**
7.  **Persistent history for auditability**
8.  **Performance-aware rendering for high connection counts**
9.  **No fake security claims**
10. **No autonomous firewall modification**

------------------------------------------------------------------------

## Current Scope

### Implemented

-   Live network connection monitoring
-   Simulated network mode
-   Device discovery
-   Asset intelligence
-   Stable radial network topology
-   Risk scoring
-   Port-scan detection
-   Fan-out/lateral-movement detection
-   Policy generation
-   Human policy approval/rejection
-   Segmentation matrix
-   Policy-impact simulation
-   Attack-path analysis
-   SQLite history
-   Recurring alert tracking
-   Notifications
-   Optional OpenAI-powered security analyst
-   Live dashboard refresh
-   Persistent dashboard view state

### Advisory / simulation-oriented

-   Policy enforcement is advisory
-   Attack-path analysis uses observed telemetry
-   Policy impact is simulation
-   AI recommendations require human review

### Not claimed

-   Automatic firewall enforcement
-   Full packet inspection
-   Enterprise-grade SIEM replacement
-   Autonomous incident response
-   Guaranteed malicious/benign classification

------------------------------------------------------------------------

## Troubleshooting

### Dashboard says backend is unavailable

Verify the backend terminal is running:

``` powershell
python backend_server.py --mode live --port 5000
```

Then verify:

``` text
http://127.0.0.1:5000/api/status
```

### Dashboard is blank or stale

Refresh the dashboard and check the backend terminal for errors.

Also confirm the frontend server is running:

``` powershell
python -m http.server 8000
```

### AI is not available

Confirm the environment contains:

``` text
OPENAI_API_KEY
```

Then restart the backend.

Never paste the API key into GitHub, screenshots, chat messages, or
source files.

### Live network visibility is limited

Run the backend from an **Administrator PowerShell** on Windows.

### Dependency installation fails on a package requiring native compilation

Install the core runtime dependencies individually:

``` powershell
pip install flask flask-cors psutil openai python-dotenv
```

This is sufficient for the main dashboard and AI workflow. Optional
audit/blockchain components may have additional environment
requirements.

------------------------------------------------------------------------

## Why This Project Matters

Zero Trust is not simply "block everything."

A practical Zero-Trust monitoring workflow needs to answer:

-   **Who is communicating?**
-   **What are they communicating with?**
-   **Which segment are they in?**
-   **Is the behavior normal?**
-   **What is the risk?**
-   **Why is it suspicious?**
-   **What policy should be considered?**
-   **What would that policy affect?**
-   **Who approved the decision?**
-   **Can the decision be reviewed later?**

Aegis demonstrates that workflow in one integrated security operations
interface.

------------------------------------------------------------------------

## Technology Stack

**Frontend**

-   HTML
-   JavaScript
-   Tailwind CSS
-   D3-based topology visualization

**Backend**

-   Python
-   Flask
-   Flask-CORS
-   psutil

**Persistence**

-   SQLite
-   JSON telemetry/configuration

**Security Intelligence**

-   Deterministic detection/risk engine
-   Policy generation
-   Segmentation evaluation
-   Optional OpenAI LLM analyst

**Testing / Demonstration**

-   Controlled localhost port-scan simulator
-   Live network capture
-   Simulated network mode

------------------------------------------------------------------------

## License

See [`LICENSE`](LICENSE) for the project license.

------------------------------------------------------------------------

## Final Note

Aegis is a security engineering prototype intended for controlled
environments, demonstrations, research, and hackathon evaluation.

The project prioritizes **reliable telemetry, explainable security
decisions, human review, and demonstrability** over pretending to
provide autonomous enterprise-grade protection.
