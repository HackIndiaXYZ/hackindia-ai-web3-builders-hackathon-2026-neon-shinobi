# Running the Zero-Trust dashboard with real live data

## 1. Install dependencies
```bash
cd "Scan input"
pip install flask flask-cors psutil
```

Optional — only needed for the on-chain audit trail feature:
```bash
pip install "web3[tester]"
```
If you skip this, everything else works fine; the audit endpoints just
report clearly that it's unavailable instead of crashing anything.

## 2. Start the backend (this is the important part)
```bash
python3 backend_server.py
```
That's it — one command. By default it runs in **live mode**:
- Captures your machine's real active network connections continuously (every 2s)
- Automatically runs the full detection pipeline (risk engine → policy
  generator → alert agent) on every cycle
- Serves the results at `http://127.0.0.1:5000/api/summary`
- Logs everything into a local SQLite DB (`output/zerotrust_history.db`)
  for the History tab's trend chart and recurring-alert tracking
- Suppresses fan-out alerts for the first 60s while it learns your
  normal traffic pattern (see "False positives" below)

No more running `network_simulator.py` → `risk_engine.py` →
`policy_generator.py` → `alert_agent.py` by hand — the backend now does
that loop itself, continuously, on real data.

For full visibility (seeing other processes' connections, not just this
terminal's), run it elevated:
- Linux/macOS: `sudo python3 backend_server.py`
- Windows: open Command Prompt "as Administrator" first

### Try it live
In a second terminal, once the backend is running:
```bash
python3 port_scan_simulator.py
```
This safely scans 15 ports on your own machine (127.0.0.1 only). Within
a couple of seconds you'll see a real `PORT_SCANNING` alert and a real
generated iptables rule show up in the dashboard — from genuinely
captured data, not a canned demo.

### Useful flags
```bash
python3 backend_server.py --interval 1.5 --retention 180 --port 5000
```
- `--interval` — seconds between capture cycles
- `--retention` — seconds of connection history kept in the rolling window
- `--mode simulated` — old behavior: generates one fake network snapshot
  (via `network_simulator.py`) and serves that instead of live capture;
  useful for an offline demo with no real traffic required

## 3. Open the dashboard
Open `dashboard.html` in your browser (double-click it, or serve it with
`python3 -m http.server` from this folder). It talks to
`http://localhost:5000` by default — change that in Settings if you're
running the backend elsewhere.

If the backend isn't reachable, the dashboard shows a circular demo
topology (clearly labeled "Demo preview") instead of blank panels — real
alerts/policies still correctly show empty states until the backend is
actually running.

## False positives (fan-out) and the allowlist

Real traffic naturally fans out to lots of destinations (CDNs, updates,
etc.) — on its own that's not suspicious. Two things keep this from
flooding you with noise:

- **Baseline learning**: for the first 60s (`--baseline-seconds`), the
  backend watches traffic without alerting on fan-out, building each
  device's "normal destinations" list. After that, only genuinely *new*
  destinations count toward the threshold.
- **`Scan input/allowlist.json`**: list any IPs/CIDRs/ports you already
  know are fine (your DNS server, an internal update server, etc.) —
  they're excluded from every rule, not just fan-out. Empty by default.

## History, trends, and the on-chain audit trail

The dashboard's **History** tab shows a connections/alerts trend chart
and a table of recurring alert patterns (first seen / last seen /
occurrence count) — all backed by the SQLite DB, so it survives restarts.

Below that is an **on-chain audit trail**: click "Anchor now" to hash
the current alerts/policies history and write that hash on-chain as a
tamper-evident checkpoint. By default this uses a local in-process test
chain (zero setup, but ephemeral — resets each restart). To make it a
real, permanent, publicly-verifiable audit trail:

```bash
export WEB3_RPC_URL="https://<your-testnet-rpc-url>"       # e.g. Polygon Amoy or Sepolia
export WEB3_PRIVATE_KEY="<a testnet wallet's private key>"  # get free funds from a faucet
python3 backend_server.py
```
The first anchor on a real chain deploys the contract and prints its
address — save it and set `AUDIT_CONTRACT_ADDRESS` next time to reuse
it instead of redeploying (deploying costs a little gas).
