# MST Security Policy Network

**"AI detects. AI proposes. MST authorizes. Zero Trust enforces."**

A decentralized security-policy coordination and authorization network, built on MST Blockchain for the AI & Web3 Builders Hackathon. Independently operated security systems — a Zero Trust engine, a SIEM, a firewall, an AI agent — can use MST as a shared, verifiable source of truth for which security policies are actually authorized, without any of them needing to trust each other's databases.

## Key Features

- **Full policy lifecycle on-chain** — `PROPOSED → ACTIVE`, with terminal `REJECTED` and `REVOKED` states, plus computed `EXPIRED`. Approval events and counts explain how a policy became active. Invalid transitions (e.g. re-approving a revoked policy) are rejected by the contract itself, not just the UI.
- **Risk-based multi-party authorization** — LOW/MEDIUM/HIGH policies need one qualifying approver; CRITICAL policies require **two distinct, real addresses** (`securityApprover` and `networkApprover`) to both sign off. No single party can authorize the most dangerous changes alone.
- **`isAuthorized()` — the verification gate** — a single on-chain function any external system calls before enforcing a policy. This is the literal code embodiment of "MST authorizes, Zero Trust enforces": it returns `true` only if the policy is `ACTIVE`, not revoked, and not expired.
- **Policy versioning** — every revision to a policy appends a new version rather than overwriting history, so full lineage is queryable and nothing is silently lost.
- **Time-boxed policies** — an `expiresAt` timestamp lets a policy (e.g. an emergency 30-minute isolation) become unauthorized automatically once time passes, computed at read-time rather than requiring a separate expiry transaction.
- **Tamper-evident off-chain data** — the full policy payload (reason, risk explanation) stays off-chain; only a `keccak256` hash commitment lives on-chain, so any tampering with the off-chain copy is immediately detectable.
- **An AI agent that can propose but never approve** — enforced by the absence of an approve-capable code path in the agent, not by convention. A human must always authorize through the dashboard.
- **Independently verifiable, not just "on a blockchain"** — every proposal, approval, and revocation is a real MST Testnet transaction, checkable by anyone on MSTScan without asking our backend's permission.

## Screenshots

### MST 1

![MST 1 dashboard](screenshots/mst%201.png)

### MST 2

![MST 2 dashboard](screenshots/mst%202.png)

## Problem

Security teams routinely need to authorize network policy changes (e.g. "block Guest network from reaching the Finance database"). Today, that authorization typically lives in a database row: whoever has write access can silently change who approved what, when, or whether it was approved at all. There's no independently verifiable record of *who actually authorized a given security policy*, and no way for a third-party system (or an auditor, or another security tool) to verify that authorization without trusting the database operator.

## Solution

MST Security Policy Network lets security policies be **proposed, authorized, and verified** through an on-chain smart contract, while keeping the operational detail of the policy off-chain. Anyone — a judge, an auditor, another security product — can independently verify on MST's public block explorer that a specific policy was proposed by a specific address and approved by a specific authorized approver, at a specific time, with no need to trust our backend or database.

An AI Security Policy Agent observes simulated network events, reasons about which ones represent a real security risk, and proposes policies automatically — but it is architecturally incapable of approving its own proposals. Approval is a human action, taken through a dashboard, which is the authorization boundary of the whole system.

## Why Blockchain?

Applying the necessity test directly:

| Question | Answer |
|---|---|
| Why not just a database? | A database's audit log is only as trustworthy as whoever controls the database. It can be edited retroactively with no external way to detect it. |
| What must be independently verifiable? | *Who* proposed a policy, *who* approved it, and *when* — without needing to trust our backend. |
| Who doesn't fully trust whom? | A security team, an auditor, and any downstream system (like a Zero Trust platform) consuming the policy shouldn't have to take our backend's word for its own authorization history. |
| What's tamper-evident? | The policy's identity, status, and a hash commitment to its full content. |
| What stays off-chain? | The actual policy detail (reason, risk explanation) and all high-volume operational telemetry — never put on a public chain. |

We do **not** put raw network traffic, logs, or credentials on-chain — only the policy identity, its lifecycle status, and a `keccak256` hash commitment to the full off-chain payload, so tampering with the off-chain copy is detectable.

**The removal test:** if MST were removed from this system, everything upstream still works — traffic can still be observed, risk can still be analyzed, an AI agent can still generate a proposal. What becomes impossible is the *claim* that a policy is currently authorized meaning anything to a party who doesn't trust our backend. Without MST, a compromised or dishonest operator could quietly re-activate a revoked policy, let an expired emergency rule keep firing, or claim a single approval satisfied a two-party requirement — and nothing outside our own database would catch it. `isAuthorized()` (see Smart Contract, below) is the specific function that closes that gap: any external system can call it directly and get an answer that doesn't depend on trusting us.

## Why MST?

MST Blockchain is EVM-compatible (confirmed via its official Python/JS SDKs, both built on `web3.py`/`ethers.js`-equivalent patterns), giving us standard Solidity contracts, standard wallet signing, and a public testnet explorer (MSTScan) for independent verification — exactly the properties this problem needs.

## Architecture

```
┌─────────────────────┐
│  Security Policy      │   rule-based reasoning over
│  Agent (agent/)       │   observed security events
└──────────┬───────────┘
           │ POST /policies (propose only — never approves)
           ▼
┌─────────────────────┐        ┌──────────────────────┐
│  Backend API          │◄──────►│  Off-chain store       │
│  (backend/)           │        │  (policy payload +     │
│  Express + ethers.js   │        │   tx history)          │
└──────────┬───────────┘        └──────────────────────┘
           │ ethers.js
           ▼
┌─────────────────────┐
│  SecurityPolicyRegistry│   V1: propose → approve → read (Milestone 1 proof)
│  V1 & V2 (contracts/)  │   V2: full lifecycle, multi-party approval,
│                        │       versioning, expiration, isAuthorized()
└──────────┬───────────┘
           │
           ▼
    MST Testnet (Chain ID 91562037)
           │
           ▼
     MSTScan (public, independent verification)

┌─────────────────────┐        ┌──────────────────────┐
│  Dashboard (frontend/) │       │  Zero Trust adapter    │
│  human approval step,  │       │  calls                  │
│  the authorization     │       │  isAuthorized() before  │
│  boundary               │       │  enforcing anything     │
└─────────────────────┘        └──────────────────────┘
```

## Smart Contract

Two contracts exist, deliberately: the original is kept deployed and untouched as historical proof, and the second is the real production design.

### V1 — `contracts/SecurityPolicyRegistry.sol` (Milestone 1 proof, kept as-is)

- **State:** one `Policy` struct per `policyId` — creator, approver, `policyHash` commitment, status, timestamps.
- **Functions:** `proposePolicy`, `approvePolicy`, `getPolicy` (read-only).
- **Permissions:** anyone can propose; a single `authorizedApprover` address can approve.
- Deliberately minimal — proved the core propose→approve→verify loop before anything more complex was built on top of it.

### V2 — `contracts/SecurityPolicyRegistryV2.sol` (current design)

- **Lifecycle:** `PROPOSED → ACTIVE`, with terminal `REJECTED` and `REVOKED`, plus a *computed* `EXPIRED` condition (see below). Every invalid transition (e.g. approving an already-active policy, re-approving a rejected one) reverts with a specific custom error — enforced by the contract, not just by the UI choosing not to show the button.
- **Risk-based multi-party approval:** LOW/MEDIUM/HIGH require one approval; CRITICAL requires two. Two named roles, `securityApprover` and `networkApprover`, are set at deploy time as **distinct real addresses** — the constructor itself rejects a deploy where they're the same address, specifically because that would make CRITICAL policies permanently unreachable. Each address can only count once per policy (`hasApproved` mapping), so a single signer can't satisfy a 2-approval requirement alone.
- **`isAuthorized(policyId)` — the verification gate:** returns `true` only if `status == ACTIVE`, not revoked, and (`expiresAt == 0` or `now <= expiresAt`). This is the one function an external system like a Zero Trust engine should call before enforcing anything.
- **Why expiration is computed, not stored:** nothing on a blockchain spontaneously notices a clock ticking — a stored `EXPIRED` status would need someone to remember to submit a transaction the instant expiry hits, which is unreliable and adds gas cost for no real benefit. Instead, `isAuthorized()` and `getPolicy()` compute "expired" live from `block.timestamp` on every read, so it's always accurate with zero extra transactions.
- **Versioning:** each policy keeps an append-only `PolicyVersion[]` array. `revisePolicy()` adds a new version (updating the current hash/risk) without erasing history — `getPolicyVersion(id, index)` reads any historical version directly.
- **Events:** `PolicyProposed`, `PolicyApproved`, `PolicyActivated`, `PolicyRejected`, `PolicyRevoked`, `PolicyRevised` — a complete, independently reconstructible audit trail with no reliance on our backend's database.
- **Why each piece is on-chain:** identity, authorization state, and the approval count all need to be tamper-evident and checkable by parties who don't trust each other or our backend. The policy hash proves the off-chain payload wasn't altered, without putting operational detail on a public chain.

## AI Agent

`agent/policyAgent.js` implements a simplified version of the OBSERVE → ANALYZE → REASON → PLAN → PROPOSE loop:

- Reads simulated security events (`agent/events.sample.json`) representing what a Zero Trust platform would detect.
- `agent/rules.js` is a small, deliberately readable rule engine: untrusted segments (Guest, IoT) reaching sensitive segments (Finance, HR, Corporate) on sensitive ports (3306, 5432, 22, 3389) trigger a DENY proposal with an explained rationale.
- Submits proposals through the real backend API — every proposal is a real on-chain transaction.
- **The agent's code contains no function capable of calling the approve endpoint.** This is an enforced boundary, not a convention: autonomous approval was deliberately excluded so a human must authorize every policy through the dashboard.

## MCP Integration

The official MST-MCP server (`mcp-client/`) is a **read-only documentation lookup service** — three tools: `list_documents`, `read_document`, `search_documents`. It has no transaction or signing capability. We use it as a live documentation reference (e.g. to confirm the testnet Chain ID and SDK details directly from source), not as a blockchain execution path. This scope was deliberately kept narrow to avoid overclaiming what MCP provides.

## MST Testnet Deployment

- **Network:** MST Testnet, Chain ID `91562037`
- **RPC:** `https://testnetrpc.mstblockchain.com`
- **V1 contract (current configured deployment):** `0x4aBF5E8369CF5502e0aEA5a22cF4bc930094E502`
- **V2 contract (current deployment):** `0xD28473e28C3BF7A6Be90C6Be529870aE5A48C1a4`

## Example Transactions

**V1 — Milestone 1 proof:**
- Policy ID: `0x3bd3bf685fcbf6fcd7af62f43d67d81394f13c43c7d12372c0bf715ebf549fc`
- Propose tx: `0xc628d0a4cd98e36edcb09911cc2798eaad5b2c4f4020c268a9a2e36fcf2fc862`
- Approve tx: `0xafbdbbfc6aef7128892d023f0598ed15deac1a035481a72a56b19d62fdab1aea`
- Integrity check: PASS (on-chain hash matches off-chain payload)

**V2 — full lifecycle proof:**
- The contract test suite covers propose, 2-of-2 approval, active authorization, expiration, revision, rejection, and revocation. A live proof can be run through the backend endpoints below after the wallets are funded.

## MSTScan Verification

- V1 contract: `https://testnet.mstscan.com/address/0x4aBF5E8369CF5502e0aEA5a22cF4bc930094E502`
- Historical V1 proof contract: `https://testnet.mstscan.com/address/0xCB4Ae175C8F95Bac34C21a14fd2A2AaacBe2e4C2`
- V1 approve tx: `https://testnet.mstscan.com/tx/0xafbdbbfc6aef7128892d023f0598ed15deac1a035481a72a56b19d62fdab1aea`
- V2 contract: `https://testnet.mstscan.com/address/0xD28473e28C3BF7A6Be90C6Be529870aE5A48C1a4`

## Local Setup

```bash
git clone <your-repo-url>
cd mst-security-policy-network
npm install
```

## Environment Variables

Each sub-project has its own `.env.example`. Copy each to `.env` and fill in real values — **never commit `.env` files**:

- `/.env.example` — Hardhat deploy key + authorized approver address
- `/backend/.env.example` — RPC URL, contract address, proposer/approver keys
- `/mcp-client/.env.example` — MST-MCP OAuth credentials

All private keys used are **testnet-only**, funded via `https://faucet.mstblockchain.com`, holding no real value.

For V2, keep private keys in `backend/.env` only:

```env
PROPOSER_PRIVATE_KEY=0x...
SECURITY_APPROVER_PRIVATE_KEY=0x...
NETWORK_APPROVER_PRIVATE_KEY=0x...
```

The corresponding public addresses go in the root `.env` as `SECURITY_APPROVER_ADDRESS` and `NETWORK_APPROVER_ADDRESS`. The security and network wallets must both be funded before they can sign approvals. Never paste private keys into chat or commit them to Git.

## Running the Backend

```bash
cd backend
npm install
cp .env.example .env   # fill in values
npm start              # http://localhost:4000
```

## Running the Frontend

```bash
cd frontend
npx serve -l 8080      # http://localhost:8080
```

Requires the backend running on `localhost:4000`.

## Running the AI Agent

```bash
cd agent
BACKEND_URL=http://localhost:4000 node policyAgent.js
```

## Running the V2 Deployment

V2 requires **two distinct approver addresses** — `securityApprover` and `networkApprover` — since CRITICAL-risk policies need both to sign. Generate a second real keypair locally if you don't already have one:

```bash
node -e '
const { ethers } = require("ethers");
const w = ethers.Wallet.createRandom();
console.log("Address:", w.address);
console.log("Private key:", w.privateKey);
'
```

Fund the new wallet with a small amount of tMSTC from `https://faucet.mstblockchain.com`, then add the address to your root `.env` and the private key to `backend/.env`:
```
SECURITY_APPROVER_ADDRESS=0x...   # your existing address
NETWORK_APPROVER_ADDRESS=0x...    # the new second address
```

In `backend/.env`:
```
SECURITY_APPROVER_PRIVATE_KEY=0x...
NETWORK_APPROVER_PRIVATE_KEY=0x...
```

Deploy:
```bash
npx hardhat run scripts/deployV2.js --network mstTestnet
```

After deployment, set `CONTRACT_V2_ADDRESS` in `backend/.env` to the printed contract address and use the V2 API endpoints to propose, approve, verify, and revoke policies.

## Testing

```bash
npx hardhat test
```

**V1 suite:** 7 tests — approver storage at deploy, propose access, duplicate-proposal rejection, approver-only enforcement, approve-nonexistent rejection, double-approval rejection, read-nonexistent rejection. All passing.

**V2 suite** (`test/SecurityPolicyRegistryV2.test.js`): covers deployment role storage, proposal, risk-based approval thresholds (1-of-1 and 2-of-2), duplicate-approval rejection, non-approver rejection, every invalid state transition (approve-when-active, reject-when-active, revoke-when-not-active, re-approve-after-reject, re-approve-after-revoke), revocation flipping `isAuthorized`, expiration computed correctly via time-travel (`hardhat-network-helpers`), versioning and revision authorization, and reads against nonexistent policies.

## Zero Trust Integration

This project is designed to be consumed by external security platforms, including an existing Zero Trust cybersecurity system, without modifying that system's core architecture:

```
Existing Zero Trust Platform
        │  detects a cross-segment access event
        ▼
   Policy Generator (adapter, thin)
        │  translates the detection into this project's
        │  policy payload shape
        ▼
   MST Security Policy Network (this project)
     91562037     91562037     91562037     91562037        │  proposes → human approves → active on-chain
        ▼
   Zero Trust Platform consumes the authorized,
   verifiable policy back into its enforcement layer
```

This same pattern generalizes beyond one Zero Trust product — any SIEM, SOC platform, or firewall system could consume the same verifiable policy layer, giving multiple otherwise-untrusting systems a shared, independently checkable source of truth for security authorization.

## Security Considerations

- No private keys, secrets, or credentials are committed to this repository. All are supplied via `.env` files excluded by `.gitignore`.
- The smart contract stores only identity, status, approval counts/addresses, and hash commitments — never raw policy detail or sensitive operational data.
- The AI agent can propose but not approve — enforced by the absence of an approve-capable code path, not by convention alone.
- `securityApprover` and `networkApprover` must be distinct addresses — enforced at deploy time by the constructor itself, preventing an accidental single-point-of-authority deployment.
- Every state transition is validated on-chain: `REVOKED` and `REJECTED` are genuinely terminal (no code path returns from them), and double-approval by the same address is blocked by an explicit mapping check.
- BridgeKey (the ecosystem's recommended non-custodial wallet) was evaluated for the human-approval step. We confirmed, through direct testing (unlocked wallet, correct network and account, correct Chrome site-access permissions, served over `http://` rather than `file://`), that it does not currently expose a page-injectable wallet provider (no `window.ethereum`, no EIP-6963 announcement). Approvals in this demo are signed by designated backend/approver accounts instead. The architecture is ready to swap in BridgeKey, or any standard EIP-1193 wallet, the moment that support is available.

## Future Roadmap

- `mst_adapter.py` / `mstAdapter.js` — a thin Zero Trust–facing adapter exposing `get_policy()`, `verify_policy()`, `is_authorized()`, so the existing Zero Trust engine's detection code never needs to contain raw MST transaction logic
- Contract verification on MSTScan (source-code transparency)
- Real BridgeKey signing once a page-injectable provider is available
- Full autonomous OBSERVE→REASON→PLAN loop for the agent, with configurable risk tolerance
- Emergency-isolation demo scenario using the expiration mechanism end-to-end with live Zero Trust enforcement
- Multi-tenant support for additional security products (SIEM, firewall platforms) consuming the same policy layer
