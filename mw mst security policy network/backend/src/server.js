require("dotenv").config();
const express = require("express");
const cors = require("cors");
const {
  contractAsProposer,
  contractAsApprover,
  contractReadOnly,
  hashPolicyPayload,
  newPolicyId,
  CONTRACT_ADDRESS,
} = require("./chain");
const store = require("./store");
const chainV2 = require("./chainV2");

const app = express();
app.use(cors());
app.use(express.json());

// On-chain Status enum from the contract: 0=NONE, 1=PROPOSED, 2=APPROVED
const STATUS_LABELS = ["NONE", "PROPOSED", "APPROVED"];

/**
 * POST /policies
 * Body: { sourceSegment, destSegment, protocol, port, action, risk, reason, createdBy }
 * Proposes the policy on-chain (hash only) and stores the full payload off-chain.
 */
app.post("/policies", async (req, res) => {
  try {
    const payload = req.body;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      return res.status(400).json({ error: "Request body must be a JSON object describing the policy." });
    }

    const requiredFields = ["sourceSegment", "destSegment", "protocol", "port", "action", "risk"];
    const missing = requiredFields.filter((f) => payload[f] === undefined || payload[f] === null || payload[f] === "");
    if (missing.length > 0) {
      return res.status(400).json({ error: `Missing required fields: ${missing.join(", ")}` });
    }

    const policyId = newPolicyId();
    const policyHash = hashPolicyPayload(payload);

    const tx = await contractAsProposer.proposePolicy(policyId, policyHash);
    const receipt = await tx.wait();

    store.savePolicy(policyId, {
      payload,
      policyHash,
      proposeTx: receipt.hash,
      approveTx: null,
      createdAt: new Date().toISOString(),
    });

    return res.status(201).json({
      policyId,
      policyHash,
      proposeTx: receipt.hash,
      status: "PROPOSED",
      contract: CONTRACT_ADDRESS,
    });
  } catch (err) {
    return handleChainError(res, err);
  }
});

function v2Payload(req) {
  const payload = req.body;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Request body must be a JSON object describing the policy.");
  }
  const requiredFields = ["sourceSegment", "destSegment", "protocol", "port", "action", "risk"];
  const missing = requiredFields.filter((field) => payload[field] === undefined || payload[field] === null || payload[field] === "");
  if (missing.length > 0) throw new Error(`Missing required fields: ${missing.join(", ")}`);
  return payload;
}

function v2VersionView(version) {
  return {
    policyHash: version[0],
    risk: ["LOW", "MEDIUM", "HIGH", "CRITICAL"][Number(version[1])],
    requiredApprovals: Number(version[2]),
    approvalCount: Number(version[3]),
    storedStatus: chainV2.statusLabel(version[4]),
    effectiveStatus: chainV2.statusLabel(version[5]),
    proposedAt: Number(version[6]),
    activatedAt: Number(version[7]),
    rejectedAt: Number(version[8]),
    revokedAt: Number(version[9]),
    expiresAt: Number(version[10]),
  };
}

async function v2Detail(ctx, policyId, versionNumber) {
  const record = store.getPolicy(policyId);
  if (!record || record.protocolVersion !== 2) return null;
  const current = await ctx.readOnly.getPolicy(policyId);
  const version = versionNumber
    ? await ctx.readOnly.getPolicyVersion(policyId, versionNumber)
    : [current[2], current[3]];
  return {
    policyId,
    creator: current[0],
    currentVersion: Number(current[1]),
    version: versionNumber ? Number(versionNumber) : Number(current[1]),
    payload: record.payload,
    onChain: v2VersionView([version[0][0], version[0][1], version[0][2], version[0][3], version[0][4], version[1], version[0][5], version[0][6], version[0][7], version[0][8], version[0][9]]),
    integrityCheck: version[0][0].toLowerCase() === record.policyHash.toLowerCase() ? "PASS" : "FAIL",
    proposeTx: record.proposeTx,
    securityApproveTx: record.securityApproveTx || null,
    networkApproveTx: record.networkApproveTx || null,
    rejectTx: record.rejectTx || null,
    revokeTx: record.revokeTx || null,
    contract: ctx.address,
  };
}

app.post("/v2/policies", async (req, res) => {
  try {
    const payload = v2Payload(req);
    const ctx = chainV2.buildContext();
    const policyId = chainV2.newPolicyId();
    const policyHash = chainV2.hashPolicyPayload(payload);
    const tx = await ctx.proposer.proposePolicy(policyId, policyHash, chainV2.riskValue(payload.risk), Number(payload.expiresAt || 0));
    const receipt = await tx.wait();
    store.savePolicy(policyId, { protocolVersion: 2, payload, policyHash, version: 1, proposeTx: receipt.hash, createdAt: new Date().toISOString() });
    return res.status(201).json({ policyId, policyHash, version: 1, proposeTx: receipt.hash, status: "PROPOSED", contract: ctx.address });
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.get("/v2/policies", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    const records = store.listPolicies().filter((policy) => policy.protocolVersion === 2);
    const details = await Promise.all(records.map(async (record) => {
      try {
        return await v2Detail(ctx, record.policyId);
      } catch (err) {
        if (err.code === "CALL_EXCEPTION") return null;
        throw err;
      }
    }));
    return res.json(details.filter(Boolean));
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.get("/v2/policies/:id", async (req, res) => {
  try {
    const detail = await v2Detail(chainV2.buildContext(), req.params.id);
    return detail ? res.json(detail) : res.status(404).json({ error: "Unknown V2 policyId." });
  } catch (err) {
    if (err.code === "CALL_EXCEPTION") return res.status(404).json({ error: "Policy is not present on the active V2 contract." });
    return handleChainError(res, err);
  }
});

app.get("/v2/policies/:id/version/:version", async (req, res) => {
  try {
    const detail = await v2Detail(chainV2.buildContext(), req.params.id, req.params.version);
    return detail ? res.json(detail) : res.status(404).json({ error: "Unknown V2 policyId." });
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.get("/v2/authorized/:id", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    return res.json({ policyId: req.params.id, authorized: await ctx.readOnly.isAuthorized(req.params.id), contract: ctx.address });
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.post("/v2/policies/:id/approve", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    const tx = await ctx.security.approvePolicy(req.params.id);
    const receipt = await tx.wait();
    store.savePolicy(req.params.id, { securityApproveTx: receipt.hash });
    return res.json(await v2Detail(ctx, req.params.id));
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.post("/v2/policies/:id/network-approve", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    if (!ctx.network) throw new Error("NETWORK_APPROVER_PRIVATE_KEY is required for network approval.");
    const tx = await ctx.network.approvePolicy(req.params.id);
    const receipt = await tx.wait();
    store.savePolicy(req.params.id, { networkApproveTx: receipt.hash });
    return res.json(await v2Detail(ctx, req.params.id));
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.post("/v2/policies/:id/reject", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    const tx = await ctx.security.rejectPolicy(req.params.id);
    const receipt = await tx.wait();
    store.savePolicy(req.params.id, { rejectTx: receipt.hash });
    return res.json(await v2Detail(ctx, req.params.id));
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.post("/v2/policies/:id/revoke", async (req, res) => {
  try {
    const ctx = chainV2.buildContext();
    const tx = await ctx.security.revokePolicy(req.params.id);
    const receipt = await tx.wait();
    store.savePolicy(req.params.id, { revokeTx: receipt.hash });
    return res.json(await v2Detail(ctx, req.params.id));
  } catch (err) {
    return handleChainError(res, err);
  }
});

app.post("/v2/policies/:id/revise", async (req, res) => {
  try {
    const payload = v2Payload(req);
    const ctx = chainV2.buildContext();
    const policyHash = chainV2.hashPolicyPayload(payload);
    const tx = await ctx.proposer.revisePolicy(req.params.id, policyHash, chainV2.riskValue(payload.risk), Number(payload.expiresAt || 0));
    const receipt = await tx.wait();
    const current = await ctx.readOnly.getPolicy(req.params.id);
    store.savePolicy(req.params.id, { payload, policyHash, version: Number(current[1]), proposeTx: receipt.hash, securityApproveTx: null, networkApproveTx: null, rejectTx: null, revokeTx: null, revisedAt: new Date().toISOString() });
    return res.json(await v2Detail(ctx, req.params.id));
  } catch (err) {
    return handleChainError(res, err);
  }
});

/**
 * POST /policies/:id/approve
 * Calls approvePolicy() using the designated approver signer.
 */
app.post("/policies/:id/approve", async (req, res) => {
  try {
    const policyId = req.params.id;
    const existing = store.getPolicy(policyId);
    if (!existing) {
      return res.status(404).json({ error: "Unknown policyId (not proposed via this backend)." });
    }

    const tx = await contractAsApprover.approvePolicy(policyId);
    const receipt = await tx.wait();

    store.savePolicy(policyId, { approveTx: receipt.hash, approvedAt: new Date().toISOString() });

    return res.json({
      policyId,
      approveTx: receipt.hash,
      status: "APPROVED",
      contract: CONTRACT_ADDRESS,
    });
  } catch (err) {
    return handleChainError(res, err);
  }
});

/**
 * GET /policies/:id
 * Reads on-chain state, cross-checks it against the off-chain payload hash.
 */
app.get("/policies/:id", async (req, res) => {
  try {
    const policyId = req.params.id;
    const offChain = store.getPolicy(policyId);
    if (!offChain) {
      return res.status(404).json({ error: "Unknown policyId (not proposed via this backend)." });
    }

    const onChain = await contractReadOnly.getPolicy(policyId);
    const [creator, approver, policyHash, status, proposedAt, approvedAt] = onChain;

    const hashMatches = policyHash.toLowerCase() === offChain.policyHash.toLowerCase();

    return res.json({
      policyId,
      offChainPayload: offChain.payload,
      onChain: {
        creator,
        approver,
        policyHash,
        status: STATUS_LABELS[Number(status)],
        proposedAt: Number(proposedAt),
        approvedAt: Number(approvedAt),
      },
      integrityCheck: hashMatches ? "PASS" : "FAIL",
      proposeTx: offChain.proposeTx,
      approveTx: offChain.approveTx,
      contract: CONTRACT_ADDRESS,
    });
  } catch (err) {
    return handleChainError(res, err);
  }
});

/** GET /policies — list everything this backend knows about (off-chain index). */
app.get("/policies", (req, res) => {
  return res.json(store.listPolicies());
});

app.get("/health", (req, res) => res.json({ ok: true, contract: CONTRACT_ADDRESS }));

function handleChainError(res, err) {
  console.error(err);
  const message = err.shortMessage || err.reason || err.message || "Unknown error";
  return res.status(500).json({ error: message });
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`MST Security Policy backend listening on http://localhost:${PORT}`);
  console.log(`Contract: ${CONTRACT_ADDRESS}`);
});
