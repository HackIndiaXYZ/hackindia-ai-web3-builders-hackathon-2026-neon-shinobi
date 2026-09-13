const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
const { canonicalize } = require("./canonicalize");

const artifactPath = path.join(__dirname, "..", "..", "artifacts", "contracts", "SecurityPolicyRegistryV2.sol", "SecurityPolicyRegistryV2.json");
const abi = JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;

const STATUS_LABELS = ["NONE", "PROPOSED", "ACTIVE", "REJECTED", "REVOKED", "EXPIRED"];
const RISK_VALUES = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}. Check backend/.env`);
  return value;
}

function config() {
  return {
    rpcUrl: required("RPC_URL"),
    address: required("CONTRACT_V2_ADDRESS"),
    proposerKey: required("PROPOSER_PRIVATE_KEY"),
    securityKey: process.env.SECURITY_APPROVER_PRIVATE_KEY || required("APPROVER_PRIVATE_KEY"),
    networkKey: process.env.NETWORK_APPROVER_PRIVATE_KEY || null,
  };
}

function buildContext() {
  const values = config();
  const provider = new ethers.JsonRpcProvider(values.rpcUrl);
  const proposer = new ethers.Wallet(values.proposerKey, provider);
  const security = new ethers.Wallet(values.securityKey, provider);
  const network = values.networkKey ? new ethers.Wallet(values.networkKey, provider) : null;
  return {
    provider,
    proposer: new ethers.Contract(values.address, abi, proposer),
    security: new ethers.Contract(values.address, abi, security),
    network: network ? new ethers.Contract(values.address, abi, network) : null,
    readOnly: new ethers.Contract(values.address, abi, provider),
    address: values.address,
  };
}

function hashPolicyPayload(payload) {
  return ethers.id(canonicalize(payload));
}

function newPolicyId() {
  return ethers.id(`policy-v2-${Date.now()}-${Math.random()}`);
}

function riskValue(risk) {
  const value = RISK_VALUES[String(risk || "").toUpperCase()];
  if (value === undefined) throw new Error("risk must be LOW, MEDIUM, HIGH, or CRITICAL");
  return value;
}

function statusLabel(value) {
  return STATUS_LABELS[Number(value)] || "UNKNOWN";
}

module.exports = {
  buildContext,
  hashPolicyPayload,
  newPolicyId,
  riskValue,
  statusLabel,
  STATUS_LABELS,
  RISK_VALUES,
};
