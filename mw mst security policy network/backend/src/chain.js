const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

const abi = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "abi", "SecurityPolicyRegistry.json"), "utf8")
);

const RPC_URL = process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const PROPOSER_PRIVATE_KEY = process.env.PROPOSER_PRIVATE_KEY;
const APPROVER_PRIVATE_KEY = process.env.APPROVER_PRIVATE_KEY;

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Missing required env var: ${name}. Check backend/.env`);
  }
}
requireEnv("RPC_URL", RPC_URL);
requireEnv("CONTRACT_ADDRESS", CONTRACT_ADDRESS);
requireEnv("PROPOSER_PRIVATE_KEY", PROPOSER_PRIVATE_KEY);
requireEnv("APPROVER_PRIVATE_KEY", APPROVER_PRIVATE_KEY);

const provider = new ethers.JsonRpcProvider(RPC_URL);

const proposerWallet = new ethers.Wallet(PROPOSER_PRIVATE_KEY, provider);
const approverWallet = new ethers.Wallet(APPROVER_PRIVATE_KEY, provider);

const contractAsProposer = new ethers.Contract(CONTRACT_ADDRESS, abi, proposerWallet);
const contractAsApprover = new ethers.Contract(CONTRACT_ADDRESS, abi, approverWallet);
const contractReadOnly = new ethers.Contract(CONTRACT_ADDRESS, abi, provider);

/** Deterministic on-chain hash commitment for an off-chain policy payload. */
function hashPolicyPayload(payload) {
  return ethers.id(JSON.stringify(payload));
}

/** New unique policyId (bytes32). Callers may also supply their own. */
function newPolicyId() {
  return ethers.id(`policy-${Date.now()}-${Math.random()}`);
}

module.exports = {
  provider,
  contractAsProposer,
  contractAsApprover,
  contractReadOnly,
  hashPolicyPayload,
  newPolicyId,
  CONTRACT_ADDRESS,
};
