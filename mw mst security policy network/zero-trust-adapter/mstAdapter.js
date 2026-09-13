const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
const { canonicalize } = require("../backend/src/canonicalize");

const artifact = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "artifacts", "contracts", "SecurityPolicyRegistryV2.sol", "SecurityPolicyRegistryV2.json"),
  "utf8"
));

class MSTPolicyVerifier {
  constructor({ rpcUrl, contractAddress }) {
    if (!rpcUrl || !contractAddress) throw new Error("rpcUrl and contractAddress are required");
    this.provider = new ethers.JsonRpcProvider(rpcUrl);
    this.contract = new ethers.Contract(contractAddress, artifact.abi, this.provider);
  }

  async get_policy(policyId) {
    const [creator, currentVersion, policy, effectiveStatus] = await this.contract.getPolicy(policyId);
    return {
      policyId,
      creator,
      currentVersion: Number(currentVersion),
      policyHash: policy.policyHash,
      risk: ["LOW", "MEDIUM", "HIGH", "CRITICAL"][Number(policy.risk)],
      requiredApprovals: Number(policy.requiredApprovals),
      approvalCount: Number(policy.approvalCount),
      storedStatus: ["NONE", "PROPOSED", "ACTIVE", "REJECTED", "REVOKED", "EXPIRED"][Number(policy.status)],
      effectiveStatus: ["NONE", "PROPOSED", "ACTIVE", "REJECTED", "REVOKED", "EXPIRED"][Number(effectiveStatus)],
      expiresAt: Number(policy.expiresAt),
    };
  }

  async verify_policy(policyId, payload) {
    const policy = await this.get_policy(policyId);
    const expectedHash = ethers.id(canonicalize(payload));
    return {
      policyId,
      matches: policy.policyHash.toLowerCase() === expectedHash.toLowerCase(),
      expectedHash,
      onChainHash: policy.policyHash,
      effectiveStatus: policy.effectiveStatus,
    };
  }

  async is_authorized(policyId) {
    return this.contract.isAuthorized(policyId);
  }
}

module.exports = { MSTPolicyVerifier };
