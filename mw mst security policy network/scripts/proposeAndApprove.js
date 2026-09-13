const hre = require("hardhat");

// Usage: CONTRACT_ADDRESS=0x... npx hardhat run scripts/proposeAndApprove.js --network mstTestnet
async function main() {
  const contractAddress = process.env.CONTRACT_ADDRESS;
  if (!contractAddress) {
    throw new Error("Set CONTRACT_ADDRESS env var to the deployed registry address.");
  }

  const [signer] = await hre.ethers.getSigners();
  const registry = await hre.ethers.getContractAt(
    "SecurityPolicyRegistry",
    contractAddress,
    signer
  );

  // Example conceptual policy straight from the project spec:
  // Guest -> Finance, DENY, port 3306, risk HIGH, status PROPOSED
  const offChainPolicy = {
    sourceSegment: "Guest",
    destSegment: "Finance",
    protocol: "TCP",
    port: 3306,
    action: "DENY",
    risk: "HIGH",
    reason: "Guest network must not reach the Finance DB directly",
  };

  const policyId = hre.ethers.id(`policy-${Date.now()}`); // unique id per run
  const policyHash = hre.ethers.id(JSON.stringify(offChainPolicy)); // integrity commitment

  console.log("Off-chain policy payload:", offChainPolicy);
  console.log("policyId:", policyId);
  console.log("policyHash:", policyHash);

  console.log("\n--- Step 1: propose ---");
  const proposeTx = await registry.proposePolicy(policyId, policyHash);
  const proposeReceipt = await proposeTx.wait();
  console.log("Propose tx hash:", proposeReceipt.hash);

  console.log("\n--- Step 2: approve ---");
  const approveTx = await registry.approvePolicy(policyId);
  const approveReceipt = await approveTx.wait();
  console.log("Approve tx hash:", approveReceipt.hash);

  console.log("\n--- Step 3: read back and verify ---");
  const onChain = await registry.getPolicy(policyId);
  console.log("On-chain state:", {
    creator: onChain[0],
    approver: onChain[1],
    policyHash: onChain[2],
    status: onChain[3], // 2 = APPROVED
    proposedAt: onChain[4].toString(),
    approvedAt: onChain[5].toString(),
  });

  const hashMatches = onChain[2] === policyHash;
  console.log(
    `\nIntegrity check (on-chain hash matches off-chain payload): ${hashMatches ? "PASS" : "FAIL"}`
  );

  console.log("\n=== MILESTONE RECORD ===");
  console.log("Contract address:", contractAddress);
  console.log("Network:", hre.network.name);
  console.log("Policy ID:", policyId);
  console.log("Propose tx:", proposeReceipt.hash);
  console.log("Approve tx:", approveReceipt.hash);
  console.log("Wallet used:", signer.address);
  console.log("Timestamp:", new Date().toISOString());
  console.log(`View on MSTScan: https://testnet.mstscan.com/tx/${approveReceipt.hash}`);
  console.log("========================\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
