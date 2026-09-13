const hre = require("hardhat");

async function main() {
  const approverAddress = process.env.APPROVER_ADDRESS;
  if (!approverAddress) {
    throw new Error(
      "APPROVER_ADDRESS is not set. Add it to your .env file (see .env.example)."
    );
  }

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Network:", hre.network.name);
  console.log("Authorized approver:", approverAddress);

  const Registry = await hre.ethers.getContractFactory("SecurityPolicyRegistry");
  const registry = await Registry.deploy(approverAddress);
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const deployTx = registry.deploymentTransaction();

  console.log("\n=== DEPLOYMENT RESULT ===");
  console.log("Contract address:", address);
  console.log("Deployment tx hash:", deployTx.hash);
  console.log("Network:", hre.network.name);
  console.log("Timestamp:", new Date().toISOString());
  console.log("=========================\n");
  console.log(
    `Verify on MSTScan (once confirmed): https://testnet.mstscan.com/address/${address}`
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
