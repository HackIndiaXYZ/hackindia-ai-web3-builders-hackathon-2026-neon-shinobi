const hre = require("hardhat");

async function main() {
  const securityApprover = process.env.SECURITY_APPROVER_ADDRESS || process.env.APPROVER_ADDRESS;
  const networkApprover = process.env.NETWORK_APPROVER_ADDRESS;
  if (!securityApprover || !networkApprover) {
    throw new Error("Set SECURITY_APPROVER_ADDRESS and NETWORK_APPROVER_ADDRESS in .env.");
  }
  if (securityApprover.toLowerCase() === networkApprover.toLowerCase()) {
    throw new Error("SECURITY_APPROVER_ADDRESS and NETWORK_APPROVER_ADDRESS must be distinct.");
  }

  const [deployer] = await hre.ethers.getSigners();
  const Registry = await hre.ethers.getContractFactory("SecurityPolicyRegistryV2");
  const registry = await Registry.deploy(securityApprover, networkApprover);
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("=== V2 DEPLOYMENT RESULT ===");
  console.log("Contract address:", address);
  console.log("Deployment tx hash:", registry.deploymentTransaction().hash);
  console.log("Network:", hre.network.name);
  console.log("Deployer:", deployer.address);
  console.log("Security approver:", securityApprover);
  console.log("Network approver:", networkApprover);
  console.log("============================");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
