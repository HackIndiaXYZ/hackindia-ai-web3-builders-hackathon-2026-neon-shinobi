const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("SecurityPolicyRegistry (milestone 1)", function () {
  let registry, deployer, approver, other;

  beforeEach(async function () {
    [deployer, approver, other] = await ethers.getSigners();
    const Registry = await ethers.getContractFactory("SecurityPolicyRegistry");
    registry = await Registry.deploy(approver.address);
    await registry.waitForDeployment();
  });

  function makeIds(seed) {
    const policyId = ethers.id(`policy-${seed}`);
    const policyHash = ethers.id(`payload-${seed}`);
    return { policyId, policyHash };
  }

  it("stores the authorized approver at deployment", async function () {
    expect(await registry.authorizedApprover()).to.equal(approver.address);
  });

  it("allows anyone to propose a policy", async function () {
    const { policyId, policyHash } = makeIds("a");
    await expect(registry.connect(other).proposePolicy(policyId, policyHash))
      .to.emit(registry, "PolicyProposed")
      .withArgs(policyId, other.address, policyHash, anyValue);

    const p = await registry.getPolicy(policyId);
    expect(p.creator).to.equal(other.address);
    expect(p.status).to.equal(1); // PROPOSED
  });

  it("rejects proposing the same policyId twice", async function () {
    const { policyId, policyHash } = makeIds("b");
    await registry.proposePolicy(policyId, policyHash);
    await expect(registry.proposePolicy(policyId, policyHash)).to.be.revertedWithCustomError(
      registry,
      "PolicyAlreadyExists"
    );
  });

  it("only allows the authorized approver to approve", async function () {
    const { policyId, policyHash } = makeIds("c");
    await registry.proposePolicy(policyId, policyHash);

    await expect(registry.connect(other).approvePolicy(policyId)).to.be.revertedWithCustomError(
      registry,
      "NotAuthorizedApprover"
    );

    await expect(registry.connect(approver).approvePolicy(policyId))
      .to.emit(registry, "PolicyApproved")
      .withArgs(policyId, approver.address, anyValue);

    const p = await registry.getPolicy(policyId);
    expect(p.status).to.equal(2); // APPROVED
    expect(p.approver).to.equal(approver.address);
  });

  it("rejects approving a policy that doesn't exist", async function () {
    const { policyId } = makeIds("missing");
    await expect(registry.connect(approver).approvePolicy(policyId)).to.be.revertedWithCustomError(
      registry,
      "PolicyDoesNotExist"
    );
  });

  it("rejects double-approval", async function () {
    const { policyId, policyHash } = makeIds("d");
    await registry.proposePolicy(policyId, policyHash);
    await registry.connect(approver).approvePolicy(policyId);

    await expect(registry.connect(approver).approvePolicy(policyId)).to.be.revertedWithCustomError(
      registry,
      "PolicyNotInProposedState"
    );
  });

  it("reverts reading a policy that doesn't exist", async function () {
    const { policyId } = makeIds("ghost");
    await expect(registry.getPolicy(policyId)).to.be.revertedWithCustomError(
      registry,
      "PolicyDoesNotExist"
    );
  });
});

