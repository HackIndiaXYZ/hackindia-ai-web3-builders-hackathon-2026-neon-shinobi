const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("SecurityPolicyRegistryV2", function () {
  let registry;
  let deployer;
  let securityApprover;
  let networkApprover;
  let other;

  beforeEach(async function () {
    [deployer, securityApprover, networkApprover, other] = await ethers.getSigners();
    const Registry = await ethers.getContractFactory("SecurityPolicyRegistryV2");
    registry = await Registry.deploy(securityApprover.address, networkApprover.address);
    await registry.waitForDeployment();
  });

  function ids(seed) {
    return {
      policyId: ethers.id(`v2-policy-${seed}`),
      policyHash: ethers.id(`v2-hash-${seed}`),
    };
  }

  async function propose(seed, risk = 0, expiresAt = 0, proposer = deployer) {
    const values = ids(seed);
    await registry.connect(proposer).proposePolicy(values.policyId, values.policyHash, risk, expiresAt);
    return values;
  }

  it("stores distinct approver roles", async function () {
    expect(await registry.securityApprover()).to.equal(securityApprover.address);
    expect(await registry.networkApprover()).to.equal(networkApprover.address);
  });

  it("rejects a single wallet for both approver roles", async function () {
    const Registry = await ethers.getContractFactory("SecurityPolicyRegistryV2");
    await expect(Registry.deploy(securityApprover.address, securityApprover.address))
      .to.be.revertedWithCustomError(Registry, "ApproversMustBeDistinct");
  });

  it("requires the security approver for low, medium, and high risk", async function () {
    const { policyId } = await propose("low", 0);
    await expect(registry.connect(networkApprover).approvePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "ApprovalNotRequired");
    await registry.connect(securityApprover).approvePolicy(policyId);
    expect(await registry.isAuthorized(policyId)).to.equal(true);
  });

  it("requires both distinct roles for critical risk", async function () {
    const { policyId } = await propose("critical", 3);
    await registry.connect(securityApprover).approvePolicy(policyId);
    let current = await registry.getPolicy(policyId);
    expect(current.effectiveStatus).to.equal(1); // PROPOSED
    expect(current.policy.approvalCount).to.equal(1);

    await registry.connect(networkApprover).approvePolicy(policyId);
    current = await registry.getPolicy(policyId);
    expect(current.effectiveStatus).to.equal(2); // ACTIVE
    expect(current.policy.approvalCount).to.equal(2);
    expect(await registry.hasApproved(policyId, 1, securityApprover.address)).to.equal(true);
    expect(await registry.hasApproved(policyId, 1, networkApprover.address)).to.equal(true);
  });

  it("blocks duplicate approvals and unauthorized approvers", async function () {
    const { policyId } = await propose("duplicate", 3);
    await expect(registry.connect(other).approvePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "NotAuthorizedRole");
    await registry.connect(securityApprover).approvePolicy(policyId);
    await expect(registry.connect(securityApprover).approvePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "AlreadyApproved");
  });

  it("rejects a proposed policy and makes rejection terminal", async function () {
    const { policyId } = await propose("reject", 1);
    await registry.connect(networkApprover).rejectPolicy(policyId);
    expect((await registry.getPolicy(policyId)).effectiveStatus).to.equal(3); // REJECTED
    await expect(registry.connect(securityApprover).approvePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "InvalidTransition");
    await expect(registry.connect(networkApprover).rejectPolicy(policyId))
      .to.be.revertedWithCustomError(registry, "InvalidTransition");
  });

  it("revokes an active policy and makes revocation terminal", async function () {
    const { policyId } = await propose("revoke", 2);
    await registry.connect(securityApprover).approvePolicy(policyId);
    await registry.connect(networkApprover).revokePolicy(policyId);
    expect((await registry.getPolicy(policyId)).effectiveStatus).to.equal(4); // REVOKED
    expect(await registry.isAuthorized(policyId)).to.equal(false);
    await expect(registry.connect(securityApprover).revokePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "InvalidTransition");
  });

  it("computes expiry without storing EXPIRED", async function () {
    const expiresAt = (await time.latest()) + 100;
    const { policyId } = await propose("expiry", 0, expiresAt);
    await registry.connect(securityApprover).approvePolicy(policyId);
    await time.increaseTo(expiresAt);
    expect((await registry.getPolicy(policyId)).effectiveStatus).to.equal(2); // ACTIVE at the boundary
    await time.increaseTo(expiresAt + 1);
    const current = await registry.getPolicy(policyId);
    expect(current.policy.status).to.equal(2); // stored ACTIVE
    expect(current.effectiveStatus).to.equal(5); // computed EXPIRED
    expect(await registry.isAuthorized(policyId)).to.equal(false);
  });

  it("preserves every version when a creator revises a policy", async function () {
    const first = await propose("revision", 0);
    await registry.connect(deployer).revisePolicy(first.policyId, ethers.id("revision-2"), 3, 0);
    const current = await registry.getPolicy(first.policyId);
    expect(current.currentVersion).to.equal(2);
    expect(current.effectiveStatus).to.equal(1); // new version is PROPOSED

    const oldVersion = await registry.getPolicyVersion(first.policyId, 1);
    expect(oldVersion.policy.policyHash).to.equal(first.policyHash);
    expect(oldVersion.policy.status).to.equal(1); // original remains PROPOSED

    await registry.connect(securityApprover).approvePolicy(first.policyId);
    await registry.connect(networkApprover).approvePolicy(first.policyId);
    expect(await registry.isAuthorized(first.policyId)).to.equal(true);
  });

  it("rejects revisions by non-creators and revisions after terminal states", async function () {
    const { policyId } = await propose("revision-auth", 0);
    await expect(registry.connect(other).revisePolicy(policyId, ethers.id("bad"), 0, 0))
      .to.be.revertedWithCustomError(registry, "NotPolicyCreator");
    await registry.connect(securityApprover).rejectPolicy(policyId);
    await expect(registry.revisePolicy(policyId, ethers.id("bad-2"), 0, 0))
      .to.be.revertedWithCustomError(registry, "InvalidTransition");
  });

  it("rejects invalid roles and missing policies across transitions", async function () {
    const missing = ethers.id("missing-v2");
    await expect(registry.getEffectiveStatus(missing))
      .to.be.revertedWithCustomError(registry, "PolicyDoesNotExist");
    const { policyId } = await propose("invalid-role", 0);
    await expect(registry.connect(other).rejectPolicy(policyId))
      .to.be.revertedWithCustomError(registry, "NotAuthorizedRole");
    await expect(registry.connect(other).revokePolicy(policyId))
      .to.be.revertedWithCustomError(registry, "NotAuthorizedRole");
  });
});
