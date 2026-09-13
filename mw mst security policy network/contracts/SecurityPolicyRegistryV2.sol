// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecurityPolicyRegistryV2
 * @notice Versioned, risk-based policy authorization for MST.
 *
 * EXPIRED is computed by getEffectiveStatus and is never written to storage.
 * This avoids a gas-paying transaction whose only purpose is observing time.
 */
contract SecurityPolicyRegistryV2 {
    enum Status {
        NONE,
        PROPOSED,
        ACTIVE,
        REJECTED,
        REVOKED,
        EXPIRED
    }

    enum Risk {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    struct PolicyVersion {
        bytes32 policyHash;
        Risk risk;
        uint256 requiredApprovals;
        uint256 approvalCount;
        Status status;
        uint256 proposedAt;
        uint256 activatedAt;
        uint256 rejectedAt;
        uint256 revokedAt;
        uint256 expiresAt;
    }

    address public immutable securityApprover;
    address public immutable networkApprover;

    mapping(bytes32 => address) private creators;
    mapping(bytes32 => PolicyVersion[]) private versions;
    mapping(bytes32 => mapping(uint256 => mapping(address => bool))) private approvals;

    event PolicyProposed(bytes32 indexed policyId, uint256 indexed version, address indexed creator, bytes32 policyHash, Risk risk, uint256 expiresAt);
    event PolicyApproved(bytes32 indexed policyId, uint256 indexed version, address indexed approver, uint256 approvalCount);
    event PolicyActivated(bytes32 indexed policyId, uint256 indexed version, uint256 timestamp);
    event PolicyRejected(bytes32 indexed policyId, uint256 indexed version, address indexed rejector, uint256 timestamp);
    event PolicyRevoked(bytes32 indexed policyId, uint256 indexed version, address indexed revoker, uint256 timestamp);
    event PolicyRevised(bytes32 indexed policyId, uint256 indexed version, bytes32 policyHash, Risk risk, uint256 expiresAt);

    error ZeroAddress();
    error ApproversMustBeDistinct();
    error PolicyDoesNotExist(bytes32 policyId);
    error PolicyAlreadyExists(bytes32 policyId);
    error InvalidVersion(bytes32 policyId, uint256 version);
    error NotAuthorizedRole(address caller);
    error NotPolicyCreator(address caller);
    error InvalidTransition(bytes32 policyId, uint256 version, Status currentStatus);
    error AlreadyApproved(bytes32 policyId, uint256 version, address approver);
    error ApprovalNotRequired(bytes32 policyId, uint256 version);

    constructor(address _securityApprover, address _networkApprover) {
        if (_securityApprover == address(0) || _networkApprover == address(0)) revert ZeroAddress();
        if (_securityApprover == _networkApprover) revert ApproversMustBeDistinct();
        securityApprover = _securityApprover;
        networkApprover = _networkApprover;
    }

    function proposePolicy(bytes32 policyId, bytes32 policyHash, Risk risk, uint256 expiresAt) external {
        if (versions[policyId].length != 0) revert PolicyAlreadyExists(policyId);
        creators[policyId] = msg.sender;
        _appendVersion(policyId, policyHash, risk, expiresAt);
    }

    function revisePolicy(bytes32 policyId, bytes32 policyHash, Risk risk, uint256 expiresAt) external {
        if (creators[policyId] == address(0)) revert PolicyDoesNotExist(policyId);
        if (msg.sender != creators[policyId]) revert NotPolicyCreator(msg.sender);
        uint256 version = versions[policyId].length;
        Status current = getEffectiveStatus(policyId);
        if (current == Status.REJECTED || current == Status.REVOKED) revert InvalidTransition(policyId, version, current);
        _appendVersion(policyId, policyHash, risk, expiresAt);
    }

    function approvePolicy(bytes32 policyId) external {
        uint256 version = _currentVersion(policyId);
        PolicyVersion storage policy = versions[policyId][version - 1];
        Status current = getEffectiveStatus(policyId);
        if (current != Status.PROPOSED) revert InvalidTransition(policyId, version, current);
        bool isSecurity = msg.sender == securityApprover;
        bool isNetwork = msg.sender == networkApprover;
        if (!isSecurity && !isNetwork) revert NotAuthorizedRole(msg.sender);
        if (policy.risk != Risk.CRITICAL && !isSecurity) revert ApprovalNotRequired(policyId, version);
        if (approvals[policyId][version][msg.sender]) revert AlreadyApproved(policyId, version, msg.sender);

        approvals[policyId][version][msg.sender] = true;
        policy.approvalCount += 1;
        emit PolicyApproved(policyId, version, msg.sender, policy.approvalCount);
        if (policy.approvalCount == policy.requiredApprovals) {
            policy.status = Status.ACTIVE;
            policy.activatedAt = block.timestamp;
            emit PolicyActivated(policyId, version, block.timestamp);
        }
    }

    function rejectPolicy(bytes32 policyId) external {
        uint256 version = _currentVersion(policyId);
        if (msg.sender != securityApprover && msg.sender != networkApprover) revert NotAuthorizedRole(msg.sender);
        PolicyVersion storage policy = versions[policyId][version - 1];
        Status current = getEffectiveStatus(policyId);
        if (current != Status.PROPOSED) revert InvalidTransition(policyId, version, current);
        policy.status = Status.REJECTED;
        policy.rejectedAt = block.timestamp;
        emit PolicyRejected(policyId, version, msg.sender, block.timestamp);
    }

    function revokePolicy(bytes32 policyId) external {
        uint256 version = _currentVersion(policyId);
        if (msg.sender != securityApprover && msg.sender != networkApprover) revert NotAuthorizedRole(msg.sender);
        PolicyVersion storage policy = versions[policyId][version - 1];
        Status current = getEffectiveStatus(policyId);
        if (current != Status.ACTIVE) revert InvalidTransition(policyId, version, current);
        policy.status = Status.REVOKED;
        policy.revokedAt = block.timestamp;
        emit PolicyRevoked(policyId, version, msg.sender, block.timestamp);
    }

    function isAuthorized(bytes32 policyId) external view returns (bool) {
        return getEffectiveStatus(policyId) == Status.ACTIVE;
    }

    function getEffectiveStatus(bytes32 policyId) public view returns (Status) {
        uint256 version = _currentVersion(policyId);
        PolicyVersion storage policy = versions[policyId][version - 1];
        if (policy.status == Status.ACTIVE && policy.expiresAt != 0 && block.timestamp > policy.expiresAt) {
            return Status.EXPIRED;
        }
        return policy.status;
    }

    function getPolicy(bytes32 policyId) external view returns (
        address creator,
        uint256 currentVersion,
        PolicyVersion memory policy,
        Status effectiveStatus
    ) {
        uint256 version = _currentVersion(policyId);
        policy = versions[policyId][version - 1];
        return (creators[policyId], version, policy, getEffectiveStatus(policyId));
    }

    function getPolicyVersion(bytes32 policyId, uint256 version) external view returns (PolicyVersion memory policy, Status effectiveStatus) {
        _requireVersion(policyId, version);
        policy = versions[policyId][version - 1];
        return (policy, getEffectiveStatusForVersion(policyId, version));
    }

    function hasApproved(bytes32 policyId, uint256 version, address approver) external view returns (bool) {
        _requireVersion(policyId, version);
        return approvals[policyId][version][approver];
    }

    function _appendVersion(bytes32 policyId, bytes32 policyHash, Risk risk, uint256 expiresAt) internal {
        uint256 requiredApprovals = risk == Risk.CRITICAL ? 2 : 1;
        versions[policyId].push(PolicyVersion({
            policyHash: policyHash,
            risk: risk,
            requiredApprovals: requiredApprovals,
            approvalCount: 0,
            status: Status.PROPOSED,
            proposedAt: block.timestamp,
            activatedAt: 0,
            rejectedAt: 0,
            revokedAt: 0,
            expiresAt: expiresAt
        }));
        uint256 version = versions[policyId].length;
        if (version == 1) emit PolicyProposed(policyId, version, msg.sender, policyHash, risk, expiresAt);
        else emit PolicyRevised(policyId, version, policyHash, risk, expiresAt);
    }

    function getEffectiveStatusForVersion(bytes32 policyId, uint256 version) public view returns (Status) {
        _requireVersion(policyId, version);
        PolicyVersion storage policy = versions[policyId][version - 1];
        if (policy.status == Status.ACTIVE && policy.expiresAt != 0 && block.timestamp > policy.expiresAt) return Status.EXPIRED;
        return policy.status;
    }

    function _currentVersion(bytes32 policyId) internal view returns (uint256) {
        uint256 version = versions[policyId].length;
        if (version == 0) revert PolicyDoesNotExist(policyId);
        return version;
    }

    function _requireVersion(bytes32 policyId, uint256 version) internal view {
        if (version == 0 || version > versions[policyId].length) revert InvalidVersion(policyId, version);
    }
}
