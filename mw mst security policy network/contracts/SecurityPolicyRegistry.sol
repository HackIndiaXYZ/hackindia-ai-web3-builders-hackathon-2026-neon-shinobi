// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecurityPolicyRegistry
 * @notice MILESTONE-1 MINIMAL VERSION.
 *
 * Purpose: prove the core loop — propose a security policy, have a
 * designated approver authorize it on-chain, and let anyone
 * independently read back and verify that state. Nothing else.
 *
 * Explicitly NOT in this version (by design, see Section 9 / 13
 * of the project spec — do not add until Phase 1 is proven on testnet):
 *  - versioning
 *  - revocation
 *  - multi-approver / role management
 *  - upgradeability
 *
 * On-chain vs off-chain (Section 5/11 test applied):
 *  - On-chain: policy identity, status, who proposed/approved, when,
 *    and a hash commitment of the full policy payload.
 *  - Off-chain (NOT here): the full policy JSON (source/dest segment,
 *    protocol, port, risk explanation, etc.) — the on-chain hash lets
 *    anyone prove that off-chain payload hasn't been tampered with,
 *    without putting operational detail on a public chain.
 */
contract SecurityPolicyRegistry {
    enum Status {
        NONE,       // default / does not exist
        PROPOSED,
        APPROVED
    }

    struct Policy {
        address creator;      // who proposed it
        address approver;     // who approved it (address(0) until approved)
        bytes32 policyHash;   // keccak256 hash of the off-chain policy payload
        Status status;
        uint256 proposedAt;
        uint256 approvedAt;
    }

    /// @notice The only account allowed to approve policies in this milestone.
    /// A future phase will replace this with proper role-based access.
    address public immutable authorizedApprover;

    mapping(bytes32 => Policy) private policies;

    event PolicyProposed(
        bytes32 indexed policyId,
        address indexed creator,
        bytes32 policyHash,
        uint256 timestamp
    );

    event PolicyApproved(
        bytes32 indexed policyId,
        address indexed approver,
        uint256 timestamp
    );

    error PolicyAlreadyExists(bytes32 policyId);
    error PolicyDoesNotExist(bytes32 policyId);
    error PolicyNotInProposedState(bytes32 policyId, Status currentStatus);
    error NotAuthorizedApprover(address caller);

    constructor(address _authorizedApprover) {
        require(_authorizedApprover != address(0), "approver cannot be zero address");
        authorizedApprover = _authorizedApprover;
    }

    /**
     * @notice Propose a new security policy.
     * @param policyId Caller-generated unique id (e.g. keccak256 of an off-chain UUID).
     * @param policyHash keccak256 hash of the full off-chain policy payload (for integrity proof).
     */
    function proposePolicy(bytes32 policyId, bytes32 policyHash) external {
        if (policies[policyId].status != Status.NONE) {
            revert PolicyAlreadyExists(policyId);
        }

        policies[policyId] = Policy({
            creator: msg.sender,
            approver: address(0),
            policyHash: policyHash,
            status: Status.PROPOSED,
            proposedAt: block.timestamp,
            approvedAt: 0
        });

        emit PolicyProposed(policyId, msg.sender, policyHash, block.timestamp);
    }

    /**
     * @notice Approve a proposed policy. Only the authorizedApprover may call this.
     */
    function approvePolicy(bytes32 policyId) external {
        if (msg.sender != authorizedApprover) {
            revert NotAuthorizedApprover(msg.sender);
        }

        Policy storage p = policies[policyId];

        if (p.status == Status.NONE) {
            revert PolicyDoesNotExist(policyId);
        }
        if (p.status != Status.PROPOSED) {
            revert PolicyNotInProposedState(policyId, p.status);
        }

        p.status = Status.APPROVED;
        p.approver = msg.sender;
        p.approvedAt = block.timestamp;

        emit PolicyApproved(policyId, msg.sender, block.timestamp);
    }

    /**
     * @notice Read back a policy's on-chain state.
     */
    function getPolicy(bytes32 policyId)
        external
        view
        returns (
            address creator,
            address approver,
            bytes32 policyHash,
            Status status,
            uint256 proposedAt,
            uint256 approvedAt
        )
    {
        Policy storage p = policies[policyId];
        if (p.status == Status.NONE) {
            revert PolicyDoesNotExist(policyId);
        }
        return (p.creator, p.approver, p.policyHash, p.status, p.proposedAt, p.approvedAt);
    }
}
