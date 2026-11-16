// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title CredentialRegistry
 * @notice Educational prototype for DiplomaProof (Introduction to Finance, 2026).
 * @dev Stores Merkle roots of salted SHA-256 credential hashes and tracks issuer/revocation states.
 *      No personal data or PDF files are stored on-chain.
 */
contract CredentialRegistry is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    enum VerificationStatus {
        Unknown,
        Valid,
        Revoked
    }

    struct BatchInfo {
        address issuer;
        uint256 timestamp;
        bool exists;
    }

    // Mapping from Merkle root => Batch metadata
    mapping(bytes32 => BatchInfo) public batches;

    // Mapping from credential salted SHA-256 hash => revoked status
    mapping(bytes32 => bool) public revokedCredentials;

    // Mapping from credential hash => address of issuer who revoked it
    mapping(bytes32 => address) public revokedBy;

    event IssuerAdded(address indexed issuer, address indexed admin);
    event IssuerRemoved(address indexed issuer, address indexed admin);
    event BatchAnchored(bytes32 indexed merkleRoot, address indexed issuer, uint256 timestamp);
    event CredentialRevoked(bytes32 indexed credentialHash, address indexed issuer, uint256 timestamp);

    constructor(address initialAdmin) {
        require(initialAdmin != address(0), "Invalid admin address");
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    }

    /**
     * @notice Registers an approved educational institution (university, college, training centre).
     * @param issuer Wallet address representing the approved institution.
     */
    function addIssuer(address issuer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(issuer != address(0), "Invalid issuer address");
        grantRole(ISSUER_ROLE, issuer);
        emit IssuerAdded(issuer, msg.sender);
    }

    /**
     * @notice Disables an issuer that is no longer authorized to anchor new batches.
     * @dev Historical batches remain verifiable, while current issuer status can be audited.
     * @param issuer Wallet address of the institution to remove.
     */
    function removeIssuer(address issuer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(ISSUER_ROLE, issuer);
        emit IssuerRemoved(issuer, msg.sender);
    }

    /**
     * @notice Anchors a weekly Merkle root representing a batch of salted SHA-256 credential hashes.
     * @param root The 32-byte Merkle root of the batch.
     */
    function anchorBatch(bytes32 root) external onlyRole(ISSUER_ROLE) {
        require(root != bytes32(0), "Empty Merkle root");
        require(!batches[root].exists, "Batch root already anchored");

        batches[root] = BatchInfo({
            issuer: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        emit BatchAnchored(root, msg.sender, block.timestamp);
    }

    /**
     * @notice Marks a specific credential hash as revoked.
     * @param credentialHash The salted SHA-256 hash of the credential PDF.
     */
    function revoke(bytes32 credentialHash) external onlyRole(ISSUER_ROLE) {
        require(credentialHash != bytes32(0), "Invalid credential hash");
        require(!revokedCredentials[credentialHash], "Credential already revoked");

        revokedCredentials[credentialHash] = true;
        revokedBy[credentialHash] = msg.sender;

        emit CredentialRevoked(credentialHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Public verification function returning Valid, Revoked, or Unknown.
     * @param credentialHash Salted SHA-256 hash of the submitted credential.
     * @param merkleRoot The Merkle root of the batch containing the credential.
     * @param proof Merkle proof path from credentialHash to merkleRoot.
     * @return status VerificationStatus enum (0 = Unknown, 1 = Valid, 2 = Revoked).
     * @return issuer Address of the issuer that anchored the batch (address(0) if Unknown).
     * @return anchoredAt Timestamp when the batch was anchored (0 if Unknown).
     */
    function verify(
        bytes32 credentialHash,
        bytes32 merkleRoot,
        bytes32[] calldata proof
    )
        external
        view
        returns (
            VerificationStatus status,
            address issuer,
            uint256 anchoredAt
        )
    {
        BatchInfo memory batch = batches[merkleRoot];

        // 1. Check if the batch exists on-chain
        if (!batch.exists) {
            return (VerificationStatus.Unknown, address(0), 0);
        }

        // 2. Verify Merkle proof against the anchored root
        bool isValidProof = MerkleProof.verify(proof, merkleRoot, credentialHash);
        if (!isValidProof) {
            return (VerificationStatus.Unknown, address(0), 0);
        }

        // 3. Check if the credential has been revoked
        if (revokedCredentials[credentialHash]) {
            return (VerificationStatus.Revoked, batch.issuer, batch.timestamp);
        }

        // 4. Optional check: verify issuer is still active (if removed, historical validity can be flagged or checked)
        if (!hasRole(ISSUER_ROLE, batch.issuer)) {
            return (VerificationStatus.Unknown, batch.issuer, batch.timestamp);
        }

        return (VerificationStatus.Valid, batch.issuer, batch.timestamp);
    }
}