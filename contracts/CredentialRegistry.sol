// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract CredentialRegistry is Ownable {

    struct IssuerInfo {
        bool isAuthorized;
        uint256 registeredAt;
    }

    mapping(address => IssuerInfo) public issuers;
    mapping(bytes32 => bool) public anchoredBatches;
    mapping(bytes32 => bool) public revokedCredentials;

    event IssuerAdded(address indexed issuerAddress, uint256 timestamp);
    event IssuerRemoved(address indexed issuerAddress, uint256 timestamp);
    event BatchAnchored(address indexed issuerAddress, bytes32 indexed merkleRoot, uint256 timestamp);
    event CredentialRevoked(address indexed issuerAddress, bytes32 indexed credentialHash, uint256 timestamp);

    constructor() Ownable(msg.sender) {}

    function addIssuer(address _issuer) external onlyOwner {
        require(_issuer != address(0), "Invalid issuer address");
        require(!issuers[_issuer].isAuthorized, "Issuer is already authorized");

        issuers[_issuer] = IssuerInfo({
            isAuthorized: true,
            registeredAt: block.timestamp
        });

        emit IssuerAdded(_issuer, block.timestamp);
    }

    function removeIssuer(address _issuer) external onlyOwner {
        require(issuers[_issuer].isAuthorized, "Issuer is not authorized");
        issuers[_issuer].isAuthorized = false;

        emit IssuerRemoved(_issuer, block.timestamp);
    }

    function anchorBatch(bytes32 _merkleRoot) external {
        require(issuers[msg.sender].isAuthorized, "Caller is not an authorized issuer");
        require(_merkleRoot != bytes32(0), "Invalid Merkle root");
        require(!anchoredBatches[_merkleRoot], "Batch already anchored");

        anchoredBatches[_merkleRoot] = true;

        emit BatchAnchored(msg.sender, _merkleRoot, block.timestamp);
    }

    function revokeCredential(bytes32 _credentialHash) external {
        require(issuers[msg.sender].isAuthorized, "Caller is not an authorized issuer");
        require(_credentialHash != bytes32(0), "Invalid credential hash");
        require(!revokedCredentials[_credentialHash], "Credential already revoked");

        revokedCredentials[_credentialHash] = true;

        emit CredentialRevoked(msg.sender, _credentialHash, block.timestamp);
    }

    function verifyCredential(
        bytes32 _merkleRoot, 
        bytes32 _credentialHash
    ) external view returns (bool isValid, bool isRevoked, bool batchExists) {
        batchExists = anchoredBatches[_merkleRoot];
        isRevoked = revokedCredentials[_credentialHash];
        isValid = (batchExists && !isRevoked);
        
        return (isValid, isRevoked, batchExists);
    }
}