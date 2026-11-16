const { expect } = require("chai");
const { ethers } = require("hardhat");
const crypto = require("crypto");
const { MerkleTree } = require("merkletreejs");

// Helper: Calculate salted SHA-256 hash matching off-chain DiplomaProof pipeline
function calculateSaltedSha256(documentContent, salt) {
  const hashHex = crypto
    .createHash("sha256")
    .update(Buffer.from(documentContent + ":" + salt, "utf8"))
    .digest("hex");
  return "0x" + hashHex;
}

// Helper: Keccak256 wrapper for MerkleTreeJS compatibility with OpenZeppelin MerkleProof
function keccak256Buffer(data) {
  return Buffer.from(ethers.keccak256(data).slice(2), "hex");
}

describe("DiplomaProof — CredentialRegistry Smart Contract", function () {
  let registry;
  let admin, universityA, collegeB, unauthorizedUser;

  // Synthetic test credentials (no real personal data)
  const cred1 = calculateSaltedSha256("SYNTHETIC_DIPLOMA_001|BSc_CS|GPA_3.8", "salt_991a");
  const cred2 = calculateSaltedSha256("SYNTHETIC_DIPLOMA_002|BSc_SE|GPA_3.9", "salt_482b");
  const cred3 = calculateSaltedSha256("SYNTHETIC_CERT_003|Data_Analytics|Pass", "salt_773c");

  let merkleTree;
  let merkleRoot;

  beforeEach(async function () {
    [admin, universityA, collegeB, unauthorizedUser] = await ethers.getSigners();

    const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry");
    registry = await CredentialRegistry.deploy(admin.address);
    await registry.waitForDeployment();

    // Build Merkle Tree from salted SHA-256 leaves
    const leaves = [cred1, cred2, cred3].map((x) => Buffer.from(x.slice(2), "hex"));
    merkleTree = new MerkleTree(leaves, keccak256Buffer, { sortPairs: true });
    merkleRoot = merkleTree.getHexRoot();
  });

  it("1. Should allow Admin to add and remove approved issuers", async function () {
    await expect(registry.connect(admin).addIssuer(universityA.address))
      .to.emit(registry, "IssuerAdded")
      .withArgs(universityA.address, admin.address);

    const ISSUER_ROLE = await registry.ISSUER_ROLE();
    expect(await registry.hasRole(ISSUER_ROLE, universityA.address)).to.be.true;

    await expect(registry.connect(admin).removeIssuer(universityA.address))
      .to.emit(registry, "IssuerRemoved")
      .withArgs(universityA.address, admin.address);

    expect(await registry.hasRole(ISSUER_ROLE, universityA.address)).to.be.false;
  });

  it("2. Should prevent unauthorized accounts from adding issuers or anchoring batches", async function () {
    await expect(
      registry.connect(unauthorizedUser).addIssuer(collegeB.address)
    ).to.be.reverted;

    await expect(
      registry.connect(unauthorizedUser).anchorBatch(merkleRoot)
    ).to.be.reverted;
  });

  it("3. Should allow an approved issuer to anchor a weekly Merkle root", async function () {
    await registry.connect(admin).addIssuer(universityA.address);

    await expect(registry.connect(universityA).anchorBatch(merkleRoot))
      .to.emit(registry, "BatchAnchored");

    const batch = await registry.batches(merkleRoot);
    expect(batch.exists).to.be.true;
    expect(batch.issuer).to.equal(universityA.address);
  });

  it("4. Should prevent anchoring the exact same Merkle root twice", async function () {
    await registry.connect(admin).addIssuer(universityA.address);
    await registry.connect(universityA).anchorBatch(merkleRoot);

    await expect(
      registry.connect(universityA).anchorBatch(merkleRoot)
    ).to.be.revertedWith("Batch root already anchored");
  });

  it("5. Should return 'Valid' (status = 1) for an authentic credential with valid Merkle proof", async function () {
    await registry.connect(admin).addIssuer(universityA.address);
    await registry.connect(universityA).anchorBatch(merkleRoot);

    const proof = merkleTree.getHexProof(Buffer.from(cred1.slice(2), "hex"));
    const [status, issuer, anchoredAt] = await registry.verify(cred1, merkleRoot, proof);

    expect(status).to.equal(1n); // VerificationStatus.Valid
    expect(issuer).to.equal(universityA.address);
    expect(anchoredAt).to.be.greaterThan(0n);
  });

  it("6. Should return 'Revoked' (status = 2) after an issuer revokes a credential", async function () {
    await registry.connect(admin).addIssuer(universityA.address);
    await registry.connect(universityA).anchorBatch(merkleRoot);

    await expect(registry.connect(universityA).revoke(cred2))
      .to.emit(registry, "CredentialRevoked");

    const proof = merkleTree.getHexProof(Buffer.from(cred2.slice(2), "hex"));
    const [status, issuer] = await registry.verify(cred2, merkleRoot, proof);

    expect(status).to.equal(2n); // VerificationStatus.Revoked
    expect(issuer).to.equal(universityA.address);
  });

  it("7. Should return 'Unknown' (status = 0) if the credential PDF was tampered with", async function () {
    await registry.connect(admin).addIssuer(universityA.address);
    await registry.connect(universityA).anchorBatch(merkleRoot);

    // Tampered document (GPA changed from 3.8 to 4.0)
    const tamperedCred = calculateSaltedSha256("SYNTHETIC_DIPLOMA_001|BSc_CS|GPA_4.0", "salt_991a");
    const proof = merkleTree.getHexProof(Buffer.from(cred1.slice(2), "hex"));

    const [status] = await registry.verify(tamperedCred, merkleRoot, proof);
    expect(status).to.equal(0n); // VerificationStatus.Unknown
  });

  it("8. Should return 'Unknown' (status = 0) for a non-existent batch root", async function () {
    const fakeRoot = ethers.keccak256(ethers.toUtf8Bytes("FAKE_ROOT"));
    const [status, issuer, anchoredAt] = await registry.verify(cred1, fakeRoot, []);

    expect(status).to.equal(0n); // VerificationStatus.Unknown
    expect(issuer).to.equal(ethers.ZeroAddress);
    expect(anchoredAt).to.equal(0n);
  });
});