const { ethers } = require("hardhat");
const crypto = require("crypto");
const { MerkleTree } = require("merkletreejs");

function calculateSaltedSha256(content, salt) {
  return (
    "0x" +
    crypto
      .createHash("sha256")
      .update(Buffer.from(content + ":" + salt, "utf8"))
      .digest("hex")
  );
}

function keccak256Buffer(data) {
  return Buffer.from(ethers.keccak256(data).slice(2), "hex");
}

const STATUS_NAMES = ["Unknown", "Valid", "Revoked"];

async function main() {
  console.log("=== DiplomaProof Local Prototype Demo (Educational Simulation) ===\n");

  const [admin, universityIssuer] = await ethers.getSigners();

  // Step 1: Deploy Contract
  const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry");
  const registry = await CredentialRegistry.deploy(admin.address);
  await registry.waitForDeployment();
  console.log("[1] Contract deployed at:", await registry.getAddress());

  // Step 2: Register Approved University Issuer
  await (await registry.connect(admin).addIssuer(universityIssuer.address)).wait();
  console.log("[2] Approved Issuer registered:", universityIssuer.address);

  // Step 3: Off-chain Salted SHA-256 Hashing & Weekly Merkle Tree Construction
  const diplomaA = calculateSaltedSha256("TEST_GRADUATE_01|Software_Engineering|2026", "salt_alpha_01");
  const diplomaB = calculateSaltedSha256("TEST_GRADUATE_02|Cybersecurity|2026", "salt_beta_02");
  const leaves = [diplomaA, diplomaB].map((h) => Buffer.from(h.slice(2), "hex"));

  const tree = new MerkleTree(leaves, keccak256Buffer, { sortPairs: true });
  const root = tree.getHexRoot();
  console.log("[3] Off-chain Merkle Root computed:", root);

  // Step 4: Anchor Merkle Root On-Chain
  await (await registry.connect(universityIssuer).anchorBatch(root)).wait();
  console.log("[4] Weekly Merkle Root anchored on-chain successfully.\n");

  // Step 5: Employer Verifies Valid Diploma A
  const proofA = tree.getHexProof(Buffer.from(diplomaA.slice(2), "hex"));
  const resValid = await registry.verify(diplomaA, root, proofA);
  console.log(`[5] Employer check for Diploma A -> Status: ${STATUS_NAMES[Number(resValid[0])]}`);

  // Step 6: Employer Checks Tampered PDF (Modified Grade/Major)
  const tamperedA = calculateSaltedSha256("TEST_GRADUATE_01|Modified_Major|2026", "salt_alpha_01");
  const resTampered = await registry.verify(tamperedA, root, proofA);
  console.log(`[6] Employer check for Tampered PDF -> Status: ${STATUS_NAMES[Number(resTampered[0])]}`);

  // Step 7: University Revokes Diploma B & Employer Re-checks
  await (await registry.connect(universityIssuer).revoke(diplomaB)).wait();
  const proofB = tree.getHexProof(Buffer.from(diplomaB.slice(2), "hex"));
  const resRevoked = await registry.verify(diplomaB, root, proofB);
  console.log(`[7] Employer check for Revoked Diploma B -> Status: ${STATUS_NAMES[Number(resRevoked[0])]}\n`);

  console.log("=== Demo Completed Successfully ===");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});