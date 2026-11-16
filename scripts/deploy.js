const { ethers } = require("hardhat");

async function main() {
  const [admin] = await ethers.getSigners();
  console.log("Deploying CredentialRegistry with Admin test account:", admin.address);

  const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry");
  const registry = await CredentialRegistry.deploy(admin.address);
  await registry.waitForDeployment();

  console.log("CredentialRegistry deployed to:", await registry.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});