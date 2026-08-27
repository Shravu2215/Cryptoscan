const hre = require('hardhat');
const fs = require('fs');
const path = require('path');

/**
 * Deploys CryptoAnchor and writes its address + network to
 * deployed-contract.json, which anchor.js / verify.js read from
 * so nobody has to hardcode addresses by hand.
 */
async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log('Deploying CryptoAnchor with account:', deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log('Deployer balance:', hre.ethers.formatEther(balance), 'ETH');

  const CryptoAnchor = await hre.ethers.getContractFactory('CryptoAnchor');
  const contract = await CryptoAnchor.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const network = hre.network.name;

  console.log('CryptoAnchor deployed at:', address, 'on', network);

  const outPath = path.join(__dirname, '..', 'deployed-contract.json');
  fs.writeFileSync(
    outPath,
    JSON.stringify({ address, network, deployedAt: new Date().toISOString() }, null, 2)
  );
  console.log('Address written to', outPath);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
