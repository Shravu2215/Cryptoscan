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

  // Authorize configured KMS / environment wallet as an authorized writer if different from deployer
  if (process.env.PRIVATE_KEY) {
    try {
      const kmsWallet = new hre.ethers.Wallet(process.env.PRIVATE_KEY);
      if (kmsWallet.address.toLowerCase() !== deployer.address.toLowerCase()) {
        const authTx = await contract.setAuthorizedWriter(kmsWallet.address, true);
        await authTx.wait();
        console.log('Authorized KMS signer wallet as writer:', kmsWallet.address);

        if (network === 'localhost') {
          const fundTx = await deployer.sendTransaction({
            to: kmsWallet.address,
            value: hre.ethers.parseEther('10.0'),
          });
          await fundTx.wait();
          console.log('Funded KMS wallet with 10 ETH for local testing');
        }
      }
    } catch (authErr) {
      console.warn('Could not authorize KMS key:', authErr.message);
    }
  }

  // Write network-specific deployment file (e.g., deployed-sepolia.json, deployed-localhost.json)
  const networkPath = path.join(__dirname, '..', `deployed-${network}.json`);
  const record = { address, network, deployedAt: new Date().toISOString() };
  fs.writeFileSync(networkPath, JSON.stringify(record, null, 2));
  console.log(`Deployment recorded to ${networkPath}`);

  // Only update default deployed-contract.json if deploying to localhost or if it does not exist
  const defaultPath = path.join(__dirname, '..', 'deployed-contract.json');
  if (network === 'localhost' || !fs.existsSync(defaultPath)) {
    fs.writeFileSync(defaultPath, JSON.stringify(record, null, 2));
    console.log(`Default address written to ${defaultPath}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
