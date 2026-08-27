require('@nomicfoundation/hardhat-toolbox');
require('dotenv').config();

/**
 * Networks:
 *  - hardhat/localhost: for dev + demo rehearsal (fast, free, resettable)
 *  - sepolia: real public testnet for the actual demo tx (real tx hash,
 *    viewable on a block explorer — this is what makes the anchor "real")
 *
 * SEPOLIA_RPC_URL: get a free RPC endpoint from Alchemy/Infura.
 * PRIVATE_KEY: a throwaway testnet wallet's private key (never a real wallet).
 * Fund it from a Sepolia faucet before demo day.
 */
module.exports = {
  solidity: {
    version: '0.8.24',
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: {},
    localhost: {
      url: 'http://127.0.0.1:8545',
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || '',
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
};
