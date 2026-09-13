require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

// PRIVATE_KEY must be a TESTNET-ONLY key (funded only via the MST faucet).
// Never use a key that holds real/mainnet value. See .env.example.
const PRIVATE_KEY = process.env.PRIVATE_KEY;

/** @type {import("hardhat/config").HardhatUserConfig} */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    mstTestnet: {
      // OFFICIAL, confirmed via MST-MCP "Development Networks - MST Testnet" doc:
      url: "https://testnetrpc.mstblockchain.com",
      chainId: 91562037,
      accounts: PRIVATE_KEY ? [PRIVATE_KEY] : [],
    },
  },
};
