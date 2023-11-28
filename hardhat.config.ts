import { HardhatUserConfig } from "hardhat/types";
import * as dotenv from 'dotenv';
import "@nomicfoundation/hardhat-ethers";
import fs from 'fs';

dotenv.config({ path: __dirname + '/docker/.env' });

// THIS ASSUMES THIS IS BEING RUN VIA `hardhat.sh` TO GENERATE KEYS AS A PRE-STEP
const lines = fs.readFileSync('./docker/.env', 'utf8').split('\n');
const privatekeys = lines
  .filter(line => line.startsWith('PRIVATEKEY_'))
  .map(key => key.split('=')[1]);

console.log("privatekeys")
console.log(privatekeys);

// Create account with balance
const accounts = privatekeys.map(key => {
  return {
    privateKey: key.valueOf(),
    balance: "100000000000000000000000000000000000"
  }
});

console.log("accounts")
console.log(accounts);

// Use the mnemonics in your Hardhat configuration
const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  networks: {
    hardhat: {
      accounts: accounts,
      mining: {
        auto: true,
        interval: 1000
      },
    },
  },
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache_hardhat",
    artifacts: "./artifacts"
  },
};

export default config;
