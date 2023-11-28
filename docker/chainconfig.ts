import { GetContractReturnType, PrivateKeyAccount, createWalletClient, defineChain, getContract, publicActions, http, createPublicClient} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { exchangerABI } from "./_generated_dhkeabi";
import fs from 'fs';

// parse the current contract address from ./address.txt and create a viem-compliant address (`0x{string}`)
export const contractAddressRaw = fs.readFileSync('./address.txt', 'utf8');
export const contractAddress = contractAddressRaw.slice(2);

// derive a wallet from the private key in env - slicing the first two characters (0x) off to comply with viems `0x{string}` type
export const privateKey = process.env.PRIVATEKEY!.slice(2);
export const account = privateKeyToAccount(`0x${privateKey}`);

// define a chain and RPC entrypoint pointed at the docker host
export const chain = defineChain({
  name: 'hardhat',
  network: 'hardhat',
  rpcUrls: {
    default: {
      http: ['http://host.docker.internal:8545'],
    },
    public: {
      http: ['http://host.docker.internal:8545'],
    },
  },
  id: 31337,
  nativeCurrency: {
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18,
  },
});

// create a test client for the chain
export const walletclient = createWalletClient({
  chain: chain,
  transport: http(),
  account: account,
  }
).extend(publicActions);

export const publicclient = createPublicClient({
  chain: chain,
  transport: http(),
});

export const contract = getContract({
  address: `0x${contractAddress}`,
  abi: exchangerABI,
  walletClient: walletclient,
  publicClient: walletclient,
});