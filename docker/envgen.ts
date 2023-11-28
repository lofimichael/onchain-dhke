import fs from 'fs';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

function generateEnvVariables(numberOfInstances: number) {
  let envVariables: string[] = [];
  let publicKeyAddressMap: string[] = [];

  for (let i = 0; i < numberOfInstances; i++) {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    const publicKey = account.publicKey;
    const address = account.address;

    envVariables.push(`PRIVATEKEY_${i}=${privateKey}`);
    publicKeyAddressMap.push(`PUBLICKEY_${i}=${publicKey}`);
    publicKeyAddressMap.push(`ADDRESS_${i}=${address}`);

    console.log(`Generated private key ${i}: ${privateKey}`);
    console.log(`Public Key ${i}: ${publicKey}`);
    console.log(`Address ${i}: ${address}`);
  }

  fs.writeFileSync('.env', envVariables.concat(publicKeyAddressMap).join('\n'));

  return envVariables;
}

const numberOfInstances = parseInt(process.argv[2], 10);
generateEnvVariables(numberOfInstances);
