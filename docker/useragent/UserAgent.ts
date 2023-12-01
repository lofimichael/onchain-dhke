import { GetContractReturnType, PrivateKeyAccount, createWalletClient, defineChain, getContract, publicActions, http, numberToHex, numberToBytes} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { keccak256, toHex } from 'viem'
import ethers from 'ethers';
import { exchangerABI } from "../_generated_dhkeabi";
import fs from 'fs';

import { pad } from 'viem'

import { chain, walletclient, contract } from '../chainconfig'

import crypto, { DiffieHellmanGroup } from 'crypto';
import { type } from "os";

// for this first version, we will assume a contiguous single file with metadata is being sent over
type PayloadChunk = {
    // things like filenames, accompanying checksums, etc. -- if the "data" field is a remote URI like
    // an encrypted IPFS object, we can include an optional decryption key inside "meta" as well.
    // A 1024 byte chunk of data with metadata costs ~3.7m (+- ~300k for meta) gas per chunk, so ideally, the sent data *would* be
    // a remote URI. This also means that you ideally only need to register the payload once instead of chunking it up.

    // for the normies reading this, ~3.7m gas is $721.36 @ ~$2000/ETH L1, or $0.004 @ ~$0.511907/CELO L2. **Why we'd do this**: it can be
    // inherently assumed that the cost of compute and storage will continue to decrease over time approaching zero, 
    // and *eventually*, XYZ number of years down the line, we'll be able to accommodate a 
    // *completely* decentralized and encrypted payload transmission system disrupting functions of ISPs and cloud providers. 
    // this code is a proof of concept for that future, and the gas costs are a temporary limitation of the current state of the art.
    meta: {
        filename: string,
        checksum: string
        // decryptionkey: string -- see comment above
        },
    // base64 encoded string
    data: string
}

type EncryptedChunk = {
    checksum: string,
    encryptedData: string
};

// each checksum has its own payload assembly task -- this lets us *ideally* handle concurrent payloads with different checksums
// later down the line we can make the user agent more robust for more complex use cases
type PayloadAssembly = {
    chunks: { [index: number]: string }; // Stores chunks indexed by their chunk index
    totalChunks: number;
    isComplete: () => boolean; 
    processCompletePayload: () => Promise<void>; // Method to process complete payload
};

export class DHKEUserAgent {

    public account: PrivateKeyAccount;
    public contract: GetContractReturnType<typeof exchangerABI>;
    public role: string;
    public primenum: string;
    public generator: string;

    public dhkepubkey: string;
    public dhkeprivkey: string;
    public dhke: DiffieHellmanGroup;

    private incomingPayloads: { [checksum: string]: PayloadAssembly } = {};

    private publicKeyCache: { [address: string]: { publicKey: string, fetchTime: number } } = {};

    constructor() {
        this.account = walletclient.account as PrivateKeyAccount;
        this.contract = contract;
        this.role = process.env.ROLE!;
        this.primenum = "";
        this.generator = "";
        this.dhkeprivkey = "";
        this.dhkepubkey = "";
        this.dhke = undefined as unknown as DiffieHellmanGroup;; 
        
        // on init, fetch the primehex and generator from the contract
        contract.read.getConstants().then((result) => {
            
            // For the time being, we want to confirm the on-chain constants are
            // equivalent to the NodeJS modp18 group, and then take over with NodeJS for client/useragent ops from there.
            // never roll your own crypto, kids.

            const primehex = result.primehex

            // remove spaces from primehex, add 0x prefix
            const prefixedprimehex = "0x" +primehex.split(' ').join('').toLowerCase()
            
            const primenum = BigInt(prefixedprimehex).toString()

            // remove spaces from primehex without prefix
            const formattedprimehex = primehex.split(' ').join('').toLowerCase()

            this.primenum = primenum

            const gen = numberToBytes(result.generator)

            // we check the result of the contract against the NodeJS modp18 group, and if it matches, we proceed with the NodeJS DHKE module
            // we set it here instead of the environment because the contract *could* employ a different modp group in the future 
            // Given this is simulated client code - if we ever use a different modp group on-chain, we'll need to change this.
            const dhke = crypto.createDiffieHellmanGroup("modp18")
            const dhex = dhke.getPrime("hex")
            const dgen = dhke.getGenerator("hex")

            // pad both the contract generator value and the nodejs dhke generator value
            const padded_contractgen = pad(`0x${gen}`)
            const padded_dhkegen = pad(`0x${dgen}`)

            console.log("Padded contract generator: " + padded_contractgen)
            console.log("Padded dhke-gen: " + padded_dhkegen)

            // assert the values between local Node and on-chain contract constants are equivalent for the sake of the user agent
            if (padded_contractgen == padded_dhkegen) {
                console.log("Generator values match. Proceeding with User Agent operations.")
            } else {
                console.log("On-chain generator value does not match target NodeJS DHKE generator value. Exiting.")
                process.exit(1)
            }

            if (formattedprimehex == dhex) {
                console.log("Prime number values match. Proceeding with User Agent operations.")
            } else {
                console.log("On-chain primehex value does not match target NodeJS DHKE primehex value. Exiting.")
                process.exit(1)
            }


            console.log("Both public constants check out. Proceeding with local User Agent operations.")
            console.log("running dhke.generateKeys() on local NodeJS modp18...")
            dhke.generateKeys()

            // set the agent's DHKE public/private key pair
            this.dhke = dhke
            this.dhkeprivkey = dhke.getPrivateKey("hex")
            this.dhkepubkey = dhke.getPublicKey("hex")
            this.registerPublicKey()
            this.getPublicKey(this.account.address)
            console.log("Set user agent's DHKE public/private key pair.")

        }).catch((error) => {
            console.error("Error fetching smart contract constants in DHKE User Agent: " + error)
            console.error("Unable to properly set agent's reference to primehex and generator.")
        })

    }    

    // we cache here for the sake of the user agent so we dont overfetch the same public key from the contract on each encryption/decryption operation and stress poor Viem
    async getPublicKey(address: `0x${string}`) {
        const addressLowercase = address.toLowerCase();
        const currentTime = Date.now();
        const cacheEntry = this.publicKeyCache[addressLowercase];
        const cacheDuration = 30000; // 30 seconds in milliseconds
    
        if (cacheEntry) {
            if ((currentTime - cacheEntry.fetchTime) < cacheDuration) {
                return cacheEntry.publicKey;
            } else {
                console.log(`Cache expired for address ${addressLowercase}. Fetching new key...`);
            }
        } else {
            console.log(`No cache entry found for address ${addressLowercase}. Fetching new key...`);
        }
        
        try {
            const publicKey = await contract.read.getPublicKey([address]);
            
            if (publicKey == undefined || publicKey == "") {
                console.log("Public key is undefined. Fetching and caching.")
            }
    
            // Update the cache
            this.publicKeyCache[addressLowercase] = { publicKey, fetchTime: currentTime };
            
            console.log("Refreshed public key cache for address " + addressLowercase);
            console.log("Public Key:", publicKey.substring(0, 10) + '...' + publicKey.substring(publicKey.length - 10));
            return publicKey;
        } catch (error) {
            console.error('Error fetching public key:', error);
            throw error;
        }
    }

    async generateSharedSecret(PublicKey: string) {
        if (!this.dhkepubkey || !this.dhkeprivkey) {
            throw new Error("DHKE parameters not initialized");
        }
        try {
        
        const dhke = this.dhke

        const sharedSecret: Buffer = dhke.computeSecret(PublicKey, 'hex');
    
        return sharedSecret;
        } catch (error) {
            console.error('Error generating shared secret:', error);
            throw error;
        }
    }

    async encryptData(chunk: PayloadChunk, recipientAddress: `0x${string}`) {
        // Fetch the recipient's public key
        const recipientPublicKey = await this.getPublicKey(recipientAddress);
    
        // Generate the shared secret
        const sharedSecret = await this.generateSharedSecret(recipientPublicKey);
    
        // Derive a symmetric key from the shared secret
        const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();
    
        // Concatenate metadata and data for encryption
        let combinedData = JSON.stringify(chunk)

        // convert the combined data to a hexstring
        combinedData = Buffer.from(combinedData, 'ascii').toString('hex')

        // Encrypt the combined data using the symmetric key
        const iv = crypto.randomBytes(16); // Initialization vector for AES

        const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
    
        let encrypted = cipher.update(combinedData, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Return the checksum of the complete file and encrypted data chunk from it
        return {
            checksum: chunk.meta.checksum,
            encryptedData: iv.toString('hex') + encrypted
        };
    }

    async decryptData(encryptedData: string, senderAddress: `0x${string}`) {
        // Fetch the sender's public key
        const senderPublicKey = await this.getPublicKey(senderAddress);

        // Generate the shared secret
        const sharedSecret = await this.generateSharedSecret(senderPublicKey);

        // Derive a symmetric key from the shared secret
        const symmetricKey = crypto.createHash('sha256').update(sharedSecret).digest();
    
        const iv = Buffer.from(encryptedData.substring(0, 32), 'hex');

        const encrypted = encryptedData.substring(32);
    
        // Decrypt the data using the symmetric key
        const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');


        // Return the decrypted data
        return decrypted;
    }

    public async preparePayload(payload: Express.Multer.File[]): Promise<EncryptedChunk[]> {
      
      console.log("Preparing payloads for transmission...")
      console.log("Logging all received files...")
      console.log(payload)

      const paths = []

      for (let i = 0; i < payload.length; i++) {
        const file = payload[i]
        const path = file.path
        paths.push(path)
      }

        // convert each file to a payload chunk, with a data string no longer than 1024 bytes per chunk
        const payloadChunks: PayloadChunk[] = []

        for (let i = 0; i < paths.length; i++) {
            const path = paths[i]
            const filename = payload[i].originalname
            
            const b64 = fs.readFileSync(path, "base64")
            // hash the b64
            const hash = crypto.createHash('sha256')
            hash.update(b64)

            const checksum = hash.digest('hex')

            console.log("Logging checksum of file " + filename + ":")
            console.log(checksum)
            console.log("logging path:")
            console.log(path)

            const data = fs.readFileSync(path, 'base64')

            // split the data into chunks of 1024 bytes
            for (let i = 0; i < data.length; i += 1024) {
                const chunk = data.substring(i, Math.min(i + 1024, data.length));

                let payloadChunk: PayloadChunk = {
                    meta: {
                        filename: filename,
                        checksum: checksum
                    },
                    data: chunk
                }

                payloadChunks.push(payloadChunk)
            }
        }

    // prefetch the recipient's public key and make sure its stored in the cache
    await this.getPublicKey(process.env.PARTNER_ADDRESS as `0x${string}`)

    // Encrypt each chunk and collect promises
    const encryptedChunkPromises = payloadChunks.map(chunk=>  
    this.encryptData(chunk, process.env.PARTNER_ADDRESS as `0x${string}`)
    );

    // Wait for all promises to resolve
    const encryptedChunks = await Promise.all(encryptedChunkPromises)

    return encryptedChunks;
  }

    public async registerPublicKey(): Promise<any> {
        const pubkey = this.dhkepubkey
        console.log("Logging pubkey in user agent:")
        console.log(pubkey.substring(0, 10) + '...' + pubkey.substring(pubkey.length - 10))

        try {
            console.log("Sending transaction as " + this.role + " with address " + this.account.address + " to register public key " + pubkey.substring(0, 10) + '...' + pubkey.substring(pubkey.length - 10))
            const tx = await contract.write.setPublicKey([pubkey]);
            const pubkey2 = await contract.read.getPublicKey([this.account.address]);
            console.log("Logging pubkey after registering:")
            console.log(pubkey2.substring(0, 10) + '...' + pubkey2.substring(pubkey2.length - 10))
        } catch (error) {
            console.error("Error in registerPublicKey:", error);
            throw error;
        }
    }

    public async sendPayload(
        encryptedChunks: EncryptedChunk[],
        recipientAddress: string
    ): Promise<any[]> {
        let txs: any[] = [];
    
        // we send in series for now because viem lacks good nonce management
        // https://github.com/wevm/viem/discussions/1338

        for (let i = 0; i < encryptedChunks.length; i++) {
            const chunk = encryptedChunks[i];
            const chunkIndex = i;  // Chunk index
            const chunkHash = crypto.createHash('sha256').update(chunk.encryptedData).digest('hex');

            // coerce the encrypted chunks length and index to a bigint
            const encryptedChunksLength = BigInt(encryptedChunks.length)
            const chunkIndexBigInt = BigInt(chunkIndex)
                            
            // convert the checksum to a bytes32 array
            const b32checksum = `0x${encryptedChunks[chunkIndex].checksum}` as `0x${string}`    
            
            try {
                const tx = await contract.write.registerEncryptedPayload([
                    this.account.address,  // Sender address
                    recipientAddress as `0x${string}`,  // Recipient address
                    chunk.encryptedData, 
                    b32checksum,
                    chunkIndexBigInt,
                    encryptedChunksLength,
                ]);
                console.log(`Sending chunk ${i + 1}/${encryptedChunks.length}`);
                txs.push(tx);
            } catch (error) {
                console.error(`Error sending chunk ${i + 1}:`, error);
                throw error;
            }
        }
    
        return txs;
    }

    // logs are added as a last param to the handler as a sanity check
    async handleIncomingPayloadEvent(sender: string, recipient: string, encryptedData: string, checksum: string, chunkIndex: number, totalChunks: number, logs: any) {
        if (!this.incomingPayloads[checksum]) {
            this.incomingPayloads[checksum] = {
              chunks: {},
              totalChunks,
              isComplete: function() {
                return Object.keys(this.chunks).length === this.totalChunks;
              },
              processCompletePayload: async () => {


                // concat the chunk object values into a single string
                let payload = ""
                for (const [key, value] of Object.entries(this.incomingPayloads[checksum].chunks)) {
                    payload += value
                }

                let decryptedChunks = [];
            
                // Decrypt each chunk and add to the decryptedChunks array
                for (let i = 0; i < totalChunks; i++) {
                    let encryptedChunk = this.incomingPayloads[checksum].chunks[i];

                    // snip illegal characters like @#$%^&*(){}[]|\/+=-~`"' and whitespace
                    encryptedChunk = encryptedChunk.replace(/[^a-zA-Z0-9]/g, '')

                    let decryptedChunk = await this.decryptData(encryptedChunk, process.env.PARTNER_ADDRESS as `0x${string}`);
                    decryptedChunks.push(decryptedChunk);
                }

                // convert each decrypted chunkhex to a json object
                let reconstructedData: PayloadChunk = {
                    meta: {
                        filename: "",
                        checksum: ""
                    },
                    data: ""
                }
                for (let i = 0; i < decryptedChunks.length; i++) {
                    // each chunk is a hexstring representing type EncryptedChunk
                    const chunk = decryptedChunks[i]
                    // convert chunk hex to ascii
                    const chunkascii = Buffer.from(chunk, 'hex').toString('ascii')
                    // convert chunk ascii to json
                    const chunkjson:PayloadChunk = JSON.parse(chunkascii)

                    reconstructedData.meta.filename = chunkjson.meta.filename
                    reconstructedData.meta.checksum = chunkjson.meta.checksum
                    reconstructedData.data += chunkjson.data
                }

                // write the payload to a file
                const filename = reconstructedData.meta.filename
                const data = reconstructedData.data
                const path = `./received/${filename}`

                const filebuffer = Buffer.from(data, 'base64')

                fs.writeFileSync(path, filebuffer)

                // Verify the data payload
                const b64 = fs.readFileSync(path, "base64")
                console.log("logging b64 in decryption")
                console.log(b64.substring(0, 10) + '...' + b64.substring(b64.length - 10))
                // hash the buffer
                const hash = crypto.createHash('sha256')
                hash.update(b64)
    
                const stringhash = hash.digest('hex')

                const reconstructed_file_checksum = stringhash
                const sent_file_checksum = reconstructedData.meta.checksum
                console.log("Logging reconstructed file checksum:")
                console.log(reconstructed_file_checksum)
                console.log("Logging sent file checksum:")
                console.log(sent_file_checksum)
                console.log("Asserting equality (reconstructed file equals what was sent on-chain)...")
                if (reconstructed_file_checksum == sent_file_checksum) {
                    console.log("✨✨✨✨✨ File integrity verified. Check the receiving docker container for your file. ✨✨✨✨✨")
                } else {
                    console.log("🚨🚨🚨🚨 File integrity violation detected. 🚨🚨🚨🚨")
                    console.log("Reconstructed file checksum does not match sent file checksum.")
                }

                console.log(`Payload processing complete for checksum ${checksum}.`);
                
              }
            };
            console.log(`Initialized new payload assembly for checksum ${checksum}.`);
          }
        
          this.incomingPayloads[checksum].chunks[chunkIndex] = encryptedData;
          console.log(`Received chunk ${chunkIndex}/${totalChunks} for checksum ${checksum}.`);
        
          if (this.incomingPayloads[checksum].isComplete()) {
            await this.incomingPayloads[checksum].processCompletePayload();
            delete this.incomingPayloads[checksum];
          }
    }

}