import { ethers } from "ethers";
import { defineChain, createWalletClient, http as viemhttp, PrivateKeyAccount, getContract, parseAbi, createPublicClient, parseGwei, publicActions } from 'viem'
import fs from 'fs';
import { exchangerABI } from './_generated_dhkeabi';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'

import { chain, walletclient, contract, contractAddress, account } from './chainconfig'
import express, { Express } from 'express';
import http from 'http';
import multer from 'multer';

import { DHKEUserAgent } from './useragent/UserAgent'

console.log("🚀 Initializing container and user agents 🚀")
console.log("Asserting that contract ABI (used in contract.read) and exchanger ABI are the same:")
console.log(contract.abi === exchangerABI)
if (contract.abi !== exchangerABI) {
  throw new Error("Viem Contract ABI and exchanger ABI file is not the same!")
}
console.log("__Pointed at: " + "[" + contractAddress + "]");
console.log("__Role: " + process.env.ROLE);
console.log(`__Using private key: ${process.env.PRIVATEKEY}`);
console.log(`__Using account: ${account.address}`);
const userAgent = new DHKEUserAgent();
    
const pubkeyinterval = 30000; // 30 seconds, same as useragent
// set interval to get public key using dhke user agent
setInterval(() => {
  userAgent.getPublicKey(userAgent.account.address);
}, pubkeyinterval);

// watch for all events and incoming payloads
const unwatchEncryptedPayloadReg = walletclient.watchEvent({

  // ABI per IDHKE.sol: 
  events: parseAbi([
    'event encryptedPayloadRegistered(address indexed sender, address indexed recipient, string encryptedData, bytes32 indexed checksum, uint256 chunkIndex, uint256 contentlength)',
  ]),

  onLogs: (logs) => {
    // Iterate over each log entry
    logs.forEach(log => {
      // Extract sender, recipient, and other data from the log's topics and data
      const _sender = '0x' + log.topics[1]!.slice(26); // Extracting sender address
      const _recipient = '0x' + log.topics[2]!.slice(26); // Extracting recipient address
      const _encryptedData = log.args.encryptedData!; // Extracting encrypted data
      const _checksum = log.args.checksum; // Extracting checksum
      const _chunkIndex = log.args.chunkIndex; // Extracting chunkIndex
      const _contentlength = log.args.contentlength; // Extracting contentlength

      // coerce checksum to string
      const checksumString = String(_checksum);
      // coerce chunkIndex to number
      const chunkIndexNumber = Number(_chunkIndex);
      // coerce contentlength to number
      const contentlengthNumber = Number(_contentlength);

      console.log(userAgent.role + " with address " + account.address + " received event from contract:")

      // Role Logs 🪵🪵🪵🪵🪵🪵
      const suppressRoleLogs = false;

      if (userAgent.role === "WARDEN" && suppressRoleLogs === false) {
        // Logic specific to the Warden role observing the transaction
        console.log("WARDEN 💀💀💀💀💀💀💀💀💀💀💀")
        console.log("WARDEN SEES SENDER " + _sender + " SENT TO RECIPIENT " + _recipient);
        console.log("WARDEN SEES PAYLOAD DATA " + _encryptedData.substring(0, 10) + "..." + _encryptedData.substring(_encryptedData.length - 10, _encryptedData.length));
        console.log("WARDEN SEES CHECKSUM " + _checksum);
        console.log("WARDEN SEES CHUNK INDEX" + _chunkIndex);
        console.log("WARDEN SEES CONTENT LENGTH" + _contentlength);

        // theoretically, the warden could store the payload data here and do whatever analysis they want on it afterwards

      }

      // Check if the recipient matches this container's address
      if (_recipient.toLowerCase() === userAgent.account.address.toLowerCase() && suppressRoleLogs === false) {

        console.log("📧 📧 📧 📧  Incoming payload!  📧 📧 📧 📧 ")
        console.log("sender: " + _sender);
        console.log("recipient: " + userAgent.account.address);
        console.log("encryptedData: " + _encryptedData.substring(0, 10) + "..." + _encryptedData.substring(_encryptedData.length - 10, _encryptedData.length));
        console.log("checksum: " + _checksum);
        console.log("chunkIndex: " + _chunkIndex);
        console.log("contentlength: " + _contentlength);

        const receiver = userAgent.account.address ? "me" : _recipient; ;
        console.log(`Incoming transaction detected. Sender: ${_sender}, Recipient: ${receiver}"`);
        userAgent.handleIncomingPayloadEvent(_sender, _recipient, _encryptedData, checksumString, chunkIndexNumber, contentlengthNumber, logs);

      } 

      if (_sender.toLowerCase() === userAgent.account.address.toLowerCase() && suppressRoleLogs === false) {
        console.log("📤 📤 📤 📤  Outgoing payload registered!  📤 📤 📤 📤 ")
        console.log("sender: " + userAgent.account.address);
        console.log("recipient: " + _recipient);
        console.log("encryptedData: " + _encryptedData.substring(0, 10) + "..." + _encryptedData.substring(_encryptedData.length - 10, _encryptedData.length));
        console.log("checksum: " + _checksum);
        console.log("chunkIndex: " + _chunkIndex);
        console.log("contentlength: " + _contentlength);
      }
    });
  },
poll: true,
pollingInterval: 500
});

const app:Express = express();
const externalPort = process.env.EXTERNAL_PORT // set in docker-compose.yml
const internalPort = 3000; // Port that the container is listening on
// Parse JSON bodies (as sent by API clients)
app.use(express.json());

// multer storage config -- set where sent files are held
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './pending_uploads/')
  },
  filename: function (req, file, cb) {
    // use the file originalname file extension as the file extension
    const fileExtension = file.originalname.split('.').pop();
    // get the name of the file without the extension
    const fileName = file.originalname.split('.').slice(0, -1).join('.');
    // [prefix of choice]-name.file extension
    cb(null, fileName + '.' + fileExtension)
  }
})

// multer upload middleware for express
const upload = multer({ storage: storage })

const server = app.listen(internalPort, () => {
  console.log(`Docker container listening at http://localhost:${internalPort} using external port ${externalPort}`);
});

// multipart/form-data file upload endpoint
app.post('/send-file-payload', upload.any(), async function (req, res) {
  console.log("Received file request to /send-file-payload");

  // Check if any files are available in the request
  if (req.files) {
    // have the user agent prepare the payload
    const files = req.files as Express.Multer.File[];
    const encryptedChunks = await userAgent.preparePayload(files);
    console.log("Finished preparing payload with encrypted chunks");
  
    // Send each encrypted chunk
    try {
      const txs = await userAgent.sendPayload(encryptedChunks, process.env.PARTNER_ADDRESS!);
      console.log(`Payloads sent successfully. Transactions: ${txs.map(tx => tx.hash).join(', ')}`);
      res.json({ message: "Files uploaded and payloads sent successfully"});
    } catch (error) {
      console.error("Error sending payloads:", error);
      res.status(500).json({ message: "Error sending payloads"});
    }
  } else {
    console.log("No files were uploaded.");
    res.json({ message: "No files received" });
  }
});

// get public key of this container
app.get('/get-publickey', async (req, res) => {
  try {
    console.log("Received request to /get-publickeys");
    contract.read.getPublicKey([account.address]).then((pubkey) => {
      console.log("Logging publickey of " + process.env.ROLE + " with address " + account.address + ":")
      console.log(pubkey)
      res.json({ message: "Public key retrieved successfully", publicKey: pubkey });
    }).catch((error) => {
      console.error("Error in getPublicKey:", error);
      throw error;
    })
  }
  catch (error) {
    console.error("Error in /get-publickeys:", error);
    res.status(500).json({ message: "Error getting public keys" });
  }
});

// get all on-chain payloads sent by this container, grouped by checksum
app.get('/get-payloads', async (req, res) => {
  try {
    console.log("Received request to /get-payloads");
    contract.read.getChecksumsBySender([account.address]).then((payloads) => {
      // call getPayloadsByChecksum for each payload
      if (payloads.length == 0) {
        console.log("No outgoing payloads found for " + process.env.ROLE + " with address " + account.address + ":")
        res.json({ message: "No outgoing payloads found for given container", payloads: payloads });
      } else {
      console.log("logging checksum payloads:")
      console.log(payloads)

      const uniqueChecksums = [...new Set(payloads)];
      console.log("logging unique checksums:")
      console.log(uniqueChecksums)

      type PayloadsByChecksum = {
        checksum: string,
        payloads: {}
      }

      // slice the 0x from each unique checksum
      const uniqueChecksumsNo0x = uniqueChecksums.map((checksum) => checksum.slice(2));

      let payloadsbychecksum: PayloadsByChecksum[] = []

        // create an array of promises for each unique checksum
        const getPayloadsByChecksumPromises = uniqueChecksums.map((checksum) => {
          return contract.read.getPayloadsByChecksum([checksum]);
        });

        // resolve all promises
        Promise.all(getPayloadsByChecksumPromises).then((payloads) => {

          // for each unique checksum, create a new object with the checksum and the payloads
          payloadsbychecksum = uniqueChecksumsNo0x.map((checksum, index) => {
            const payloadsWithoutBigInt = payloads[index].map(payload => ({
              ...payload,
              // convert bigints to strings to avoid JSON serialization issues
              index: payload.index.toString(),
              contentlength: payload.contentlength.toString()
            }));
            return { checksum: checksum as string, payloads: payloadsWithoutBigInt };
          });

          res.json({ message: "Checksummed payloads sent by given container retrieved successfully", payloads: payloadsbychecksum });

        }).catch((error) => {
          console.error("Error in getPayloadsByChecksumPromises:", error);
          throw error;
        });
    }
    }).catch((error) => {
      console.error("Error in getPayloadsBySender:", error);
      throw error;
    })
  }
  catch (error) {
    console.error("Error in /get-payloads:", error);
    res.status(500).json({ message: "Error getting payloads" });
  }
});

// Ping hardhat node default address to check if it's online
function checkHardhatNode() {
  return new Promise((resolve) => {
    const request = http.get('http://host.docker.internal:8545', (response) => {
      resolve(response.statusCode === 200);
    });

    request.on('error', () => {
      resolve(false);
    });

    request.end();
  });
}

// Hardhat node interval health check
const checkInterval = setInterval(async () => {
  const isNodeAlive = await checkHardhatNode();
  if (!isNodeAlive) {
    console.error('Hardhat node is not online. Shutting down...');
    clearInterval(checkInterval);
    server.close(() => {
      process.exit(1);
    });
  }
}, 500); 
