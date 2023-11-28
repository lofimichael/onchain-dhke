# <h1 align="center"> On-Chain Diffie Hellman Key Exchange </h1>

### Overview

This is a repository containing an implementation of [Diffie-Hellman Key Exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) payload messenging over blockchain.

Docker containers act as isolated user agents interacting with a Hardhat node running on the host device, sending and receiving data payloads. 

Individual container endpoints exist for publishing and retrieving payloads (defined in `/docker/app.ts`).

Payloads published on-chain by one container are received/listened-to by all other containers, but only the intended recipient of the container (designated by `PARTNER_ADDRESS` in `docker-compose.yml`) can decrypt the payload. 

Files are uploaded via multiform data (using multer Express middleware), chunked to 1024 bytes (default), and sent in order to the recipient. The recipient then decrypts the payload and saves it to disk. Comments on this are elaborated-upon in `UserAgent.ts`. Payloads can be verified by observing the `uploads` directory of the sending container and the `received` directory of the receiving container, as well as the logs.

### Installation of Dependencies

* Make sure you have [NodeJS](https://nodejs.org/en/), [Hardhat](https://hardhat.org/hardhat-runner/docs/getting-started#installation), [Foundry](https://book.getfoundry.sh/getting-started/installation), and [Docker](https://docs.docker.com/desktop/) installed. You should be able to run `npm`, `npx hardhat`, `forge`, and `docker` in your terminal.

--------

### Getting Started

```bash
# Install NPM dependencies
npm install

# Build Solidty contracts in ./src
forge build

# Optional: test Solidity contracts in ./test
forge test

# Build Hardhat artifacts from Forge
npx hardhat compile

# Run Hardhat node in one terminal
./hardhat.sh

# Run Docker sevices in another terminal
cd docker && ./docker.sh
```
--------

### Usage

Call locally-running Docker container endpoints as defined in `app.ts`.

### Considerations

This is a proof-of-concept implementation of Diffie-Hellman Key Exchange over blockchain using Docker containers for full isolation. It is not *currently* intended for production use, as full files are sent and stored on-chain. Files themselves are encrypted using AES-256-CBC.

[Kyber](https://github.com/fisherstevenk/crystals-kyber-ts), a quantum-resistant cryptography scheme, is a potential future candidate for use to ensure that transmitted files/symlinks are not decrypted, even if the underlying blockchain is compromised.

In the future, symlinks to encrypted payloads can be sent instead of full files, and the data can be stored off-chain in a distributed file system (IPFS, etc.) for more efficient storage and communication. This way, egress of data can be measured in regulated environments. User agents defined here are done to simulate behaviour, and in real-world applications can be any arbitrary user agent (mobile, web, etc.).

### License
MIT

