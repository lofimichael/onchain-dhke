import hre from "hardhat";
import fs from 'fs';
import crypto from 'crypto';

import { primehex, generator } from "../consts/contractconsts";

// run `npx hardhat node`
hre.run("node")

// deploy DHKE exchanger contract and output address to docker/address.txt
// @ts-ignore -- ethers *does* exist on the hardhat runtime environment
hre.ethers.deployContract("Exchanger", [generator, primehex]).then((result) => {
    console.log("Deployed!")
    result.getAddress().then((address) => {
        console.log("Contract address: " + address)
        console.log("Writing to docker dir...")
        fs.writeFileSync('docker/address.txt', address);
    })
    
}
);