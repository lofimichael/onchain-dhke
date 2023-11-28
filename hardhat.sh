#!/bin/bash 
echo "generating abi from foundry artifacts via wagmi"
npx wagmi generate

INSTANCES=3

# echo "compiling hardhat contract for npx hardhat node deployment"
# npx hardhat compile --force
# wait 

echo "generating docker env via envgen.ts"
cd ./docker && npx ts-node ./envgen.ts $INSTANCES

cd ..

echo "running hardhat task: run.ts"
ts-node ./tasks/run.ts

