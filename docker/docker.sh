#!/bin/bash

# Function to check if Hardhat node is running
check_hardhat_node() {
    echo "Checking if Hardhat node is running at http://127.0.0.1:8545..."

    if curl --output /dev/null --silent --head --fail "http://127.0.0.1:8545"; then
        echo "Hardhat node is running."
    else
        echo "Error: Hardhat node is not running. Please start the Hardhat node in a separate terminal."
        exit 1
    fi
}

# Check if Hardhat node is running
check_hardhat_node

# Prune containers where DHKE_ROLE label exists (is not null)
# echo "Pruning Docker containers where DHKE_ROLE label is not null..."
# docker container prune --filter "label=DHKE_ROLE" -f

# Start Docker Compose
docker-compose up --build