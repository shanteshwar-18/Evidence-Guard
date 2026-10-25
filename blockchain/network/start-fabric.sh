#!/bin/bash
# blockchain/network/start-fabric.sh
# Starts the Hyperledger Fabric test network for Evidence Guard.
# Time-box: spend max 4 hours on this. If not working by end of week 5,
# switch to Ethereum fallback (start-eth.sh) and record in docs/decisions/ledger-platform.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Evidence Guard – Fabric Test Network ==="

# Check for fabric-samples
if [ ! -d "$SCRIPT_DIR/fabric-samples" ]; then
  echo "Downloading Fabric binaries and samples (this may take a few minutes)..."
  curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.6 1.5.9
fi

cd "$SCRIPT_DIR/fabric-samples/test-network"

echo "Bringing down any existing network..."
./network.sh down

echo "Starting Fabric test network with channel 'evidence-channel'..."
./network.sh up createChannel -c evidence-channel -ca

echo "Deploying Evidence Guard chaincode..."
./network.sh deployCC -c evidence-channel \
  -ccn evidence-chaincode \
  -ccp "$SCRIPT_DIR/../chaincode" \
  -ccl go

echo ""
echo "✅ Fabric network is up. Channel: evidence-channel"
echo "   Peer0.Org1: localhost:7051"
echo "   Peer0.Org2: localhost:9051"
echo "   Orderer:    localhost:7050"
echo ""
echo "Next: set LEDGER_PLATFORM=fabric in .env and restart the backend."
