#!/bin/bash
# blockchain/network/start-eth.sh
# Break-glass Scenario 1: Private Ethereum network with Hardhat.
# Use this if Fabric is not working by end of week 5.
# Record the switch in docs/decisions/ledger-platform.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETH_DIR="$SCRIPT_DIR/../ethereum"

echo "=== Evidence Guard – Ethereum Fallback Network (Hardhat) ==="
echo ""
echo "BREAK-GLASS: This fallback is used when Fabric is blocked."
echo "Record what is lost (channels, private data collections, MSP identities)"
echo "in docs/decisions/ledger-platform.md"
echo ""

# Check for Node.js
if ! command -v node &> /dev/null; then
  echo "ERROR: Node.js is required for Hardhat. Install it first."
  exit 1
fi

mkdir -p "$ETH_DIR"
cd "$ETH_DIR"

if [ ! -f "package.json" ]; then
  echo "Initialising Hardhat project..."
  npm init -y --quiet
  npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
  npx hardhat init --typescript
fi

echo "Starting Hardhat local node..."
npx hardhat node --port 8545 &
HARDHAT_PID=$!
echo "Hardhat node PID: $HARDHAT_PID (port 8545)"

sleep 3
echo "Deploying Evidence Guard contract..."
npx hardhat run scripts/deploy.ts --network localhost

echo ""
echo "✅ Ethereum fallback network is up."
echo "   RPC: http://localhost:8545"
echo "   Set in .env: LEDGER_PLATFORM=ethereum, ETH_RPC_URL=http://localhost:8545"
echo ""
echo "The LedgerClient interface does not change – only the implementation class is swapped."
