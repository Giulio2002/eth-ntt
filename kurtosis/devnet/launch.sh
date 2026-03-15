#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KURTOSIS_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$KURTOSIS_DIR")"
ERIGON_DIR="$REPO_ROOT/erigon"

echo "── Building custom Erigon Docker image with NTT precompiles..."
docker build -t erigon-ntt:latest "$ERIGON_DIR"

echo "── Launching Kurtosis devnet..."
kurtosis enclave rm -f falcon-devnet 2>/dev/null || true
kurtosis run --enclave falcon-devnet github.com/ethpandaops/ethereum-package \
    --args-file "$SCRIPT_DIR/network_params.yaml"

RPC=$(kurtosis port print falcon-devnet el-1-erigon-lighthouse ws-rpc 2>/dev/null)
echo ""
echo "── Devnet is running!"
echo "   RPC endpoint: http://$RPC"
echo ""
echo "   Run the fuzzer:"
echo "   RPC_URL=http://$RPC python3 $KURTOSIS_DIR/scripts/falcon_fuzz.py"
