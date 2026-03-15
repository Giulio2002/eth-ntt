# Kurtosis Devnet + Falcon-512 Verification

End-to-end Falcon-512 post-quantum signature verification on Ethereum using NTT precompiles, running on a local Kurtosis devnet with custom Erigon.

## Architecture

```
                Python fuzzer
                    │
                    ▼ (eth_call / eth_sendRawTransaction)
            ┌───────────────┐
            │  Kurtosis EL  │  Custom Erigon with precompiles:
            │  (Erigon)     │  0x12-0x15: generic NTT/VEC/ADD
            │               │  0x17-0x1a: Falcon-512 compact format
            │               │  0x1b: LpNorm (generalized lattice norm)
            └───────┬───────┘
                    │ staticcall
                    ▼
            ┌───────────────┐
            │  Yul V4       │  116 bytes runtime
            │  (on-chain)   │  5 precompile calls, ~98k gas
            └───────────────┘
```

## Prerequisites

- Docker
- [Kurtosis CLI](https://docs.kurtosis.com/install/)
- Python 3.10+ with: `pip install web3 py-solc-x pqcrypto eth-abi`
- Solidity compiler: `pip install solc-select && solc-select install 0.8.26 && solc-select use 0.8.26`
- Erigon source at `../erigon/` (clone from https://github.com/erigontech/erigon)

## Quick Start

### 1. Launch the devnet

```bash
cd kurtosis/devnet
bash launch.sh
```

This builds a custom Erigon Docker image with NTT precompiles and starts a Kurtosis enclave with Lighthouse CL + Erigon EL, Osaka fork active at genesis.

### 2. Run the fuzzer

```bash
RPC_URL=http://127.0.0.1:<PORT> python3 kurtosis/scripts/falcon_fuzz.py
```

The fuzzer:
- Deploys both a Solidity oracle (ZKNOX_falcon) and the Yul V4 contract
- Generates random Falcon-512 keypairs and signatures
- **First byte of fuzz input even** → invalid signature (wrong msg / corrupted s2 / wrong key)
- **First byte odd** → valid signature
- Cross-checks Solidity oracle vs Yul V4 vs Python reference
- Runs at ~87 iterations/sec via `eth_call`

### 3. Run the demo

```bash
RPC_URL=http://127.0.0.1:<PORT> python3 kurtosis/scripts/falcon_demo.py
```

Deploys the ZKNOX_falcon Solidity contract, signs messages with pqcrypto, verifies on-chain.

## Contracts

| Contract | File | Gas | Runtime |
|---|---|---|---|
| FalconVerifierV4 | `contracts/FalconVerifierV4.yul` | **98k** | 116B |
| FalconVerifierV3 | `contracts/FalconVerifierV3.yul` | 180k | 266B |
| ZKNOX_falcon (Solidity) | `contracts/ZKNOX_falcon.sol` | 209k | 1.4KB |

## Precompiles

| Address | Name | Input | Output | Gas |
|---|---|---|---|---|
| 0x12 | NTT_FW | generic calldata | raw coefficients | 600 |
| 0x13 | NTT_INV | generic calldata | raw coefficients | 600 |
| 0x14 | VECMULMOD | generic calldata | raw coefficients | 18 |
| 0x17 | NTT_FW_COMPACT | 1024B compact | 1024B compact | 600 |
| 0x18 | NTT_INV_COMPACT | 1024B compact | 1024B compact | 600 |
| 0x19 | VECMULMOD_COMPACT | 2048B compact | 1024B compact | 18 |
| 0x1a | SHAKE256_HTP | salt\|\|msg | 1024B compact | ~50 |
| 0x1b | LpNorm | s1\|\|s2\|\|hashed (3072B) | 32B bool | 100 |

**Compact format**: 32 big-endian uint256 words, each packing 16 little-endian uint16 coefficients.

## Gas Breakdown (V4, 98k total)

| Component | Gas | % |
|---|---|---|
| Base tx | 21,000 | 21% |
| Calldata (2.1KB) | 30,632 | 31% |
| 5x cold STATICCALL | 13,000 | 13% |
| Precompile execution | 1,366 | 1.4% |
| EVM overhead | ~32,572 | 33% |

The actual cryptography (NTT + SHAKE256 + norm check) is **1.4%** of total gas.

## Tear Down

```bash
kurtosis enclave rm -f falcon-devnet
```
