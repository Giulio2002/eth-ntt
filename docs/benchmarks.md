# Benchmarks

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork). 16,090 fuzz iterations, 0 failures.

## Transaction cost

Total gas charged to the sender, including base tx fee, calldata, and execution.

| Contract | Verify Gas | Runtime Size | Deploy Gas |
|---|---|---|---|
| FalconVerifierNTT | 210,261 | 322 B | 122,572 |
| FalconVerifierNTTWithLpNorm | 210,261 | 322 B | 122,572 |
| FalconVerifierDirectVerify | 98,750 | 25 B | 58,586 |

All three take the same calldata: `s2(1024) | ntth(1024) | salt_msg(~69)` = 2,117 bytes.

## Verification cost

Gas spent on the actual signature verification, excluding base tx (21,000) and calldata intrinsic (~31,100).

| Contract | Execution Gas | Precompile Gas | On-chain norm | EVM overhead | Crypto % |
|---|---|---|---|---|---|
| FalconVerifierNTT | 158,161 | 1,266 (4 calls) | ~100,000 | ~56,895 | 0.8% |
| FalconVerifierNTTWithLpNorm | 158,161 | 1,266 (4 calls) | ~100,000 | ~56,895 | 0.8% |
| FalconVerifierDirectVerify | 46,650 | 2,800 (1 call) | 0 | ~43,850 | 6.0% |

*Execution Gas = Verify Gas - base tx (21,000) - calldata intrinsic (~31,100)*
*Crypto % = Precompile Gas / Execution Gas*

### What limits each contract

- **FalconVerifierNTT / NTTWithLpNorm**: The on-chain norm loop (512 iterations of `mod` + `mul` + `add`) costs ~100k gas. This is pure EVM interpreter overhead — the same math takes 1 microsecond in Rust.

- **FalconVerifierDirectVerify**: No on-chain computation. The 43k "EVM overhead" is almost entirely cold address access (2,600) + memory expansion (~200) + the calldata intrinsic being double-counted in the execution trace. The contract itself executes 3 EVM opcodes.

### Fixed costs (same for all contracts)

| Cost | Gas | Why |
|---|---|---|
| Base transaction | 21,000 | EIP-2718, every tx pays this |
| Calldata (2,117 bytes) | ~31,100 | 16 gas/nonzero byte, 4 gas/zero byte |
| **Total fixed** | **~52,100** | **Cannot be reduced** |

## Comparison

| Scheme | Gas | Precompile | Post-quantum |
|---|---|---|---|
| ECDSA recovery | 3,000 | ecrecover (0x01) | No |
| **Falcon-512** | **2,800** | **FALCON_VERIFY (0x17)** | **Yes** |
| BLS12-381 pairing | 43,000 | 0x0f | No |
| Falcon-512 (NTT contract) | 210,261 | 0x12-0x16 | Yes |
| Falcon-512 (DirectVerify tx) | 98,750 | 0x17 | Yes |
