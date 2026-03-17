# Gas Profile Report

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork) via real transactions + `eth_estimateGas`. Gas prices calibrated at 350 Mgas/s.

## Summary

| Contract | Total Gas | Bottleneck |
|---|---|---|
| FalconVerifierDirectVerify | **98,570** | EVM execution (47%) + calldata (31%) |
| FalconVerifierNTTWithLpNorm | **98,570** | EVM execution (47%) + calldata (31%) |
| FalconVerifierNTT (on-chain norm) | **223,889** | EVM execution (77%) |
| DilithiumVerifierNTT (no UseHint) | **889,577** | EVM execution (60%) + calldata (38%) |

## FalconVerifierDirectVerify — 98,470 gas

Single STATICCALL to FALCON_VERIFY. The simplest possible verifier.

```
  Base tx              21,000   21.3%  ██████████
  Calldata (2.1 KB)    30,988   31.5%  ███████████████
  STATICCALL (1 cold)   2,600    2.6%  █
  Precompile            3,100    3.1%  █
  EVM opcodes          40,282   40.9%  ████████████████████
```

The actual Falcon-512 cryptography (SHAKE256 + NTT + multiply + norm) costs **3,100 gas** (3.1%). The rest is EVM overhead: `calldatacopy`, memory allocation, and the 21K base tx. Calldata (2.1 KB of signature + public key) costs 31K gas.

## FalconVerifierNTTWithLpNorm — 98,470 gas

Five precompile calls: SHAKE256 → NTT_FW → VECMULMOD → NTT_INV → LP_NORM.

```
  Base tx              21,000   21.3%  ██████████
  Calldata (2.1 KB)    30,988   31.5%  ███████████████
  STATICCALLs (5 cold) 13,000   13.2%  ██████
  Precompile exec      15,660   15.9%  ███████
  EVM opcodes          17,322   17.6%  ████████
```

Same total as DirectVerify because the precompile gas (15.7K) is offset by fewer EVM opcodes (no on-chain operations). The 5 cold STATICCALLs add 13K gas overhead.

**Precompile breakdown:**

| Call | Gas |
|---|---|
| NTT_FW (n=512) | 6,794 |
| NTT_INV (n=512) | 6,656 |
| VECMULMOD (n=512) | 1,324 |
| LP_NORM (n=512) | 712 |
| SHAKE256 | 174 |
| **Total** | **15,660** |

## DilithiumVerifierNTT — 1,255,363 gas

15 batched precompile calls with on-chain Decompose + UseHint.

```
  Base tx              21,000    1.7%
  Calldata (20 KB)    309,544   24.7%  ████████████
  STATICCALLs           13,900    1.1%
  Precompile exec      45,107    3.6%  █
  Memory (~100 KB)     50,000    4.0%  █
  EVM opcodes         815,812   65.0%  ████████████████████████████████
```

### Where the 1.25M gas goes

**1. EVM opcodes — 816K gas (65%)**

The on-chain UseHint loop dominates. For each of 4 polynomials × 256 coefficients:
- Read 3-byte coefficient from memory (3 `MLOAD` + shifts)
- `MOD`, `DIV`, `GT`, `MUL`, `ADD`, `SUB` for Decompose
- `CALLDATALOAD` for hint byte
- Conditional UseHint adjustment
- 6-bit packing: shifts, OR, `MSTORE8`

That's ~30 opcodes per coefficient × 1024 coefficients ≈ 30,000 opcodes. Plus the negation loop (1024 iterations × 10 opcodes) and memory gather/scatter for batching.

The 3-byte-per-coefficient encoding is particularly expensive in EVM — each read requires `byte(0, mload(pos))` with manual shifts instead of a single `MLOAD`.

**2. Calldata — 310K gas (25%)**

20,320 bytes of unpacked coefficients. At 16 gas per nonzero byte (average ~15.2 gas/byte), calldata alone costs 310K gas. The A matrix (12,288 bytes) is 60% of this.

**3. Precompile execution — 45K gas (3.6%)**

| Call | Count | Gas |
|---|---|---|
| NTT_FW (n=256) | 4 | 14,888 |
| NTT_INV (n=256) | 4 | 13,312 |
| VECMULMOD (n=4096) | 1 | 8,492 |
| VECMULMOD (n=1024) | 1 | 2,348 |
| VECADDMOD (n=2048) | 1 | 2,648 |
| VECADDMOD (n=1024) | 2 | 3,248 |
| SHAKE256 | 1 | 171 |
| **Total** | **14** | **45,107** |

The actual post-quantum cryptography costs 45K gas — **3.6%** of the total. The other 96.4% is EVM overhead.

## Optimization opportunities

| Optimization | Saves | New total | Effort |
|---|---|---|---|
| Dedicated DILITHIUM_VERIFY precompile | ~1.15M | ~100K | High (new precompile in Erigon) |
| Pack calldata to ML-DSA format | ~250K | ~1.0M | Medium (on-chain bit unpacking) |
| Move UseHint to a precompile | ~800K | ~450K | Medium (new precompile) |
| Reduce coefficients to 2 bytes | ~100K | ~1.15M | Low (truncate, loses generality) |

### The case for DILITHIUM_VERIFY

A single precompile (like FALCON_VERIFY at 0x17) that takes raw `pk(1312) | sig(2420) | msg(var)` would:

- Eliminate 815K gas of EVM opcodes (Decompose/UseHint/ExpandA done internally)
- Reduce calldata from 20KB to 3.7KB (saving 250K gas)
- Use 1 STATICCALL instead of 15 (saving 12K gas)
- Cache the twiddle table internally (like FALCON_VERIFY's `LazyLock`)

**Estimated total: ~100K gas** — matching Falcon, with the same 3% crypto / 97% overhead ratio.

## Conclusion

The NTT precompiles work correctly and are properly priced for the cryptographic work they do. But for Dilithium, the generic precompile approach hits a wall at **1.25M gas** because:

1. The 4×4 matrix structure requires 20KB of pre-expanded calldata
2. On-chain Decompose + UseHint in Yul costs 800K+ gas (3-byte coefficient reads, modular arithmetic in 256-bit EVM words)
3. These EVM costs are fundamental and can't be optimized away without a dedicated precompile

Falcon works well with generic precompiles (98K gas) because it's a single polynomial operation with 2KB calldata. Dilithium needs a dedicated precompile to reach parity.
