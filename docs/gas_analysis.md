# Gas Analysis

Gas prices calibrated against wall-clock benchmarks on Apple M4, targeting **350 Mgas/s** throughput.

All measurements use Criterion `--release` (LTO, codegen-units=1). Each benchmark is the full precompile path: calldata decode, parameter validation, fast-path dispatch, compute, output encoding.

## Gas formulas

| Precompile | Address | Formula | Current | Notes |
|---|---|---|---|---|
| NTT_FW | `0x12` | `650 + 12n` | 600 | table construction + CT butterfly |
| NTT_INV | `0x13` | `13n` | 600 | table construction + GS butterfly |
| VECMULMOD | `0x14` | `300 + 2n` | variable | calldata decode + element-wise mul |
| VECADDMOD | `0x15` | `600 + n` | variable | calldata decode + element-wise add |
| SHAKE | `0x16` | `150 + 3 × ceil(len/rate)` | variable | rate=168 (N≤128) or 136 (N>128) |
| FALCON_VERIFY | `0x17` | `3100` | 2800 | hardcoded params, cached table |
| LP_NORM | `0x18` | `200 + n` | 400 | centered L2 norm check |

Where `n` is the polynomial dimension passed in calldata. For batched calls (concatenated vectors), `n` is the total element count.

## Gas by n

| n | NTT_FW | NTT_INV | VECMULMOD | VECADDMOD | LP_NORM |
|---|---:|---:|---:|---:|---:|
| 64 | 1,418 | 832 | 428 | 664 | 264 |
| 128 | 2,186 | 1,664 | 556 | 728 | 328 |
| 256 | 3,722 | 3,328 | 812 | 856 | 456 |
| 512 | 6,794 | 6,656 | 1,324 | 1,112 | 712 |
| 1,024 | 12,938 | 13,312 | 2,348 | 1,624 | 1,224 |
| 2,048 | 25,226 | 26,624 | 4,396 | 2,648 | 2,248 |
| 4,096 | 49,802 | 53,248 | 8,492 | 4,696 | 4,296 |

## Benchmark data

Precompile entry point timings (decode + compute):

| Precompile | Parameters | Time (µs) | Gas @ 350M | Current gas | Ratio |
|---|---|---|---|---|---|
| NTT_FW | Falcon n=512 | 19.1 | 6,700 | 600 | 0.09x |
| NTT_INV | Falcon n=512 | 19.2 | 6,700 | 600 | 0.09x |
| NTT_FW | Dilithium n=256 | 10.5 | 3,700 | 600 | 0.16x |
| NTT_INV | Dilithium n=256 | 9.6 | 3,350 | 600 | 0.18x |
| VECMULMOD | Falcon n=512 | 3.3 | 1,150 | 18 | 0.02x |
| VECADDMOD | Falcon n=512 | 3.1 | 1,100 | 9 | 0.01x |
| VECMULMOD | Dilithium n=256 | 2.1 | 750 | 18 | 0.02x |
| VECADDMOD | Dilithium n=256 | 2.4 | 850 | 9 | 0.01x |
| SHAKE-128 | 32B in → 168B out | 0.46 | 150 | 48 | 0.32x |
| SHAKE-256 | 32B in → 32B out | 0.39 | 150 | 48 | 0.32x |
| SHAKE-256 | 832B in → 32B out | 2.33 | 800 | 186 | 0.23x |
| FALCON_VERIFY | hardcoded | 8.9 | 3,100 | 2,800 | 0.90x |
| LP_NORM | Falcon n=512 | 2.0 | 700 | 400 | 0.57x |
| LP_NORM | Dilithium n=256 | 1.3 | 450 | 400 | 0.89x |

FALCON_VERIFY and LP_NORM are roughly correct. Everything else is 2–100x underpriced.

## Decode overhead

The NTT precompiles are expensive because they reconstruct the twiddle factor table from calldata on every call:

| Component | Falcon (µs) | Dilithium (µs) |
|---|---|---|
| Table construction | ~16 | ~9 |
| Actual NTT | ~3 | ~1.3 |
| **Total** | **~19** | **~10.5** |

Table construction is 85% of NTT cost. FALCON_VERIFY avoids this with a `LazyLock` static table. A (q, n, psi) cache in Erigon's precompile dispatcher would give the same benefit to the generic NTT precompiles.

## Dilithium verification cost (DilithiumVerifierNTT, 15 calls)

With corrected gas pricing:

| Step | Calls | Gas formula | Gas |
|---|---|---|---|
| 4 × NTT_FW(n=256) | 4 | 4 × (650 + 12×256) | 14,888 |
| 1 × VECMULMOD(n=4096) | 1 | 300 + 2×4096 | 8,492 |
| 1 × VECADDMOD(n=2048) | 1 | 600 + 2048 | 2,648 |
| 1 × VECADDMOD(n=1024) | 1 | 600 + 1024 | 1,624 |
| 1 × VECMULMOD(n=1024) | 1 | 300 + 2×1024 | 2,348 |
| 1 × VECADDMOD(n=1024) | 1 | 600 + 1024 | 1,624 |
| 4 × NTT_INV(n=256) | 4 | 4 × (13×256) | 13,312 |
| 1 × SHAKE(832B data) | 1 | 150 + 3×7 | 171 |
| **Precompile total** | **15** | | **45,107** |

Full transaction gas:

| Component | Gas |
|---|---|
| Base tx | 21,000 |
| Calldata (~20 KB) | ~60,000 |
| 5 cold + 10 warm STATICCALLs | 14,000 |
| On-chain UseHint (4 × 256 iter) | ~30,000 |
| Memory expansion + mcopy | ~7,000 |
| Precompile execution | ~45,000 |
| **Total** | **~177,000** |

## On-chain gas measurements (Kurtosis devnet)

Measured via `eth_estimateGas` on a live Erigon devnet (Osaka fork, `gas_benchmark.py`).

### Full contract verification

| Contract | Gas | Precompile calls | Calldata |
|---|---|---|---|
| FalconVerifierDirectVerify | 98,239 | 1 | 2.1 KB |
| FalconVerifierNTTWithLpNorm | 100,179 | 5 | 2.1 KB |
| FalconVerifierNTT | 225,081 | 4 | 2.1 KB |
| DilithiumVerifierNTT | 1,266,282 | 15 | 20 KB |

### Direct precompile calls

Total gas for a direct `eth_call` to a precompile address (includes 21K base tx + calldata + 2.6K cold STATICCALL):

| Precompile | n=256 | n=512 | n=1024 | n=4096 |
|---|---|---|---|---|
| NTT_FW | 30,170 | 32,677 | — | — |
| NTT_INV | 30,170 | 32,675 | — | — |
| VECMULMOD | 37,484 | 42,584 | 84,113 | 270,810 |
| VECADDMOD | 37,484 | 42,584 | 84,113 | 270,810 |

| Precompile | Gas |
|---|---|
| SHAKE256 (32B data) | 21,836 |
| SHAKE256 (832B data) | 30,020 |
| SHAKE256 (2KB data) | 42,204 |
| FALCON_VERIFY | 98,239 |
| LP_NORM (n=256) | 45,881 |
| LP_NORM (n=512) | 53,944 |

### Cost breakdown

For direct precompile calls, the precompile's own gas is a small fraction. Most cost is EVM overhead:

| Component | NTT_FW n=256 | FALCON_VERIFY |
|---|---|---|
| Base tx | 21,000 | 21,000 |
| Calldata | ~3,500 | ~33,000 |
| Cold STATICCALL | 2,600 | 2,600 |
| **Precompile gas** | **3,722** | **3,100** |
| **Total** | **~30,170** | **~98,239** |

The precompile gas (our formula) is 12% of the total for NTT and 3% for FALCON_VERIFY. Calldata dominates.

## Recommendations

1. **Reprice precompiles** using the formulas above. NTT and VEC are 10–100x underpriced. Implemented in Erigon at `execution/vm/contracts_ntt.go`.

2. **Cache twiddle tables** in Erigon's precompile dispatcher. Key on (q, n, psi), evict LRU. Eliminates ~9 µs per NTT call for repeated parameters.

3. **Add DILITHIUM_VERIFY precompile** (like FALCON_VERIFY). Takes raw pk + sig + msg (~3.7 KB instead of 20 KB calldata). Estimated ~100K gas total (dominated by calldata), vs 1.27M current.
