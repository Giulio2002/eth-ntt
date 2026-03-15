# Precompile API Reference

## Formats

### Raw format (generic)
Coefficients encoded as variable-length big-endian bytes with explicit headers specifying field parameters (q, n, psi). Works with any field.

### Compact format (Falcon-512 specific)
1024 bytes = 32 big-endian uint256 words. Each word packs 16 little-endian uint16 coefficients:

```
word[i] = coeff[0] | (coeff[1] << 16) | ... | (coeff[15] << 240)
```

Stored big-endian in memory (EVM native). Field params hardcoded: q=12289, n=512, psi=49.

---

## Generic Precompiles

### `0x12` — NTT_FW (Forward NTT)

**Input:**
```
q_len    (32 bytes BE)   — byte length of q
psi_len  (32 bytes BE)   — byte length of psi
n        (32 bytes BE)   — polynomial dimension
q        (q_len bytes)   — prime modulus, big-endian
psi      (psi_len bytes) — primitive 2n-th root of unity mod q
coeffs   (n × cb bytes)  — coefficients, big-endian (cb = ceil(bits(q)/8))
```

**Output:** `n × cb` bytes — NTT-transformed coefficients, big-endian.

**Gas:** 600

---

### `0x13` — NTT_INV (Inverse NTT)

Same input/output format as `0x12`. Computes the inverse NTT with scaling by n⁻¹ mod q.

**Gas:** 600

---

### `0x14` — VECMULMOD (Vector Modular Multiply)

**Input:**
```
q_len  (32 bytes BE)
n      (32 bytes BE)
q      (q_len bytes)
a      (n × cb bytes)   — first vector
b      (n × cb bytes)   — second vector
```

**Output:** `n × cb` bytes — `a[i] × b[i] mod q` for each i.

**Gas:** `k × log2(n) / 8` where k = next_power_of_two(bits(q))

---

### `0x15` — VECADDMOD (Vector Modular Add)

Same format as `0x14`. Computes `a[i] + b[i] mod q`.

**Gas:** `k × log2(n) / 32`

---

### `0x16` — SHAKE256

**Input:**
```
output_len  (32 bytes BE)  — desired output length
data        (var bytes)    — data to hash
```

**Output:** `output_len` bytes of SHAKE256(data).

**Gas:** `30 + 6 × ceil(len(data) / 32)` (same as KECCAK256)

---

## Falcon-512 Compact Precompiles

### `0x17` — NTT_FW_COMPACT

**Input:** 1024 bytes (compact format)

**Output:** 1024 bytes (compact format) — forward NTT of input.

**Gas:** 1000

---

### `0x18` — NTT_INV_COMPACT

**Input:** 1024 bytes (compact format)

**Output:** 1024 bytes (compact format) — inverse NTT of input.

**Gas:** 1000

---

### `0x19` — VECMULMOD_COMPACT

**Input:** 2048 bytes — two compact vectors concatenated: `a(1024) || b(1024)`

**Output:** 1024 bytes (compact format) — `a[i] × b[i] mod 12289`.

**Gas:** 200

---

### `0x1a` — SHAKE256_HTP (Hash-to-Point)

**Input:** `salt || message` (variable length, typically 40+ bytes)

**Output:** 1024 bytes (compact format) — 512 coefficients mod 12289 via SHAKE256 rejection sampling (threshold 61445).

**Gas:** `30 + 6 × ceil(input_len / 32)`

---

### `0x1b` — FALCON_NORM (LpNorm)

**Input:** 3072 bytes — three compact vectors: `s1(1024) || s2(1024) || hashed(1024)`

**Output:** 32 bytes — `0x00..01` if `||(hashed - s1) mod q||² + ||s2||² < 34034726`, else `0x00..00`.

**Gas:** 400

---

### `0x1c` — FALCON_VERIFY (v1)

Full Falcon-512 signature verification: SHAKE256 hash-to-point + NTT + pointwise multiply + inverse NTT + norm check.

**Input:**
```
salt_msg_len  (32 bytes BE) — length of salt||message
s2_compact    (1024 bytes)  — signature component (compact)
ntth_compact  (1024 bytes)  — public key in NTT domain (compact)
salt_msg      (var bytes)   — salt || message
```

**Output:** 32 bytes — `0x00..01` if valid, `0x00..00` if invalid.

**Gas:** 2800

---

### `0x1d` — FALCON_VERIFY_V2 (zero-copy)

Same as `0x1c` but with a simpler layout — no length header.

**Input:**
```
s2_compact    (1024 bytes)  — signature component (compact)
ntth_compact  (1024 bytes)  — public key in NTT domain (compact)
salt_msg      (var bytes)   — salt || message (remainder of input)
```

**Output:** 32 bytes — `0x00..01` if valid, `0x00..00` if invalid.

**Gas:** 2800

---

## Generalized Precompile

### LpNorm (via Rust API, not yet assigned an address)

Centered L2 norm check for any lattice-based signature scheme.

**Input:**
```
q      (32 bytes BE) — field modulus
n      (32 bytes BE) — dimension
bound  (32 bytes BE) — squared norm bound
cb     (32 bytes BE) — coefficient byte width (2 for Falcon, 4 for Dilithium)
s1     (n × cb bytes, BE) — first component
s2     (n × cb bytes, BE) — second component
hashed (n × cb bytes, BE) — hash-to-point result
```

**Output:** 32 bytes — `0x00..01` if `||(hashed - s1) mod q||² + ||s2||² < bound`, else `0x00..00`.

---

## Benchmarks (Apple M4, Rust native)

| Precompile | Time | Gas (350 Mgas/s) |
|---|---|---|
| NTT_FW_COMPACT | 2.8 µs | 1000 |
| NTT_INV_COMPACT | 2.8 µs | 1000 |
| VECMULMOD_COMPACT | 590 ns | 200 |
| SHAKE256_HTP | 1.8 µs | 600 |
| FALCON_NORM | 1.0 µs | 400 |
| **FALCON_VERIFY** | **8.1 µs** | **2800** |
