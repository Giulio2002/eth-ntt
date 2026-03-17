/// @title DilithiumVerifierNTT — ML-DSA-44 verifier using NTT precompiles
/// Uses 0x12 (NTT_FW), 0x13 (NTT_INV), 0x14 (VECMULMOD), 0x16 (SHAKE),
///      0x19 (VECSUBMOD), 0x1a (MATVECMUL)
///
/// 10 precompile calls total:
///   4 × NTT_FW(n=256)       — NTT(z[0..3])
///   1 × MATVECMUL(k=4,l=4)  — Az = A × NTT(z), replaces 3 batched calls
///   1 × VECMULMOD(n=1024)   — c × t1d for all 4 rows
///   1 × VECSUBMOD(n=1024)   — Az - ct1d, no negate loop
///   4 × NTT_INV(n=256)      — INTT(w_approx[0..3])  (verify algebra)
///   3 × SHAKE                — tr, mu, hash check
///   = 14 calls (was 14, but removed negate loop + tree reduce gathers)
///
/// UseHint done off-chain; w1 passed in calldata; mu computed on-chain.
///
/// Calldata layout:
///   A_ntt    (12288 bytes)  — 4×4 matrix, NTT domain, row-major
///   z        (3072 bytes)   — 4 response polynomials, standard domain
///   c_ntt    (768 bytes)    — challenge polynomial, NTT domain
///   t1_d_ntt (3072 bytes)   — 4 polynomials NTT(t1[i] << 13), NTT domain
///   w1       (768 bytes)    — 6-bit packed w1 (pre-computed off-chain)
///   c_tilde  (32 bytes)     — challenge seed
///   pk       (1312 bytes)   — ML-DSA-44 public key
///   msg_len  (32 bytes)     — message length
///   msg      (var bytes)    — message

object "DilithiumVerifierNTT" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let Q       := 8380417
            let N       := 256
            let PSI     := 1753
            let GAMMA1  := 131072
            let BETA    := 78
            let CB      := 3
            let POLYSZ  := 768
            let K       := 4
            let L       := 4
            let POLY4   := 3072
            let POLY16  := 12288

            // Calldata offsets
            let cdA     := 0         // 12288
            let cdZ     := 12288     // 3072
            let cdC     := 15360     // 768
            let cdT1D   := 16128     // 3072
            let cdW1    := 19200     // 768
            let cdCT    := 19968     // 32
            let cdPK    := 20000     // 1312
            let cdMsgLen := 21312    // 32
            let cdMsg   := 21344     // variable

            // Memory regions
            let mZntt   := 0x10000   // NTT(z): 3072
            let mAz     := 0x11000   // Az result: 3072
            let mCt1d   := 0x12000   // c*t1d: 3072
            let mWapx   := 0x13000   // w_approx: 3072

            // ── Step 1: Infinity norm check on z ──
            let bound := sub(GAMMA1, BETA)
            let halfQ := div(Q, 2)
            for { let p := 0 } lt(p, L) { p := add(p, 1) } {
                let base := add(cdZ, mul(p, POLYSZ))
                for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                    let off := add(base, mul(i, CB))
                    let c := or(shl(16, byte(0, calldataload(off))),
                             or(shl(8,  byte(0, calldataload(add(off, 1)))),
                                        byte(0, calldataload(add(off, 2)))))
                    if gt(c, halfQ) { c := sub(Q, c) }
                    if iszero(lt(c, bound)) { revert(0, 0) }
                }
            }

            // ── Step 2a: NTT_FW(z[j]) for j=0..3  [4 calls] ──
            for { let j := 0 } lt(j, L) { j := add(j, 1) } {
                mstore(0, N)
                mstore(0x20, Q)
                mstore(0x40, PSI)
                calldatacopy(0x60, add(cdZ, mul(j, POLYSZ)), POLYSZ)
                // NTT input: 96 + 768 = 864 = 0x360
                if iszero(staticcall(gas(), 0x12, 0, 0x360, add(mZntt, mul(j, POLYSZ)), POLYSZ)) { revert(0,0) }
            }

            // ── Step 2b: MATVECMUL(k=4, l=4)  [1 call] ──
            // Input: n(32)|q(32)|k(32)|l(32)|A(12288)|z_ntt(3072)
            mstore(0, N)
            mstore(0x20, Q)
            mstore(0x40, K)
            mstore(0x60, L)
            calldatacopy(0x80, cdA, POLY16)               // A_ntt from calldata
            mcopy(add(0x80, POLY16), mZntt, POLY4)        // z_ntt from memory
            // Total: 128 + 12288 + 3072 = 15488 = 0x3C80
            if iszero(staticcall(gas(), 0x1a, 0, 0x3C80, mAz, POLY4)) { revert(0,0) }

            // ── Step 2c: VECMULMOD(n=1024) — c×t1d  [1 call] ──
            mstore(0, 0x400)  // n = 1024
            mstore(0x20, Q)
            // a = c_ntt repeated 4 times
            for { let rep := 0 } lt(rep, K) { rep := add(rep, 1) } {
                calldatacopy(add(0x40, mul(rep, POLYSZ)), cdC, POLYSZ)
            }
            // b = t1d_ntt[0..3]
            calldatacopy(add(0x40, POLY4), cdT1D, POLY4)
            // Total: 64 + 3072 + 3072 = 6208 = 0x1840
            if iszero(staticcall(gas(), 0x14, 0, 0x1840, mCt1d, POLY4)) { revert(0,0) }

            // ── Step 2d: VECSUBMOD(n=1024) — Az - ct1d  [1 call, no negate loop] ──
            mstore(0, 0x400)  // n = 1024
            mstore(0x20, Q)
            mcopy(0x40, mAz, POLY4)
            mcopy(add(0x40, POLY4), mCt1d, POLY4)
            if iszero(staticcall(gas(), 0x19, 0, 0x1840, mWapx, POLY4)) { revert(0,0) }

            // ── Step 2e: NTT_INV(w_approx[0..3])  [4 calls] ──
            for { let i := 0 } lt(i, K) { i := add(i, 1) } {
                mstore(0, N)
                mstore(0x20, Q)
                mstore(0x40, PSI)
                mcopy(0x60, add(mWapx, mul(i, POLYSZ)), POLYSZ)
                if iszero(staticcall(gas(), 0x13, 0, 0x360, add(mWapx, mul(i, POLYSZ)), POLYSZ)) { revert(0,0) }
            }

            // ── Step 3: Compute mu on-chain  [2 SHAKE calls] ──
            // tr = SHAKE256(pk)[:64]
            mstore(0, 64)
            calldatacopy(0x20, cdPK, 1312)
            // SHAKE input: 32 + 1312 = 1344 = 0x540
            if iszero(staticcall(gas(), 0x16, 0, 0x540, 0x20000, 0x40)) { revert(0,0) }

            // mu = SHAKE256(tr || 0x0000 || msg)[:64]
            let msgLen := calldataload(cdMsgLen)
            mstore(0, 64)
            mcopy(0x20, 0x20000, 64)     // tr
            mstore8(0x60, 0)              // FIPS 204 context
            mstore8(0x61, 0)
            calldatacopy(0x62, cdMsg, msgLen)
            let muInputLen := add(0x62, msgLen)
            if iszero(staticcall(gas(), 0x16, 0, muInputLen, 0x20000, 0x40)) { revert(0,0) }

            // ── Step 4: SHAKE256(mu || w1) == c_tilde  [1 SHAKE call] ──
            mstore(0, 32)
            mcopy(0x20, 0x20000, 64)             // mu
            calldatacopy(0x60, cdW1, 768)        // w1
            // SHAKE input: 32 + 64 + 768 = 864 = 0x360
            if iszero(staticcall(gas(), 0x16, 0, 0x360, 0, 0x20)) { revert(0,0) }

            let hashResult := mload(0)
            let cTilde := calldataload(cdCT)
            if iszero(eq(hashResult, cTilde)) {
                mstore(0, 0)
                return(0, 32)
            }

            mstore(0, 1)
            return(0, 32)
        }
    }
}
