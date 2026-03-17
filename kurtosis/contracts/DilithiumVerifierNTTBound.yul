/// @title DilithiumVerifierNTTBound — ML-DSA-44 verifier with pk bound at deploy
/// Constructor: rho(32) | t1_d_ntt(3072) | tr(64) = 3168 bytes
///
/// Verify calldata (3,904 + msg bytes):
///   z        (3072)  — 4 response polynomials
///   w1       (768)   — 6-bit packed UseHint result
///   c_tilde  (32)    — challenge seed
///   msg_len  (32)
///   msg      (var)
///
/// c_ntt derived on-chain: SHAKE256(c_tilde) → SampleInBall → NTT_FW
///
/// 11 precompile calls:
///   LP_NORM(L∞), 5×NTT_FW, EXPAND_A_VECMUL, VECMULMOD, VECSUBMOD, 2×SHAKE

object "DilithiumVerifierNTTBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        calldatacopy(rtSize, 0, 3168)
        return(0, add(rtSize, 3168))
    }
    object "runtime" {
        code {
            let Q       := 8380417
            let N       := 256
            let PSI     := 1753
            let CB      := 3
            let POLYSZ  := 768
            let K       := 4
            let L       := 4
            let POLY4   := 3072
            let TAU     := 39
            let APPENDED := 3168

            // Calldata offsets (no c_ntt — derived on-chain)
            let cdZ      := 0       // 3072
            let cdW1     := 3072    // 768
            let cdCT     := 3840    // 32
            let cdMsgLen := 3872    // 32
            let cdMsg    := 3904    // variable

            let codeOff := sub(codesize(), APPENDED)

            // Memory layout
            let mZntt   := 0x4000
            let mCntt   := 0x4C00   // c_ntt: 768 bytes (derived on-chain)
            let mAz     := 0x5000
            let mCt1d   := 0x5C40
            let mMu     := 0x6840

            // ── Step 1: LP_NORM(L∞) on z ──
            mstore(0, Q)
            mstore(0x20, N)
            mstore(0x40, sub(131072, 78))
            mstore(0x60, CB)
            mstore(0x80, 0xffffffffffffffff)
            mstore(0xa0, L)
            calldatacopy(0xc0, cdZ, POLY4)
            if iszero(staticcall(gas(), 0x18, 0, 0xCC0, 0, 0x20)) { revert(0,0) }
            if iszero(mload(0)) { revert(0, 0) }

            // ── Step 2: NTT_FW(z[j]) [4 calls] ──
            for { let j := 0 } lt(j, L) { j := add(j, 1) } {
                mstore(0, N)
                mstore(0x20, Q)
                mstore(0x40, PSI)
                calldatacopy(0x60, add(cdZ, mul(j, POLYSZ)), POLYSZ)
                if iszero(staticcall(gas(), 0x12, 0, 0x360, add(mZntt, mul(j, POLYSZ)), POLYSZ)) { revert(0,0) }
            }

            // ── Step 3: Derive c_ntt from c_tilde on-chain ──
            // 3a: SHAKE256(c_tilde, 272) → XOF output at mem[0x2000]
            mstore(0, 272)    // output_len
            calldatacopy(0x20, cdCT, 32)  // c_tilde
            if iszero(staticcall(gas(), 0x16, 0, 0x40, 0x2000, 0x110)) { revert(0,0) }
            // XOF at mem[0x2000..0x210f]

            // 3b: SampleInBall — 39-iteration Yul loop
            // signs = first 8 bytes LE, then sample indices
            // Build c polynomial (256 × 3 bytes) at mem[0x3000]
            // Zero it first
            for { let i := 0 } lt(i, 768) { i := add(i, 32) } {
                mstore(add(0x3000, i), 0)
            }

            let signs := mload(0x2000)  // first 32 bytes, signs in low 8 bytes
            // Extract 64-bit LE signs from first 8 bytes of XOF
            // signs byte layout at 0x2000: byte0=LSB ... byte7=MSB
            let signs64 := or(
                or(or(shl(0, byte(31, mload(0x2000))),
                      shl(8, byte(30, mload(0x2000)))),
                   or(shl(16, byte(29, mload(0x2000))),
                      shl(24, byte(28, mload(0x2000))))),
                or(or(shl(32, byte(27, mload(0x2000))),
                      shl(40, byte(26, mload(0x2000)))),
                   or(shl(48, byte(25, mload(0x2000))),
                      shl(56, byte(24, mload(0x2000))))))

            let xofPos := 8  // start after 8 sign bytes
            let signIdx := 0

            for { let i := sub(N, TAU) } lt(i, N) { i := add(i, 1) } {
                // Read j from XOF until j <= i
                let j := 0
                for {} true {} {
                    j := byte(0, mload(add(0x2000, xofPos)))
                    xofPos := add(xofPos, 1)
                    if iszero(gt(j, i)) { break }
                }

                // c[i] = c[j]
                let jOff := add(0x3000, mul(j, CB))
                let iOff := add(0x3000, mul(i, CB))
                mstore8(iOff, byte(0, mload(jOff)))
                mstore8(add(iOff, 1), byte(0, mload(add(jOff, 1))))
                mstore8(add(iOff, 2), byte(0, mload(add(jOff, 2))))

                // c[j] = 1 or q-1 based on sign bit
                let signBit := and(shr(signIdx, signs64), 1)
                signIdx := add(signIdx, 1)
                // if signBit=1: q-1 = 8380416 = 0x7FE001
                // if signBit=0: 1 = 0x000001
                let val := add(1, mul(signBit, sub(Q, 2)))  // 1 + signBit*(q-2) = 1 or q-1
                mstore8(jOff, and(shr(16, val), 0xff))
                mstore8(add(jOff, 1), and(shr(8, val), 0xff))
                mstore8(add(jOff, 2), and(val, 0xff))
            }

            // 3c: NTT_FW(c) → c_ntt at mCntt [1 call]
            mstore(0, N)
            mstore(0x20, Q)
            mstore(0x40, PSI)
            mcopy(0x60, 0x3000, POLYSZ)
            if iszero(staticcall(gas(), 0x12, 0, 0x360, mCntt, POLYSZ)) { revert(0,0) }

            // ── Step 4: EXPAND_A_VECMUL(rho, z_ntt) → Az ──
            mstore(0, Q)
            mstore(0x20, N)
            mstore(0x40, K)
            mstore(0x60, L)
            codecopy(0x80, codeOff, 32)
            mcopy(0xa0, mZntt, POLY4)
            if iszero(staticcall(gas(), 0x1a, 0, 0xCA0, mAz, POLY4)) { revert(0,0) }

            // ── Step 5: VECMULMOD c_ntt × t1d ──
            mstore(0, 0x400)
            mstore(0x20, Q)
            // c_ntt repeated 4×
            for { let rep := 0 } lt(rep, K) { rep := add(rep, 1) } {
                mcopy(add(0x40, mul(rep, POLYSZ)), mCntt, POLYSZ)
            }
            codecopy(add(0x40, POLY4), add(codeOff, 32), POLY4)
            if iszero(staticcall(gas(), 0x14, 0, 0x1840, mCt1d, POLY4)) { revert(0,0) }

            // ── Step 6: VECSUBMOD Az - ct1d ──
            mstore(sub(mAz, 0x40), 0x400)
            mstore(sub(mAz, 0x20), Q)
            if iszero(staticcall(gas(), 0x19, sub(mAz, 0x40), 0x1840, 0, POLY4)) { revert(0,0) }

            // ── Step 7: mu = SHAKE256(tr || 0x0000 || msg) ──
            let msgLen := calldataload(cdMsgLen)
            mstore(0, 64)
            codecopy(0x20, add(codeOff, 3104), 64)
            mstore8(0x60, 0)
            mstore8(0x61, 0)
            calldatacopy(0x62, cdMsg, msgLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x62, msgLen), mMu, 0x40)) { revert(0,0) }

            // ── Step 8: SHAKE256(mu || w1) == c_tilde ──
            mstore(0, 32)
            mcopy(0x20, mMu, 64)
            calldatacopy(0x60, cdW1, 768)
            if iszero(staticcall(gas(), 0x16, 0, 0x360, 0, 0x20)) { revert(0,0) }

            if iszero(eq(mload(0), calldataload(cdCT))) {
                mstore(0, 0)
                return(0, 32)
            }

            mstore(0, 1)
            return(0, 32)
        }
    }
}
