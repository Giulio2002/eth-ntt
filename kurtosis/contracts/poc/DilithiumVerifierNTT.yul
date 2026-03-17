/// @title DilithiumVerifierNTT — ML-DSA-44 verifier using NTT precompiles
/// 10 precompile calls, ExpandA done inside precompile (no A matrix in calldata).
///
/// Calldata layout (9,109 bytes + msg):
///   rho      (32 bytes)     — public key seed (A derived internally via SHAKE128)
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
            let CB      := 3
            let POLYSZ  := 768
            let K       := 4
            let L       := 4
            let POLY4   := 3072

            // Calldata offsets (rho replaces A_ntt: 32 bytes instead of 12288)
            let cdRho    := 0        // 32
            let cdZ      := 32       // 3072
            let cdC      := 3104     // 768
            let cdT1D    := 3872     // 3072
            let cdW1     := 6944     // 768
            let cdCT     := 7712     // 32
            let cdPK     := 7744     // 1312
            let cdMsgLen := 9056     // 32
            let cdMsg    := 9088     // variable

            // Memory layout
            let mZntt   := 0x4000   // NTT(z): 3072
            let mAz     := 0x5000   // Az result: 3072
            let mCt1d   := 0x5C40   // ct1d: 3072 (right after Az for VECSUBMOD)
            let mMu     := 0x6840   // mu: 64

            // ── Step 1: LP_NORM(L∞) on z [1 call] ──
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

            // ── Step 3: EXPAND_A_VECMUL(rho, z_ntt) → Az [1 call] ──
            // Input: q(32)|n(32)|k(32)|l(32)|rho(32)|z_ntt(3072)
            mstore(0, Q)
            mstore(0x20, N)
            mstore(0x40, K)
            mstore(0x60, L)
            calldatacopy(0x80, cdRho, 32)           // rho from calldata (32 bytes!)
            mcopy(0xa0, mZntt, POLY4)               // z_ntt from memory
            // Total: 160 + 3072 = 3232 = 0xCA0
            if iszero(staticcall(gas(), 0x1a, 0, 0xCA0, mAz, POLY4)) { revert(0,0) }

            // ── Step 4: c×t1d [1 call] ──
            mstore(0, 0x400)
            mstore(0x20, Q)
            for { let rep := 0 } lt(rep, K) { rep := add(rep, 1) } {
                calldatacopy(add(0x40, mul(rep, POLYSZ)), cdC, POLYSZ)
            }
            calldatacopy(add(0x40, POLY4), cdT1D, POLY4)
            if iszero(staticcall(gas(), 0x14, 0, 0x1840, mCt1d, POLY4)) { revert(0,0) }

            // ── Step 5: VECSUBMOD Az - ct1d [1 call] ──
            // Az at mAz, ct1d at mCt1d — write header just before mAz
            mstore(sub(mAz, 0x40), 0x400)
            mstore(sub(mAz, 0x20), Q)
            // Input starts at mAz-64, length = 64 + 3072 + 3072 = 6208
            if iszero(staticcall(gas(), 0x19, sub(mAz, 0x40), 0x1840, 0, POLY4)) { revert(0,0) }

            // ── Step 6: Compute mu [2 SHAKE calls] ──
            mstore(0, 64)
            calldatacopy(0x20, cdPK, 1312)
            if iszero(staticcall(gas(), 0x16, 0, 0x540, mMu, 0x40)) { revert(0,0) }

            let msgLen := calldataload(cdMsgLen)
            mstore(0, 64)
            mcopy(0x20, mMu, 64)
            mstore8(0x60, 0)
            mstore8(0x61, 0)
            calldatacopy(0x62, cdMsg, msgLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x62, msgLen), mMu, 0x40)) { revert(0,0) }

            // ── Step 7: SHAKE256(mu || w1) == c_tilde [1 SHAKE call] ──
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
