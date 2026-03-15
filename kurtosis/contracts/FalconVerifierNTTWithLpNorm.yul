/// @title FalconVerifierNTTWithLpNorm — Falcon-512 verifier using generic precompiles
/// Uses 0x12 (NTT_FW), 0x13 (NTT_INV), 0x14 (VECMULMOD), 0x16 (SHAKE256)
/// Compact norm loop (no unrolling).
/// Calldata: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)
///
/// NOTE: The LpNorm precompile is available via the Rust API but not assigned
/// a dedicated EVM address in the current 6-precompile set. If assigned,
/// the norm loop below would be replaced with a single staticcall.

object "FalconVerifierNTTWithLpNorm" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let smLen := sub(cd, 0x800)

            // Step 1: SHAKE256(salt_msg) → 1024 bytes hashed at mem[0x800]
            mstore(0, 1024)
            calldatacopy(0x20, 0x800, smLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x20, smLen), 0x800, 0x400)) { revert(0,0) }

            // Step 2: NTT_FW(s2) — header: n(32)|q(32)|psi(32) + coeffs(1024)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            calldatacopy(0x60, 0, 0x400)
            if iszero(staticcall(gas(), 0x12, 0, 0x460, 0, 0x400)) { revert(0,0) }

            // Step 3: VECMULMOD(NTT(s2), ntth) — header: n(32)|q(32) + a(1024) + b(1024)
            mcopy(0x40, 0, 0x400)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            calldatacopy(0x440, 0x400, 0x400)
            if iszero(staticcall(gas(), 0x14, 0, 0x840, 0, 0x400)) { revert(0,0) }

            // Step 4: NTT_INV(product)
            mcopy(0x60, 0, 0x400)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            if iszero(staticcall(gas(), 0x13, 0, 0x460, 0, 0x400)) { revert(0,0) }

            // Reload s2
            calldatacopy(0x400, 0, 0x400)

            // Step 5: Norm check — s1 at mem[0], s2 at mem[0x400], hashed at mem[0x800]
            let norm := 0
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let off := mul(i, 2)
                let s1i := or(shl(8, byte(0, mload(add(off, 0)))),     byte(0, mload(add(off, 1))))
                let hi  := or(shl(8, byte(0, mload(add(off, 0x800)))), byte(0, mload(add(off, 0x801))))
                let s2i := or(shl(8, byte(0, mload(add(off, 0x400)))), byte(0, mload(add(off, 0x401))))

                let d := mod(add(hi, sub(12289, s1i)), 12289)
                if gt(d, 6144) { d := sub(12289, d) }
                if gt(s2i, 6144) { s2i := sub(12289, s2i) }
                norm := add(norm, add(mul(d, d), mul(s2i, s2i)))
            }

            mstore(0, lt(norm, 34034726))
            return(0, 32)
        }
    }
}
