/// @title FalconVerifierNTT — Falcon-512 verifier using generic NTT precompiles
/// Uses 0x12 (NTT_FW), 0x13 (NTT_INV), 0x14 (VECMULMOD), 0x16 (SHAKE256)
/// On-chain norm check loop.
/// Calldata: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)
///
/// Generic precompile format: n(32) | q(32) | [psi(32)] | coeffs

object "FalconVerifierNTT" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            // s2 = calldata[0..1024], ntth = calldata[1024..2048], salt_msg = calldata[2048..]
            let smLen := sub(cd, 0x800) // salt_msg length

            // ── Step 1: SHAKE256 hash-to-point ──
            // Build: outlen(32) | salt_msg
            // Output 1024 bytes (512×uint16 BE) to mem[0x800]
            mstore(0, 1024)
            calldatacopy(0x20, 0x800, smLen)
            let shakeInLen := add(0x20, smLen)
            if iszero(staticcall(gas(), 0x16, 0, shakeInLen, 0x800, 0x400)) { revert(0,0) }

            // ── Step 2: NTT_FW(s2) ──
            // Build: n(32) | q(32) | psi(32) | s2_coeffs(1024)
            mstore(0x00, 512)           // n = 512
            mstore(0x20, 12289)         // q = 12289
            mstore(0x40, 49)            // psi = 49
            calldatacopy(0x60, 0, 0x400) // s2 coefficients
            // Input: 96 + 1024 = 1120 bytes
            if iszero(staticcall(gas(), 0x12, 0, 0x460, 0, 0x400)) { revert(0,0) }
            // NTT(s2) now at mem[0x00..0x3ff]

            // ── Step 3: VECMULMOD(NTT(s2), ntth) ──
            // Build: n(32) | q(32) | a(1024) | b(1024)
            // Shift NTT(s2) to make room for header
            // Copy NTT(s2) from mem[0] to mem[0x40]
            mcopy(0x40, 0, 0x400)
            mstore(0x00, 512)            // n
            mstore(0x20, 12289)          // q
            // a = NTT(s2) at mem[0x40..0x43f]
            calldatacopy(0x440, 0x400, 0x400) // b = ntth from calldata
            // Input: 64 + 2048 = 2112 bytes
            if iszero(staticcall(gas(), 0x14, 0, 0x840, 0, 0x400)) { revert(0,0) }
            // Product at mem[0x00..0x3ff]

            // ── Step 4: NTT_INV(product) ──
            // Build: n(32) | q(32) | psi(32) | product(1024)
            mcopy(0x60, 0, 0x400)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            if iszero(staticcall(gas(), 0x13, 0, 0x460, 0, 0x400)) { revert(0,0) }
            // s1 at mem[0x00..0x3ff]

            // ── Step 5: Reload s2 to mem[0x400] ──
            calldatacopy(0x400, 0, 0x400)

            // ── Step 6: Norm check ──
            // s1 at mem[0x00], s2 at mem[0x400], hashed at mem[0x800]
            // All flat uint16 BE: coeff i at bytes [i*2, i*2+1]
            let norm := 0
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let off := mul(i, 2)
                // Read s1[i], hashed[i], s2[i] as uint16 BE
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
