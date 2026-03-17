/// @title FalconVerifierNTTWithLpNorm — Falcon-512 verifier using NTT + LpNorm precompiles
/// Uses 0x12 (NTT_FW), 0x13 (NTT_INV), 0x14 (VECMULMOD), 0x16 (SHAKE),
///      0x18 (LP_NORM), 0x19 (VECSUBMOD)
/// Calldata: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)

object "FalconVerifierNTTWithLpNorm" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let smLen := sub(cd, 0x800)

            // Step 1: SHAKE256(salt_msg) → 1024 bytes hashed at mem[0xc00]
            mstore(0, 256)
            mstore(0x20, 1024)
            calldatacopy(0x40, 0x800, smLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x40, smLen), 0xc00, 0x400)) { revert(0,0) }

            // Step 2: NTT_FW(s2)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            calldatacopy(0x60, 0, 0x400)
            if iszero(staticcall(gas(), 0x12, 0, 0x460, 0, 0x400)) { revert(0,0) }

            // Step 3: VECMULMOD(NTT(s2), ntth)
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
            // s1 at mem[0x00..0x3ff]

            // Step 5: VECSUBMOD(hashed - s1) — replaces the 512-iteration on-chain loop
            // hashed at mem[0xc00], s1 at mem[0x00]
            mstore(0x1000, 512)        // n
            mstore(0x1020, 12289)      // q
            mcopy(0x1040, 0xc00, 0x400)         // a = hashed
            mcopy(0x1440, 0, 0x400)             // b = s1
            // n(32)|q(32)|a(1024)|b(1024) = 2112 = 0x840
            if iszero(staticcall(gas(), 0x19, 0x1000, 0x840, 0x1000, 0x400)) { revert(0,0) }
            // diff at mem[0x1000..0x13ff]

            // Step 6: LP_NORM(L2) on [diff, s2]
            mstore(0x1400, 12289)       // q
            mstore(0x1420, 512)         // n
            mstore(0x1440, 34034726)    // bound
            mstore(0x1460, 2)           // cb
            mstore(0x1480, 2)           // p = L2
            mstore(0x14a0, 2)           // count = 2
            mcopy(0x14c0, 0x1000, 0x400)        // diff
            calldatacopy(0x18c0, 0, 0x400)      // s2
            // 192 + 2×1024 = 2240 = 0x8c0
            if iszero(staticcall(gas(), 0x18, 0x1400, 0x8c0, 0, 0x20)) { revert(0,0) }

            return(0, 0x20)
        }
    }
}
