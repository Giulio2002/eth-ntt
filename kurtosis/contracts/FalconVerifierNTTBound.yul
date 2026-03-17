/// @title FalconVerifierNTTBound — Falcon-512 verifier with pk bound at deploy
/// Constructor: receives ntth (1024 bytes) as calldata, appends to runtime code.
/// Verify calldata: s2(1024) | salt_msg(var)
/// Uses SHAKE256 (0x16), NTT_FW (0x12), VECMULMOD (0x14), NTT_INV (0x13), LP_NORM (0x18)

object "FalconVerifierNTTBound" {
    code {
        // Constructor: deploy runtime + appended ntth
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        // Append ntth from constructor calldata (1024 bytes)
        calldatacopy(rtSize, 0, 1024)
        return(0, add(rtSize, 1024))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let smLen := sub(cd, 0x400)  // salt_msg starts after s2(1024)
            let NTTH_SIZE := 1024

            // Load ntth from appended code into memory at 0xc00
            codecopy(0xc00, sub(codesize(), NTTH_SIZE), NTTH_SIZE)

            // Step 1: SHAKE256(salt_msg) → 1024 bytes hashed at mem[0x1000]
            mstore(0, 256)      // security = 256
            mstore(0x20, 1024)  // output_len
            calldatacopy(0x40, 0x400, smLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x40, smLen), 0x1000, 0x400)) { revert(0,0) }

            // Step 2: NTT_FW(s2)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            calldatacopy(0x60, 0, 0x400)
            if iszero(staticcall(gas(), 0x12, 0, 0x460, 0, 0x400)) { revert(0,0) }

            // Step 3: VECMULMOD(NTT(s2), ntth)
            mcopy(0x40, 0, 0x400)       // a = NTT(s2)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mcopy(0x440, 0xc00, 0x400)  // b = ntth from code
            if iszero(staticcall(gas(), 0x14, 0, 0x840, 0, 0x400)) { revert(0,0) }

            // Step 4: NTT_INV(product)
            mcopy(0x60, 0, 0x400)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            if iszero(staticcall(gas(), 0x13, 0, 0x460, 0, 0x400)) { revert(0,0) }
            // s1 at mem[0x00..0x3ff]

            // Step 5: VECSUBMOD(hashed - s1) — one precompile call instead of loop
            // hashed at mem[0x1000], s1 at mem[0x00]
            mstore(0x1400, 512)
            mstore(0x1420, 12289)
            mcopy(0x1440, 0x1000, 0x400)        // a = hashed
            mcopy(0x1840, 0, 0x400)             // b = s1
            if iszero(staticcall(gas(), 0x19, 0x1400, 0x840, 0x1400, 0x400)) { revert(0,0) }
            // diff at mem[0x1400..0x17ff]

            // Step 6: LP_NORM(L2) on [diff, s2]
            mstore(0x1800, 12289)       // q
            mstore(0x1820, 512)         // n
            mstore(0x1840, 34034726)    // bound
            mstore(0x1860, 2)           // cb
            mstore(0x1880, 2)           // p = L2
            mstore(0x18a0, 2)           // count = 2
            mcopy(0x18c0, 0x1400, 0x400)        // diff
            calldatacopy(0x1cc0, 0, 0x400)      // s2
            if iszero(staticcall(gas(), 0x18, 0x1800, 0x8c0, 0, 0x20)) { revert(0,0) }

            return(0, 0x20)
        }
    }
}
