/// @title FalconVerifierV4 — Falcon-512 verifier with norm precompile
/// Calldata: salt(40) | msg(var) | s2_compact(1024) | ntth_compact(1024)
/// Precompiles: 0x17 NTT_FW, 0x18 NTT_INV, 0x19 VECMULMOD,
///              0x1a SHAKE256_HTP, 0x1b FALCON_NORM
/// Returns 32 bytes from norm precompile (0x01 valid, 0x00 invalid)

object "FalconVerifierV4" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let htpLen := sub(cd, 0x800)

            // Step 1: SHAKE256_HTP → hashed at mem[0x800..0xbff]
            calldatacopy(0, 0, htpLen)
            if iszero(staticcall(gas(), 0x1a, 0, htpLen, 0x800, 0x400)) { revert(0,0) }

            // Step 2: NTT_FW(s2) → ntt_s2 at mem[0x00..0x3ff]
            calldatacopy(0, sub(cd, 0x800), 0x400)
            if iszero(staticcall(gas(), 0x17, 0, 0x400, 0, 0x400)) { revert(0,0) }

            // Step 3: VECMULMOD(ntt_s2, ntth) → product at mem[0x00..0x3ff]
            calldatacopy(0x400, sub(cd, 0x400), 0x400)
            if iszero(staticcall(gas(), 0x19, 0, 0x800, 0, 0x400)) { revert(0,0) }

            // Step 4: NTT_INV(product) → s1 at mem[0x00..0x3ff]
            if iszero(staticcall(gas(), 0x18, 0, 0x400, 0, 0x400)) { revert(0,0) }

            // Step 5: Build norm input at mem[0x00]: s1(1024) || s2(1024) || hashed(1024)
            // s1 already at mem[0x00..0x3ff]
            // Copy s2 to mem[0x400..0x7ff]
            calldatacopy(0x400, sub(cd, 0x800), 0x400)
            // hashed already at mem[0x800..0xbff]
            // Total: 3072 bytes at mem[0x00]

            // Step 6: FALCON_NORM → 32 bytes result at mem[0x00]
            if iszero(staticcall(gas(), 0x1b, 0, 0xc00, 0, 0x20)) { revert(0,0) }

            // Return the 32-byte norm result directly
            return(0, 0x20)
        }
    }
}
