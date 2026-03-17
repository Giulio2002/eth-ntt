/// @title FalconVerifierDirectBound — Falcon-512 with pk bound at deploy
/// Constructor: ntth(1024) as calldata, stored in bytecode.
/// Verify calldata: s2(1024) | salt_msg(var)
/// Single STATICCALL to FALCON_VERIFY (0x17) with ntth from code.

object "FalconVerifierDirectBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        calldatacopy(rtSize, 0, 1024)
        return(0, add(rtSize, 1024))
    }
    object "runtime" {
        code {
            let NTTH_SIZE := 1024
            let cd := calldatasize()

            // Build FALCON_VERIFY input: s2(1024) | ntth(1024) | salt_msg(var)
            calldatacopy(0, 0, cd)                              // s2 + salt_msg
            // Insert ntth between s2 and salt_msg
            // Shift salt_msg right by 1024 to make room for ntth
            let smLen := sub(cd, NTTH_SIZE)
            mcopy(add(NTTH_SIZE, NTTH_SIZE), NTTH_SIZE, smLen)  // move salt_msg
            codecopy(NTTH_SIZE, sub(codesize(), NTTH_SIZE), NTTH_SIZE)  // insert ntth

            let totalLen := add(cd, NTTH_SIZE)
            if iszero(staticcall(gas(), 0x17, 0, totalLen, 0, 0x20)) { revert(0,0) }
            return(0, 0x20)
        }
    }
}
