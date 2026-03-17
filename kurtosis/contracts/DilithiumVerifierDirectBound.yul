/// @title DilithiumVerifierDirectBound — ML-DSA-44 with pk bound at deploy
/// Constructor: pk(1312) as calldata, stored in bytecode.
/// Verify calldata: sig(2420) | msg(var)
/// Single STATICCALL to DILITHIUM_VERIFY (0x1b) with pk from code.
/// For FIPS 204 (ml_dsa_44): caller prepends 0x00||0x00 to msg.

object "DilithiumVerifierDirectBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        calldatacopy(rtSize, 0, 1312)
        return(0, add(rtSize, 1312))
    }
    object "runtime" {
        code {
            let PK_SIZE := 1312
            let cd := calldatasize()

            // Build DILITHIUM_VERIFY input: pk(1312) | sig(2420) | msg(var)
            codecopy(0, sub(codesize(), PK_SIZE), PK_SIZE)  // pk from bytecode
            calldatacopy(PK_SIZE, 0, cd)                     // sig + msg from calldata

            let totalLen := add(PK_SIZE, cd)
            if iszero(staticcall(gas(), 0x1b, 0, totalLen, 0, 0x20)) { revert(0,0) }
            return(0, 0x20)
        }
    }
}
