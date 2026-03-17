/// @title DilithiumVerifierDirectVerify — ML-DSA-44 verifier via single precompile
/// Single STATICCALL to DILITHIUM_VERIFY at 0x1b.
/// Calldata = precompile input: pk(1312) | sig(2420) | msg(var)
/// For FIPS 204 (ml_dsa_44): caller prepends 0x00||0x00 to msg.

object "DilithiumVerifierDirectVerify" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            calldatacopy(0, 0, calldatasize())
            if iszero(staticcall(gas(), 0x1b, 0, calldatasize(), 0, 0x20)) { revert(0,0) }
            return(0, 0x20)
        }
    }
}
