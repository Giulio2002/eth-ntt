/// @title FalconVerifierDirectVerify — Single-precompile Falcon-512 verifier
/// Calldata = precompile input: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)
/// One calldatacopy, one staticcall to FALCON_VERIFY at 0x17
/// Returns 32 bytes (0x01 valid, 0x00 invalid)

object "FalconVerifierDirectVerify" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            calldatacopy(0, 0, calldatasize())
            if iszero(staticcall(gas(), 0x17, 0, calldatasize(), 0, 0x20)) {
                revert(0, 0)
            }
            return(0, 0x20)
        }
    }
}
