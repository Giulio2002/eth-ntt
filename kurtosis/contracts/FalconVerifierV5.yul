/// @title FalconVerifierV5 — Minimal Falcon-512 verifier
/// Calldata: s2_compact(1024) | ntth_compact(1024) | salt(40) | msg(var)
/// ONE calldatacopy, ONE staticcall to FALCON_VERIFY_V2 at 0x1d
/// Calldata layout = precompile input layout (zero rearrangement)

object "FalconVerifierV5" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            // Copy entire calldata to memory[0]
            calldatacopy(0, 0, calldatasize())
            // staticcall(gas, 0x1d, 0, calldatasize, 0, 32)
            if iszero(staticcall(gas(), 0x1d, 0, calldatasize(), 0, 0x20)) {
                revert(0, 0)
            }
            return(0, 0x20)
        }
    }
}
