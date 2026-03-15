object "FalconVerifierV3" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let htpLen := sub(cd, 0x800)
            calldatacopy(0, 0, htpLen)
            if iszero(staticcall(gas(), 0x1a, 0, htpLen, 0x800, 0x400)) { revert(0,0) }
            calldatacopy(0, sub(cd, 0x800), 0x400)
            if iszero(staticcall(gas(), 0x17, 0, 0x400, 0, 0x400)) { revert(0,0) }
            calldatacopy(0x400, sub(cd, 0x400), 0x400)
            if iszero(staticcall(gas(), 0x19, 0, 0x800, 0, 0x400)) { revert(0,0) }
            if iszero(staticcall(gas(), 0x18, 0, 0x400, 0, 0x400)) { revert(0,0) }
            calldatacopy(0x400, sub(cd, 0x800), 0x400)

            mstore(0xc00, 0)
            for { let w := 0 } lt(w, 32) { w := add(w, 1) } {
                let off := shl(5, w)
                let s1w := mload(off)
                let s2w := mload(add(0x400, off))
                let hw  := mload(add(0x800, off))

                {
                    let d := mod(add(and(shr(0, hw), 0xffff), sub(12289, and(shr(0, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(0, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(16, hw), 0xffff), sub(12289, and(shr(16, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(16, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(32, hw), 0xffff), sub(12289, and(shr(32, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(32, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(48, hw), 0xffff), sub(12289, and(shr(48, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(48, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(64, hw), 0xffff), sub(12289, and(shr(64, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(64, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(80, hw), 0xffff), sub(12289, and(shr(80, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(80, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(96, hw), 0xffff), sub(12289, and(shr(96, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(96, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(112, hw), 0xffff), sub(12289, and(shr(112, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(112, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(128, hw), 0xffff), sub(12289, and(shr(128, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(128, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(144, hw), 0xffff), sub(12289, and(shr(144, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(144, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(160, hw), 0xffff), sub(12289, and(shr(160, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(160, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(176, hw), 0xffff), sub(12289, and(shr(176, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(176, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(192, hw), 0xffff), sub(12289, and(shr(192, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(192, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(208, hw), 0xffff), sub(12289, and(shr(208, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(208, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(224, hw), 0xffff), sub(12289, and(shr(224, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(224, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
                {
                    let d := mod(add(and(shr(240, hw), 0xffff), sub(12289, and(shr(240, s1w), 0xffff))), 12289)
                    if gt(d, 6144) { d := sub(12289, d) }
                    let s := and(shr(240, s2w), 0xffff)
                    if gt(s, 6144) { s := sub(12289, s) }
                    mstore(0xc00, add(mload(0xc00), add(mul(d, d), mul(s, s))))
                }
            }
            mstore(0, lt(mload(0xc00), 34034726))
            return(0, 32)
        }
    }
}