// Copyright (C) 2026 - ZKNOX
// Modified: norm check works directly on compact format, no expand needed
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_NTT_falcon.sol";

/// @dev Norm check on all-compact data. No uint256[512] arrays allocated.
/// s1_compact: 32 words = INTT(NTT(s2)*ntth)
/// s2_compact: 32 words = signature
/// hashed_compact: 32 words = hash_to_point result
/// Computes: ||(hashed - s1) mod q||^2 + ||s2||^2 < sigBound
function falcon_normalize_compact(
    uint256[] memory s1_compact,
    uint256[] memory s2_compact,
    uint256[] memory hashed_compact
) pure returns (bool result) {
    assembly ("memory-safe") {
        let norm := 0

        for { let w := 0 } lt(w, 32) { w := add(w, 1) } {
            let s1w := mload(add(add(s1_compact, 32), mul(w, 32)))
            let s2w := mload(add(add(s2_compact, 32), mul(w, 32)))
            let hw  := mload(add(add(hashed_compact, 32), mul(w, 32)))

            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                let shift := shl(4, j) // j * 16

                // Extract coefficients
                let s1i := and(shr(shift, s1w), 0xffff)
                let s2i := and(shr(shift, s2w), 0xffff)
                let hi  := and(shr(shift, hw),  0xffff)

                // s1_centered = (hashed - s1) mod q, centered
                let d := addmod(hi, sub(q, s1i), q)
                let cond := gt(d, qs1)
                d := add(mul(cond, sub(q, d)), mul(sub(1, cond), d))
                norm := add(norm, mul(d, d))

                // s2_centered
                cond := gt(s2i, qs1)
                let s2c := add(mul(cond, sub(q, s2i)), mul(sub(1, cond), s2i))
                norm := add(norm, mul(s2c, s2c))
            }
        }

        result := gt(sigBound, norm)
    }
}

/// @dev Core verify: HALFMUL + norm check, all in compact format
function falcon_core(
    uint256[] memory s2,
    uint256[] memory ntth,
    uint256[] memory hashed_compact
) view returns (bool) {
    if (hashed_compact.length != 32) return false;
    if (s2.length != 32) return false;

    uint256[] memory s1_compact = _ZKNOX_NTT_HALFMUL_Compact(s2, ntth);
    return falcon_normalize_compact(s1_compact, s2, hashed_compact);
}
