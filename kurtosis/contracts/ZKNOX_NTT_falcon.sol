// Copyright (C) 2026 - ZKNOX
// Modified: HALFMUL uses compact precompiles directly, zero expand/compact
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

/// @dev NTT half-multiply entirely in compact format using precompiles 0x17-0x19
/// Input: a (32 compact words), b (32 compact words, already in NTT domain)
/// Does: INTT(VECMUL(NTT(a), b)) → 32 compact words
/// Zero intermediate expand/compact conversions
function _ZKNOX_NTT_HALFMUL_Compact(uint256[] memory a, uint256[] memory b) view returns (uint256[] memory result) {
    result = new uint256[](32);
    assembly ("memory-safe") {
        let tmp := mload(0x40)

        // Step 1: Copy a's 32 words (1024 bytes) to scratch for NTT_FW call
        let aSrc := add(a, 32)
        for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
            mstore(add(tmp, i), mload(add(aSrc, i)))
        }

        // Step 2: NTT_FW(a) via 0x17 — in-place 1024 bytes
        let ok := staticcall(gas(), 0x17, tmp, 1024, tmp, 1024)
        if iszero(ok) { revert(0, 0) }

        // Step 3: Prepare VECMULMOD input: NTT(a) || b = 2048 bytes
        // NTT(a) is already at tmp[0..1024]. Copy b to tmp[1024..2048]
        let bSrc := add(b, 32)
        let bDst := add(tmp, 1024)
        for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
            mstore(add(bDst, i), mload(add(bSrc, i)))
        }

        // Step 4: VECMULMOD via 0x19 — 2048 bytes in, 1024 bytes out
        ok := staticcall(gas(), 0x19, tmp, 2048, tmp, 1024)
        if iszero(ok) { revert(0, 0) }

        // Step 5: NTT_INV via 0x18 — in-place 1024 bytes
        ok := staticcall(gas(), 0x18, tmp, 1024, tmp, 1024)
        if iszero(ok) { revert(0, 0) }

        // Step 6: Copy 1024 bytes result to output array
        let dst := add(result, 32)
        for { let i := 0 } lt(i, 1024) { i := add(i, 32) } {
            mstore(add(dst, i), mload(add(tmp, i)))
        }

        mstore(0x40, add(tmp, 2048))
    }
}
