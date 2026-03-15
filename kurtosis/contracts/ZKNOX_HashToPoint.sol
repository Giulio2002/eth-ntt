// Copyright (C) 2026 - ZKNOX
// Modified: returns compact 32-word format directly from precompile
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

/// @notice Hash to point via SHAKE256_HTP precompile at 0x1a
/// @dev Returns compact format: 32 uint256 words, 16 LE-packed uint16 per word
function hashToPointNIST(bytes memory salt, bytes memory msgHash) view returns (uint256[] memory hashed) {
    hashed = new uint256[](32);

    assembly ("memory-safe") {
        let tmp := mload(0x40)
        let sLen := mload(salt)
        let mLen := mload(msgHash)
        let totalLen := add(sLen, mLen)

        // Copy salt || msgHash contiguously
        let src := add(salt, 32)
        let dst := tmp
        for { let i := 0 } lt(i, sLen) { i := add(i, 32) } {
            mstore(add(dst, i), mload(add(src, i)))
        }
        src := add(msgHash, 32)
        dst := add(tmp, sLen)
        for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
            mstore(add(dst, i), mload(add(src, i)))
        }

        // staticcall 0x1a → 1024 bytes compact output
        let outBuf := add(hashed, 32)
        let ok := staticcall(gas(), 0x1a, tmp, totalLen, outBuf, 1024)
        if iszero(ok) { revert(0, 0) }

        mstore(0x40, add(tmp, and(add(totalLen, 31), not(31))))
    }
}
