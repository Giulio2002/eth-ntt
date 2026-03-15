// Copyright (C) 2026 - ZKNOX
// Modified: all-compact pipeline with precompiles 0x17-0x1a
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_common.sol";
import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core.sol";
import "./ZKNOX_HashToPoint.sol";

contract ZKNOX_falcon {
    function verify(
        bytes calldata h,
        bytes calldata salt,
        uint256[] calldata s2,
        uint256[] calldata ntth
    ) external view returns (bool) {
        require(salt.length == 40 && s2.length == 32 && ntth.length == 32);

        // All in compact format — no uint256[512] anywhere
        uint256[] memory hashed = hashToPointNIST(
            bytes(salt), bytes(h)
        );
        return falcon_core(
            _copyCalldata(s2), _copyCalldata(ntth), hashed
        );
    }

    function _copyCalldata(uint256[] calldata arr) private pure returns (uint256[] memory out) {
        out = new uint256[](32);
        assembly {
            calldatacopy(add(out, 32), arr.offset, 1024)
        }
    }
}
