// SPDX-License-Identifier: MIT
// Based on ZKNOX/ETHFALCON (https://github.com/ZKNoxHQ/ETHFALCON)
// Modified to use NTT + SHAKE256 precompiles at 0x12-0x16
pragma solidity ^0.8.25;

contract FalconVerifierV2 {
    uint256 constant n = 512;
    uint256 constant q = 12289;
    uint256 constant qs1 = 6144;
    uint256 constant sigBound = 34034726;
    uint256 constant kq = 61445;

    /// @notice Verify a Falcon-512 signature (ETHFALCON compact format)
    /// @param h 32-byte message hash
    /// @param salt 40-byte nonce
    /// @param s2 Compact signature (32 uint256 words, 16 x 16-bit coefficients each)
    /// @param ntth Public key in NTT domain (32 uint256 words, compact)
    function verify(
        bytes memory h,
        bytes memory salt,
        uint256[] memory s2,
        uint256[] memory ntth
    ) external view returns (bool) {
        require(salt.length == 40 && s2.length == 32 && ntth.length == 32);

        // 1. hash_to_point via SHAKE256 precompile
        uint256[] memory hashed = _hashToPoint(salt, h);

        // 2. Compute s1 = INTT(NTT(s2) * ntth) using precompiles
        //    s2 is compact, ntth is compact (already in NTT domain)
        uint256[] memory s2exp = _expand(s2);
        uint256[] memory ntthexp = _expand(ntth);

        // NTT_FW(s2) via precompile 0x12
        uint256[] memory nttS2 = _nttFw(s2exp);

        // VECMULMOD(nttS2, ntth) via precompile 0x14
        uint256[] memory product = _vecMulMod(nttS2, ntthexp);

        // NTT_INV(product) via precompile 0x13
        uint256[] memory s1 = _nttInv(product);

        // 3. Norm check
        return _normCheck(s1, s2, hashed);
    }

    // ─── Precompile wrappers ───

    /// @dev NTT Forward via precompile at 0x12
    /// Calldata: q_len(32) | psi_len(32) | n(32) | q(2) | psi(1) | coeffs(512*2)
    function _nttFw(uint256[] memory a) private view returns (uint256[] memory) {
        bytes memory input = _encodeNttCalldata(a);
        (bool ok, bytes memory out) = address(0x12).staticcall(input);
        require(ok && out.length == 1024);
        return _decodeCoeffs(out);
    }

    /// @dev NTT Inverse via precompile at 0x13
    function _nttInv(uint256[] memory a) private view returns (uint256[] memory) {
        bytes memory input = _encodeNttCalldata(a);
        (bool ok, bytes memory out) = address(0x13).staticcall(input);
        require(ok && out.length == 1024);
        return _decodeCoeffs(out);
    }

    /// @dev VECMULMOD via precompile at 0x14
    /// Calldata: q_len(32) | n(32) | q(2) | a(512*2) | b(512*2)
    function _vecMulMod(uint256[] memory a, uint256[] memory b) private view returns (uint256[] memory) {
        // Header: 66 bytes + 2 * 1024 bytes = 2114 bytes
        bytes memory input = new bytes(2114);
        assembly {
            let p := add(input, 32)
            mstore8(add(p, 31), 2)    // q_len = 2
            mstore8(add(p, 62), 2)    // n = 512 high byte
            mstore8(add(p, 63), 0)    // n = 512 low byte
            mstore8(add(p, 64), 0x30) // q = 12289 high
            mstore8(add(p, 65), 0x01) // q = 12289 low

            // Write vector a: 512 coefficients as 2-byte BE
            let dst := add(p, 66)
            let src := add(a, 32)
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let val := and(mload(add(src, mul(i, 32))), 0xffff)
                let off := add(dst, mul(i, 2))
                mstore8(off, shr(8, val))
                mstore8(add(off, 1), and(val, 0xff))
            }

            // Write vector b: 512 coefficients as 2-byte BE
            dst := add(p, 1090) // 66 + 1024
            src := add(b, 32)
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let val := and(mload(add(src, mul(i, 32))), 0xffff)
                let off := add(dst, mul(i, 2))
                mstore8(off, shr(8, val))
                mstore8(add(off, 1), and(val, 0xff))
            }
        }
        (bool ok, bytes memory out) = address(0x14).staticcall(input);
        require(ok && out.length == 1024);
        return _decodeCoeffs(out);
    }

    /// @dev SHAKE256 hash-to-point via precompile at 0x16
    function _hashToPoint(bytes memory salt, bytes memory h) private view returns (uint256[] memory hashed) {
        uint256 outLen = 1536;
        bytes memory shakeInput = new bytes(32 + salt.length + h.length);
        assembly { mstore(add(shakeInput, 32), outLen) }

        // Copy salt then h
        for (uint256 i = 0; i < salt.length; i++) shakeInput[32 + i] = salt[i];
        for (uint256 i = 0; i < h.length; i++) shakeInput[32 + salt.length + i] = h[i];

        (bool ok, bytes memory shakeOut) = address(0x16).staticcall(shakeInput);
        require(ok && shakeOut.length == outLen);

        hashed = new uint256[](512);
        uint256 count = 0;
        uint256 off = 0;
        assembly {
            let src := add(shakeOut, 32)
            let dst := add(hashed, 32)
            for {} lt(count, 512) {} {
                let hi := byte(0, mload(add(src, off)))
                let lo := byte(1, mload(add(src, off)))
                let t := add(mul(hi, 256), lo)
                off := add(off, 2)
                if lt(t, 61445) {
                    mstore(add(dst, mul(count, 32)), mod(t, 12289))
                    count := add(count, 1)
                }
            }
        }
    }

    // ─── Encoding helpers ───

    /// @dev Encode uint256[512] as NTT precompile calldata
    function _encodeNttCalldata(uint256[] memory a) private pure returns (bytes memory input) {
        // 99 byte header + 1024 byte coefficients
        input = new bytes(1123);
        assembly {
            let p := add(input, 32)
            mstore8(add(p, 31), 2)    // q_len = 2
            mstore8(add(p, 63), 1)    // psi_len = 1
            mstore8(add(p, 94), 2)    // n high = 0x02
            mstore8(add(p, 95), 0)    // n low = 0x00
            mstore8(add(p, 96), 0x30) // q high
            mstore8(add(p, 97), 0x01) // q low
            mstore8(add(p, 98), 0x31) // psi = 49

            let dst := add(p, 99)
            let src := add(a, 32)
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let val := and(mload(add(src, mul(i, 32))), 0xffff)
                let off := add(dst, mul(i, 2))
                mstore8(off, shr(8, val))
                mstore8(add(off, 1), and(val, 0xff))
            }
        }
    }

    /// @dev Decode 1024 raw bytes (512 x 2-byte BE) into uint256[512]
    function _decodeCoeffs(bytes memory data) private pure returns (uint256[] memory out) {
        out = new uint256[](512);
        assembly {
            let src := add(data, 32)
            let dst := add(out, 32)
            for { let i := 0 } lt(i, 512) { i := add(i, 1) } {
                let off := add(src, mul(i, 2))
                let hi := byte(0, mload(off))
                let lo := byte(1, mload(off))
                mstore(add(dst, mul(i, 32)), add(mul(hi, 256), lo))
            }
        }
    }

    /// @dev Expand compact (32 words) to expanded (512 uint256)
    function _expand(uint256[] memory a) private pure returns (uint256[] memory b) {
        b = new uint256[](512);
        assembly {
            let aa := a
            let bb := add(b, 32)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                aa := add(aa, 32)
                let ai := mload(aa)
                for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                    mstore(add(bb, mul(32, add(j, shl(4, i)))), and(shr(shl(4, j), ai), 0xffff))
                }
            }
        }
    }

    /// @dev Norm check: ||hashed - s1||^2 + ||s2||^2 < sigBound
    function _normCheck(
        uint256[] memory s1,
        uint256[] memory s2compact,
        uint256[] memory hashed
    ) private pure returns (bool result) {
        assembly {
            let norm := 0

            // s1 norm: s1i = (hashed[i] - s1[i]) mod q, centered
            for { let off := 32 } lt(off, 16384) { off := add(off, 32) } {
                let s1i := addmod(mload(add(hashed, off)), sub(12289, mload(add(s1, off))), 12289)
                let cond := gt(s1i, 6144)
                s1i := add(mul(cond, sub(12289, s1i)), mul(sub(1, cond), s1i))
                norm := add(norm, mul(s1i, s1i))
            }

            // s2 norm: expand from compact, center, accumulate
            // Reuse s1 memory for s2 expansion (s1 no longer needed)
            let aa := s2compact
            let bb := add(s1, 32)
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                aa := add(aa, 32)
                let ai := mload(aa)
                for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                    mstore(add(bb, mul(32, add(j, shl(4, i)))), and(shr(shl(4, j), ai), 0xffff))
                }
            }

            for { let off := add(s1, 32) } lt(off, add(s1, 16384)) { off := add(off, 32) } {
                let s2i := mload(off)
                let cond := gt(s2i, 6144)
                s2i := add(mul(cond, sub(12289, s2i)), mul(sub(1, cond), s2i))
                norm := add(norm, mul(s2i, s2i))
            }

            result := gt(34034726, norm)
        }
    }
}
