#!/usr/bin/env python3
"""
Falcon-512 signature verification on Ethereum via NTT precompiles.

Usage:
    python falcon_demo.py [--rpc URL]

Requires a devnet running custom Erigon with Osaka fork active (NTT precompiles at 0x12-0x15).
"""

import argparse
import hashlib
import json
import os
import struct
import sys

from pathlib import Path
from web3 import Web3
from solcx import compile_standard, install_solc

# Falcon-512 via pqcrypto
from pqcrypto.sign.falcon_512 import generate_keypair, sign, verify


Q = 12289
N = 512


def decode_pubkey_14bit(pk_bytes):
    """Decode 897-byte Falcon-512 public key to 512 coefficients."""
    assert len(pk_bytes) == 897 and pk_bytes[0] == 0x09
    bits = pk_bytes[1:]
    byte_pos, bit_pos = 0, 0
    h = []
    for _ in range(N):
        val = 0
        for _ in range(14):
            val = (val << 1) | ((bits[byte_pos] >> (7 - bit_pos)) & 1)
            bit_pos += 1
            if bit_pos == 8:
                bit_pos = 0
                byte_pos += 1
        h.append(val)
    return h


def ntt_fw_python(coeffs, q=Q, n=N, psi=49):
    """Forward NTT (for computing NTT(h) offline)."""
    # Use the precompile via RPC for consistency
    # But we need it offline for deployment — use a simple DFT
    # Actually, let's compute twiddle factors and do CT butterfly
    a = list(coeffs)
    # Compute powers of psi for bit-reversal permutation
    psi_powers = [1] * (2 * n)
    for i in range(1, 2 * n):
        psi_powers[i] = (psi_powers[i - 1] * psi) % q

    # Bit-reversal of psi powers
    def bit_rev(x, log_n):
        result = 0
        for _ in range(log_n):
            result = (result << 1) | (x & 1)
            x >>= 1
        return result

    log_n = n.bit_length() - 1
    psi_rev = [psi_powers[bit_rev(i, log_n + 1)] for i in range(n)]

    t = n
    m = 1
    while m < n:
        t //= 2
        for i in range(m):
            S = psi_rev[m + i]
            j1 = 2 * i * t
            j2 = j1 + t
            for j in range(j1, j1 + t):
                U = a[j]
                V = (a[j + t] * S) % q
                a[j] = (U + V) % q
                a[j + t] = (U - V + q) % q
        m *= 2
    return a


def compact_coeffs(coeffs):
    """Pack 512 uint16 coefficients into 32 uint256 words (ETHFALCON format)."""
    assert len(coeffs) == N
    words = []
    for i in range(32):
        word = 0
        for j in range(16):
            word |= (coeffs[i * 16 + j] & 0xFFFF) << (j * 16)
        words.append(word)
    return words


def decode_compressed_sig(sig_bytes):
    """Decode Falcon-512 compressed signature to (salt, s2_coefficients)."""
    # header byte, 40-byte nonce, compressed s2
    nonce = sig_bytes[1:41]
    comp = sig_bytes[41:]

    byte_pos, bit_pos = 0, 0

    def read_bit():
        nonlocal byte_pos, bit_pos
        bit = (comp[byte_pos] >> (7 - bit_pos)) & 1
        bit_pos += 1
        if bit_pos == 8:
            bit_pos = 0
            byte_pos += 1
        return bit

    s2 = []
    for _ in range(N):
        sign = read_bit()
        low = 0
        for _ in range(7):
            low = (low << 1) | read_bit()
        high = 0
        while True:
            bit = read_bit()
            if bit == 1:
                break
            high += 1
        magnitude = (high << 7) | low
        if sign == 1:
            s2.append(Q - magnitude)
        else:
            s2.append(magnitude)

    return nonce, s2


def compile_contracts():
    """Compile ZKNOX_falcon (ETHFALCON with precompile backends)."""
    contracts_dir = Path(__file__).parent.parent / "contracts"

    sources = {}
    for name in [
        "ZKNOX_falcon.sol", "ZKNOX_falcon_core.sol", "ZKNOX_falcon_utils.sol",
        "ZKNOX_NTT_falcon.sol", "ZKNOX_HashToPoint.sol", "ZKNOX_common.sol",
    ]:
        sources[name] = {"content": (contracts_dir / name).read_text()}

    install_solc("0.8.26")

    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": sources,
            "settings": {
                "viaIR": True,
                "optimizer": {"enabled": True, "runs": 10000},
                "outputSelection": {
                    "*": {"*": ["abi", "evm.bytecode.object"]}
                },
            },
        },
        solc_version="0.8.26",
    )

    c = compiled["contracts"]["ZKNOX_falcon.sol"]["ZKNOX_falcon"]
    return c["abi"], c["evm"]["bytecode"]["object"]


def deploy_verifier(w3, account, abi, bytecode, pubkey_bytes):
    """Deploy FalconVerifier with the given public key."""
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(pubkey_bytes).build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 10_000_000,
            "gasPrice": w3.eth.gas_price,
        }
    )
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    print(f"  Contract deployed at {receipt.contractAddress} (gas used: {receipt.gasUsed})")
    return w3.eth.contract(address=receipt.contractAddress, abi=abi)


def verify_on_chain(w3, contract, account, message, sig_bytes):
    """Call verify() on the deployed contract."""
    try:
        result = contract.functions.verify(message, sig_bytes).call(
            {"from": account.address}
        )
        # Also estimate gas
        gas = contract.functions.verify(message, sig_bytes).estimate_gas(
            {"from": account.address}
        )
        return result, gas
    except Exception as e:
        print(f"  On-chain verify failed: {e}")
        return False, 0


def main():
    parser = argparse.ArgumentParser(description="Falcon-512 on-chain verification demo")
    parser.add_argument(
        "--rpc",
        default=os.environ.get("RPC_URL", "http://127.0.0.1:8545"),
        help="Ethereum JSON-RPC endpoint (default: $RPC_URL or http://127.0.0.1:8545)",
    )
    args = parser.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print(f"Cannot connect to {args.rpc}")
        sys.exit(1)
    print(f"Connected to {args.rpc} (chain {w3.eth.chain_id})")

    # Use a pre-funded account. ethereum-package uses bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31
    # as the default prefunded key (address: 0x8943545177806ED17B9F23F0a21ee5948eCaa776)
    dev_key = os.environ.get(
        "PRIVATE_KEY",
        "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31",
    )
    account = w3.eth.account.from_key(dev_key)

    balance = w3.eth.get_balance(account.address)
    print(f"Account: {account.address} (balance: {w3.from_wei(balance, 'ether')} ETH)")

    # Step 1: Generate Falcon-512 keypair
    print("\n── Generating Falcon-512 keypair...")
    pk, sk = generate_keypair()
    pk_bytes = bytes(pk)
    print(f"  Public key: {len(pk_bytes)} bytes")

    # Decode pubkey and compute NTT(h) via precompile (ensures consistency)
    h_coeffs = decode_pubkey_14bit(pk_bytes)

    # Encode as NTT_FW precompile calldata and call via eth_call
    import requests
    def ntt_fw_via_precompile(coeffs, rpc_url):
        # q_len=2, psi_len=1, n=512, q=12289, psi=49, coeffs
        hdr = b'\x00' * 31 + b'\x02'  # q_len=2
        hdr += b'\x00' * 31 + b'\x01'  # psi_len=1
        hdr += b'\x00' * 30 + b'\x02\x00'  # n=512
        hdr += b'\x30\x01'  # q=12289
        hdr += b'\x31'  # psi=49
        coeff_bytes = b''.join(c.to_bytes(2, 'big') for c in coeffs)
        calldata = '0x' + (hdr + coeff_bytes).hex()
        r = requests.post(rpc_url, json={
            'jsonrpc': '2.0', 'method': 'eth_call',
            'params': [{'to': '0x0000000000000000000000000000000000000012', 'data': calldata}, 'latest'],
            'id': 1
        })
        result = bytes.fromhex(r.json()['result'][2:])
        return [int.from_bytes(result[i:i+2], 'big') for i in range(0, len(result), 2)]

    ntth_coeffs = ntt_fw_via_precompile(h_coeffs, args.rpc)
    ntth_compact = compact_coeffs(ntth_coeffs)
    print(f"  NTT(h) compact: {len(ntth_compact)} words")

    # Step 2: Sign test messages
    messages = [
        b"Hello, post-quantum Ethereum!",
        b"",
        b"The quick brown fox jumps over the lazy dog",
    ]

    signatures = []
    for msg in messages:
        sig_bytes = sign(sk, msg)
        signatures.append(sig_bytes)
        print(f"  Signed '{msg[:40].decode(errors='replace')}...' -> {len(sig_bytes)} byte sig")

    # Step 3: Compile contract
    print("\n── Compiling FalconVerifierV2...")
    abi, bytecode = compile_contracts()
    print(f"  Bytecode: {len(bytecode) // 2} bytes")

    # Step 4: Deploy (no constructor args — V2 is stateless)
    print("\n── Deploying FalconVerifierV2...")
    contract_obj = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract_obj.constructor().build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 5_000_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed_tx = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)
    print(f"  Deployed at {receipt.contractAddress} (gas: {receipt.gasUsed})")

    # Step 5: Verify signatures
    print("\n── Verifying signatures on-chain...")
    for msg, sig in zip(messages, signatures):
        label = msg[:40].decode(errors="replace") or "(empty)"
        # Decode sig to (salt, s2) and hash message
        salt, s2_coeffs = decode_compressed_sig(sig)
        s2_compact = compact_coeffs(s2_coeffs)

        try:
            result = contract.functions.verify(
                msg, salt, s2_compact, ntth_compact
            ).call({"from": account.address})
            gas = contract.functions.verify(
                msg, salt, s2_compact, ntth_compact
            ).estimate_gas({"from": account.address})
        except Exception as e:
            result, gas = False, 0
            print(f"  Error: {e}")
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] '{label}' (gas: {gas})")

    # Step 6: Wrong message
    print("\n── Testing rejection of wrong message...")
    salt0, s2_0 = decode_compressed_sig(signatures[0])
    s2_compact0 = compact_coeffs(s2_0)
    try:
        wrong_result = contract.functions.verify(
            b"WRONG MESSAGE", salt0, s2_compact0, ntth_compact
        ).call({"from": account.address})
        wrong_gas = contract.functions.verify(
            b"WRONG MESSAGE", salt0, s2_compact0, ntth_compact
        ).estimate_gas({"from": account.address})
    except:
        wrong_result, wrong_gas = False, 0
    status = "PASS (correctly rejected)" if not wrong_result else "FAIL (accepted wrong msg!)"
    print(f"  [{status}] wrong message (gas: {wrong_gas})")

    # Step 7: Wrong key
    print("\n── Testing rejection of wrong key...")
    pk2, sk2 = generate_keypair()
    h2 = decode_pubkey_14bit(bytes(pk2))
    ntth2_compact = compact_coeffs(ntt_fw_python(h2))
    try:
        wk_result = contract.functions.verify(
            messages[0], salt0, s2_compact0, ntth2_compact
        ).call({"from": account.address})
        wk_gas = contract.functions.verify(
            messages[0], salt0, s2_compact0, ntth2_compact
        ).estimate_gas({"from": account.address})
    except:
        wk_result, wk_gas = False, 0
    status = "PASS (correctly rejected)" if not wk_result else "FAIL (accepted wrong key!)"
    print(f"  [{status}] wrong key (gas: {wk_gas})")

    print("\nDone.")


if __name__ == "__main__":
    main()
