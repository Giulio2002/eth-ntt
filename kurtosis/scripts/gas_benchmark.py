#!/usr/bin/env python3
"""
Gas benchmark for all NTT precompiles and verifier contracts.
Measures actual on-chain gas via eth_estimateGas on a Kurtosis devnet.

Usage:
  RPC_URL=http://127.0.0.1:PORT python3 kurtosis/scripts/gas_benchmark.py
"""
import os, sys, subprocess, requests, hashlib
from web3 import Web3
from pathlib import Path

# ── Setup ──

RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CONTRACTS = Path(__file__).parent.parent / "contracts"
ACCT_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

Q_FALCON = 12289
N_FALCON = 512
PSI_FALCON = 49

Q_DIL = 8380417
N_DIL = 256
PSI_DIL = 1753


def connect():
    w3 = Web3(Web3.HTTPProvider(RPC))
    if not w3.is_connected():
        print(f"Cannot connect to {RPC}")
        sys.exit(1)
    acct = w3.eth.account.from_key(ACCT_KEY)
    bal = w3.eth.get_balance(acct.address)
    print(f"Connected to {RPC}")
    print(f"Account: {acct.address} ({bal / 1e18:.2f} ETH)")
    return w3, acct


def deploy_yul(w3, acct, yul_path):
    r = subprocess.run(
        ["solc", "--strict-assembly", "--optimize", "--optimize-runs", "10000", "--bin", str(yul_path)],
        capture_output=True, text=True)
    lines = r.stdout.strip().split('\n')
    init_hex = [l for l in lines if len(l) > 20 and all(c in '0123456789abcdef' for c in l)][0]
    nonce = w3.eth.get_transaction_count(acct.address, 'pending')
    tx = {"from": acct.address, "nonce": nonce, "gas": 5_000_000,
          "gasPrice": w3.eth.gas_price, "data": "0x" + init_hex, "chainId": w3.eth.chain_id}
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), 120)
    code = w3.eth.get_code(receipt.contractAddress)
    return receipt.contractAddress, len(code)


def estimate_gas(to, data):
    r = requests.post(RPC, json={"jsonrpc": "2.0", "method": "eth_estimateGas", "params": [{
        "to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)
    }], "id": 1})
    result = r.json()
    if "error" in result:
        return None, result["error"].get("message", str(result["error"]))
    return int(result["result"], 16), None


def precompile_addr(n):
    return "0x" + "0" * 38 + f"{n:02x}"


def ntt_call(addr, coeffs, rpc_url):
    """Call NTT precompile via eth_call, return result coefficients."""
    q, n, psi, cb = (Q_DIL, N_DIL, PSI_DIL, 3) if addr == "dilithium" else (Q_FALCON, N_FALCON, PSI_FALCON, 2)
    hdr = n.to_bytes(32, 'big') + q.to_bytes(32, 'big') + psi.to_bytes(32, 'big')
    body = b''.join(c.to_bytes(cb, 'big') for c in coeffs)
    r = requests.post(rpc_url, json={"jsonrpc": "2.0", "method": "eth_call", "params": [{
        "to": precompile_addr(0x12), "data": "0x" + (hdr + body).hex()}, "latest"], "id": 1})
    raw = bytes.fromhex(r.json()["result"][2:])
    return [int.from_bytes(raw[i:i+cb], 'big') for i in range(0, len(raw), cb)]


# ── Falcon helpers ──

def build_falcon_calldata():
    from pqcrypto.sign.falcon_512 import generate_keypair, sign

    pk, sk = generate_keypair()
    pk_bytes = bytes(pk)

    # Decode public key (14-bit packed)
    bits_data = pk_bytes[1:]
    bp = bip = 0
    h = []
    for _ in range(N_FALCON):
        v = 0
        for _ in range(14):
            v = (v << 1) | ((bits_data[bp] >> (7 - bip)) & 1)
            bip += 1
            if bip == 8: bip = 0; bp += 1
        h.append(v)

    # NTT(h) via precompile
    ntth = ntt_call("falcon", h, RPC)
    ntth_flat = b''.join(c.to_bytes(2, 'big') for c in ntth)

    msg = b"falcon gas benchmark message"
    sig_bytes = sign(sk, msg)
    nonce = sig_bytes[1:41]
    comp = sig_bytes[41:]
    bp = bip = 0
    def rb():
        nonlocal bp, bip
        b = (comp[bp] >> (7 - bip)) & 1; bip += 1
        if bip == 8: bip = 0; bp += 1
        return b
    s2 = []
    for _ in range(N_FALCON):
        s = rb(); lo = 0
        for _ in range(7): lo = (lo << 1) | rb()
        hi = 0
        while True:
            b = rb()
            if b == 1: break
            hi += 1
        s2.append(Q_FALCON - ((hi << 7) | lo) if s == 1 else (hi << 7) | lo)

    s2_flat = b''.join(c.to_bytes(2, 'big') for c in s2)
    return s2_flat + ntth_flat + nonce + msg


# ── Dilithium helpers ──

def build_dilithium_calldata():
    from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign
    sys.path.insert(0, str(Path(__file__).parent))
    from dilithium_fuzz import (decode_pk, decode_sig, expand_a, sample_in_ball,
        use_hint, ntt_fw_precompile, ntt_inv_precompile,
        vecmulmod_precompile, vecaddmod_precompile, build_calldata,
        Q, K, L, D)

    pk, sk = generate_keypair()
    msg = b"dilithium gas benchmark message"
    sig = sign(sk, msg)

    rho, t1 = decode_pk(bytes(pk))
    c_tilde, z, h = decode_sig(bytes(sig))
    a_ntt = expand_a(rho)

    z_ntt = [ntt_fw_precompile(zi, RPC) for zi in z]
    az_ntt = []
    for i in range(K):
        acc = vecmulmod_precompile(a_ntt[i][0], z_ntt[0], RPC)
        for j in range(1, L):
            prod = vecmulmod_precompile(a_ntt[i][j], z_ntt[j], RPC)
            acc = vecaddmod_precompile(acc, prod, RPC)
        az_ntt.append(acc)

    tr = hashlib.shake_256(bytes(pk)).digest(64)
    mu = hashlib.shake_256(tr + b'\x00\x00' + msg).digest(64)
    c_poly = sample_in_ball(c_tilde)
    c_ntt = ntt_fw_precompile(c_poly, RPC)
    t1_d_ntt = [ntt_fw_precompile([(x << D) % Q for x in ti], RPC) for ti in t1]

    w1_polys = []
    for i in range(K):
        ct1 = vecmulmod_precompile(c_ntt, t1_d_ntt[i], RPC)
        neg_ct1 = [(Q - x) % Q for x in ct1]
        w_ntt = vecaddmod_precompile(az_ntt[i], neg_ct1, RPC)
        w_approx = ntt_inv_precompile(w_ntt, RPC)
        w1_polys.append(use_hint(h[i], w_approx))

    return build_calldata(a_ntt, z, c_ntt, t1_d_ntt, h, c_tilde, mu)


# ── Main ──

def main():
    w3, acct = connect()
    results = []

    def record(name, gas, expected=None):
        if gas is None:
            results.append((name, "FAILED", expected))
        else:
            exp_str = f"  [expected {expected:,}]" if expected else ""
            results.append((name, gas, expected))

    # Deploy contracts
    print("\n── Deploying contracts ──")
    addrs = {}
    for name in ["FalconVerifierDirectVerify", "FalconVerifierNTTWithLpNorm",
                  "FalconVerifierNTT", "DilithiumVerifierNTT"]:
        yul = CONTRACTS / f"{name}.yul"
        addr, sz = deploy_yul(w3, acct, yul)
        addrs[name] = addr
        print(f"  {name}: {addr} ({sz}B)")

    # Build calldata
    print("\n── Building Falcon calldata ──")
    falcon_cd = build_falcon_calldata()
    print(f"  {len(falcon_cd)} bytes")

    print("\n── Building Dilithium calldata (takes ~30s) ──")
    dil_cd = build_dilithium_calldata()
    print(f"  {len(dil_cd)} bytes")

    # ── Individual precompile gas ──
    print("\n── Individual precompile gas ──")

    # NTT_FW at various n
    for n, q, psi, cb, label in [
        (256, Q_DIL, PSI_DIL, 3, "Dilithium"),
        (512, Q_FALCON, PSI_FALCON, 2, "Falcon"),
    ]:
        inp = n.to_bytes(32,'big') + q.to_bytes(32,'big') + psi.to_bytes(32,'big') + bytes(n*cb)
        g, e = estimate_gas(precompile_addr(0x12), inp)
        exp = 650 + 12*n
        record(f"NTT_FW n={n} ({label})", g, exp)

        # NTT_INV
        g, e = estimate_gas(precompile_addr(0x13), inp)
        exp = 13*n
        record(f"NTT_INV n={n} ({label})", g, exp)

    # VECMULMOD / VECADDMOD
    for n, q, cb, label in [
        (256, Q_DIL, 3, "Dilithium"),
        (512, Q_FALCON, 2, "Falcon"),
        (1024, Q_DIL, 3, "batched 4×256"),
        (4096, Q_DIL, 3, "batched 16×256"),
    ]:
        inp = n.to_bytes(32,'big') + q.to_bytes(32,'big') + bytes(n*cb*2)
        g, e = estimate_gas(precompile_addr(0x14), inp)
        record(f"VECMULMOD n={n} ({label})", g, 300 + 2*n)

        g, e = estimate_gas(precompile_addr(0x15), inp)
        record(f"VECADDMOD n={n} ({label})", g, 600 + n)

    # SHAKE256 at various data sizes
    for data_len, label in [(32, "32B"), (832, "832B"), (2048, "2KB")]:
        inp = (32).to_bytes(32,'big') + bytes(data_len)
        g, e = estimate_gas(precompile_addr(0x16), inp)
        blocks = (data_len + 135) // 136
        record(f"SHAKE256 {label}→32B", g, 150 + 3*blocks)

    # FALCON_VERIFY
    g, e = estimate_gas(precompile_addr(0x17), falcon_cd)
    record("FALCON_VERIFY", g, 3100)

    # LP_NORM
    for n, q, cb, label in [(256, Q_DIL, 3, "Dilithium"), (512, Q_FALCON, 2, "Falcon")]:
        inp = q.to_bytes(32,'big') + n.to_bytes(32,'big') + (1<<40).to_bytes(32,'big') + cb.to_bytes(32,'big') + bytes(n*cb*3)
        g, e = estimate_gas(precompile_addr(0x18), inp)
        record(f"LP_NORM n={n} ({label})", g, 200 + n)

    # ── Contract gas ──
    print("\n── Contract verification gas ──")

    g, e = estimate_gas(addrs["FalconVerifierDirectVerify"], falcon_cd)
    record("FalconVerifierDirectVerify", g)

    g, e = estimate_gas(addrs["FalconVerifierNTTWithLpNorm"], falcon_cd)
    record("FalconVerifierNTTWithLpNorm", g)

    g, e = estimate_gas(addrs["FalconVerifierNTT"], falcon_cd)
    record("FalconVerifierNTT", g)

    g, e = estimate_gas(addrs["DilithiumVerifierNTT"], dil_cd)
    record("DilithiumVerifierNTT", g)

    # ── Print results ──
    print("\n" + "=" * 70)
    print(f"{'Benchmark':<40} {'Gas':>10} {'Expected':>10}")
    print("=" * 70)

    section = ""
    for name, gas, expected in results:
        # Section headers
        if "NTT_FW" in name and section != "ntt":
            section = "ntt"
            print(f"\n  {'─── NTT precompiles ───':}")
        elif "VECMUL" in name and section != "vec":
            section = "vec"
            print(f"\n  {'─── Vector precompiles ───':}")
        elif "SHAKE" in name and section != "shake":
            section = "shake"
            print(f"\n  {'─── SHAKE precompile ───':}")
        elif "FALCON_VERIFY" == name and section != "falcon":
            section = "falcon"
            print(f"\n  {'─── Falcon verify ───':}")
        elif "LP_NORM" in name and section != "lp":
            section = "lp"
            print(f"\n  {'─── LP_NORM ───':}")
        elif "Verifier" in name and section != "contracts":
            section = "contracts"
            print(f"\n  {'─── Full contract verification ───':}")

        if gas == "FAILED":
            print(f"  {name:<38} {'FAILED':>10}")
        elif expected:
            diff = gas - expected
            pct = f"({diff:+,})" if diff != 0 else ""
            print(f"  {name:<38} {gas:>10,} {expected:>10,}  {pct}")
        else:
            print(f"  {name:<38} {gas:>10,}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
