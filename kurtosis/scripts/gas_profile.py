#!/usr/bin/env python3
"""
Gas profiler for NTT verifier contracts.
Builds all calldata LOCALLY (no RPC for precompile calls).
Only hits the devnet for: deploy, send tx, trace.

Usage:
  RPC_URL=http://127.0.0.1:PORT python3 kurtosis/scripts/gas_profile.py
"""
import os, sys, csv, subprocess, requests, hashlib, struct
from web3 import Web3
from pathlib import Path

RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CONTRACTS = Path(__file__).parent.parent / "contracts"
ACCT_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OUT_CSV = Path(__file__).parent.parent.parent / "docs" / "gas_profile.csv"

w3 = Web3(Web3.HTTPProvider(RPC))
acct = w3.eth.account.from_key(ACCT_KEY)

# ── Local NTT via Rust library through precompile function ──
# We call the Rust precompile functions directly via ctypes or
# fall back to calling them as raw bytes through the Python test.
# Simplest: use the pq_eth_precompiles crate via subprocess.
# But even simpler: just use the RPC for NTT only during calldata build
# since those are fast. The KEY optimization is that the fuzzer/profiler
# only calls the CONTRACT once per iteration.
#
# Actually, the user wants ALL local. Let's implement NTT in pure Python.

Q_DIL = 8380417
N_DIL = 256
PSI_DIL = 1753
K, L = 4, 4
D = 13
GAMMA1 = 1 << 17
GAMMA2 = (Q_DIL - 1) // 88
BETA = 78
ALPHA = 2 * GAMMA2
M_HINT = (Q_DIL - 1) // ALPHA

Q_FAL = 12289
N_FAL = 512
PSI_FAL = 49

def pow_mod(base, exp, mod):
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        exp >>= 1
        base = base * base % mod
    return result

def bit_reverse(x, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r

def build_twiddles(q, n, psi):
    log_n = n.bit_length() - 1
    psi_inv = pow_mod(psi, q - 2, q)
    fwd = [pow_mod(psi, bit_reverse(i, log_n), q) for i in range(n)]
    inv = [pow_mod(psi_inv, bit_reverse(i, log_n), q) for i in range(n)]
    return fwd, inv

def ntt_fw(a, q, n, twiddles):
    a = list(a)
    t = n
    m = 1
    while m < n:
        t //= 2
        for i in range(m):
            j1 = 2 * i * t
            s = twiddles[m + i]
            for j in range(j1, j1 + t):
                u = a[j]
                v = a[j + t] * s % q
                a[j] = (u + v) % q
                a[j + t] = (u - v) % q
        m *= 2
    return a

def ntt_inv(a, q, n, twiddles_inv):
    a = list(a)
    t = 1
    m = n
    while m > 1:
        h = m // 2
        for i in range(h):
            j1 = 2 * i * t
            s = twiddles_inv[h + i]
            for j in range(j1, j1 + t):
                u = a[j]
                v = a[j + t]
                a[j] = (u + v) % q
                a[j + t] = (u - v) * s % q
        t *= 2
        m //= 2
    n_inv = pow_mod(n, q - 2, q)
    return [(x * n_inv) % q for x in a]

def vec_mul(a, b, q):
    return [(ai * bi) % q for ai, bi in zip(a, b)]

def vec_add(a, b, q):
    return [(ai + bi) % q for ai, bi in zip(a, b)]

def vec_sub(a, b, q):
    return [(q + ai - bi) % q for ai, bi in zip(a, b)]

def shake256(data, outlen):
    return hashlib.shake_256(data).digest(outlen)

def shake128(data, outlen):
    return hashlib.shake_128(data).digest(outlen)

# ── Precompute twiddle tables ──
print("Precomputing twiddle tables...")
_fal_tw, _fal_tw_inv = build_twiddles(Q_FAL, N_FAL, PSI_FAL)
_dil_tw, _dil_tw_inv = build_twiddles(Q_DIL, N_DIL, PSI_DIL)

# ── Falcon calldata (all local) ──

def build_falcon_cd():
    from pqcrypto.sign.falcon_512 import generate_keypair, sign
    pk, sk = generate_keypair()
    pk_bytes = bytes(pk)
    bits_data = pk_bytes[1:]; bp = bip = 0; h = []
    for _ in range(N_FAL):
        v = 0
        for _ in range(14):
            v = (v << 1) | ((bits_data[bp] >> (7 - bip)) & 1); bip += 1
            if bip == 8: bip = 0; bp += 1
        h.append(v)
    ntth = ntt_fw(h, Q_FAL, N_FAL, _fal_tw)
    ntth_flat = b"".join(c.to_bytes(2, "big") for c in ntth)
    msg = b"gas profile falcon"
    sig = sign(sk, msg)
    nonce = sig[1:41]; comp = sig[41:]
    bp = bip = 0
    def rb():
        nonlocal bp, bip
        b = (comp[bp] >> (7 - bip)) & 1; bip += 1
        if bip == 8: bip = 0; bp += 1
        return b
    s2 = []
    for _ in range(N_FAL):
        s = rb(); lo = 0
        for _ in range(7): lo = (lo << 1) | rb()
        hi = 0
        while True:
            b = rb()
            if b == 1: break
            hi += 1
        s2.append(Q_FAL - ((hi << 7) | lo) if s == 1 else (hi << 7) | lo)
    return b"".join(c.to_bytes(2, "big") for c in s2) + ntth_flat + nonce + msg

# ── Dilithium calldata (all local) ──

def expand_a(rho):
    a = []
    for i in range(K):
        row = []
        for j in range(L):
            xof = shake128(rho + bytes([j, i]), 840)
            poly = []; p = 0
            while len(poly) < N_DIL:
                val = xof[p] | (xof[p+1] << 8) | ((xof[p+2] & 0x7F) << 16)
                p += 3
                if val < Q_DIL:
                    poly.append(val)
            row.append(poly)
        a.append(row)
    return a

def sample_in_ball(c_tilde):
    xof = shake256(c_tilde, 272)
    signs = int.from_bytes(xof[:8], "little")
    c = [0] * N_DIL; pos = 8; si = 0
    for i in range(N_DIL - 39, N_DIL):
        while True:
            j = xof[pos]; pos += 1
            if j <= i:
                c[i] = c[j]
                c[j] = (Q_DIL - 1) if ((signs >> si) & 1) else 1
                si += 1; break
    return c

def decompose(r):
    r0 = r % ALPHA
    r0c = r0 - ALPHA if r0 > ALPHA // 2 else r0
    rmr0 = r - r0c
    if rmr0 == Q_DIL - 1:
        return 0, r0c - 1
    return rmr0 // ALPHA, r0c

def use_hint(h, r_poly):
    w1 = []
    for i in range(N_DIL):
        r1, r0 = decompose(r_poly[i])
        if h[i]:
            w1.append((r1 + 1) % M_HINT if r0 > 0 else (r1 + M_HINT - 1) % M_HINT)
        else:
            w1.append(r1)
    return w1

def encode_w1(w1_polys):
    out = bytearray()
    for poly in w1_polys:
        buf = bits = 0
        for c in poly:
            buf |= c << bits; bits += 6
            while bits >= 8:
                out.append(buf & 0xFF); buf >>= 8; bits -= 8
    return bytes(out)

def decode_pk(pk):
    rho = pk[:32]; packed = pk[32:]
    t1 = []; buf = bits = pos = 0
    for _ in range(K):
        poly = []
        for _ in range(N_DIL):
            while bits < 10:
                buf |= packed[pos] << bits; bits += 8; pos += 1
            poly.append(buf & 0x3FF); buf >>= 10; bits -= 10
        t1.append(poly)
    return rho, t1

def decode_sig(sig):
    c_tilde = sig[:32]
    z_packed = sig[32:32 + L * N_DIL * 18 // 8]
    z = []; buf = bits = pos = 0
    for _ in range(L):
        poly = []
        for _ in range(N_DIL):
            while bits < 18:
                buf |= z_packed[pos] << bits; bits += 8; pos += 1
            raw = buf & 0x3FFFF; buf >>= 18; bits -= 18
            poly.append((GAMMA1 - raw) % Q_DIL)
        z.append(poly)
    h_packed = sig[32 + L * N_DIL * 18 // 8:]
    h = [[False]*N_DIL for _ in range(K)]; idx = 0
    for i in range(K):
        limit = h_packed[80 + i]
        while idx < limit:
            h[i][h_packed[idx]] = True; idx += 1
    return c_tilde, z, h

def poly_to_3be(poly):
    return b"".join(c.to_bytes(3, "big") for c in poly)

def build_dilithium_cd():
    from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign
    pk, sk = generate_keypair()
    pk_bytes = bytes(pk)
    msg = b"gas profile dilithium"
    sig = sign(sk, msg)

    rho, t1 = decode_pk(pk_bytes)
    c_tilde, z, h = decode_sig(bytes(sig))

    # All NTT locally
    a_ntt = expand_a(rho)
    z_ntt = [ntt_fw(zi, Q_DIL, N_DIL, _dil_tw) for zi in z]
    az_ntt = []
    for i in range(K):
        acc = vec_mul(a_ntt[i][0], z_ntt[0], Q_DIL)
        for j in range(1, L):
            acc = vec_add(acc, vec_mul(a_ntt[i][j], z_ntt[j], Q_DIL), Q_DIL)
        az_ntt.append(acc)

    c_poly = sample_in_ball(c_tilde)
    c_ntt = ntt_fw(c_poly, Q_DIL, N_DIL, _dil_tw)
    t1_d_ntt = [ntt_fw([(x << D) % Q_DIL for x in ti], Q_DIL, N_DIL, _dil_tw) for ti in t1]

    w1_polys = []
    for i in range(K):
        ct1 = vec_mul(c_ntt, t1_d_ntt[i], Q_DIL)
        w_ntt = vec_sub(az_ntt[i], ct1, Q_DIL)
        w_approx = ntt_inv(w_ntt, Q_DIL, N_DIL, _dil_tw_inv)
        w1_polys.append(use_hint(h[i], w_approx))

    cd = bytearray()
    for i in range(K):
        for j in range(L):
            cd += poly_to_3be(a_ntt[i][j])
    for p in z: cd += poly_to_3be(p)
    cd += poly_to_3be(c_ntt)
    for p in t1_d_ntt: cd += poly_to_3be(p)
    cd += encode_w1(w1_polys)
    cd += c_tilde
    cd += pk_bytes
    cd += len(msg).to_bytes(32, "big")
    cd += msg
    return bytes(cd)

# ── Deploy / Send / Trace ──

def deploy(yul_path):
    r = subprocess.run(["solc","--strict-assembly","--optimize","--optimize-runs","10000","--bin",str(yul_path)],
                       capture_output=True, text=True)
    init_hex = [l for l in r.stdout.strip().split("\n") if len(l)>20 and all(c in "0123456789abcdef" for c in l)][0]
    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    tx = {"from":acct.address,"nonce":nonce,"gas":5_000_000,"gasPrice":w3.eth.gas_price,
          "data":"0x"+init_hex,"chainId":w3.eth.chain_id}
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), 120)
    return receipt.contractAddress

def send_tx(to, data):
    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    tx = {"from":acct.address,"to":to,"nonce":nonce,"gas":10_000_000,
          "gasPrice":w3.eth.gas_price,"data":"0x"+data.hex(),"chainId":w3.eth.chain_id}
    txh = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(txh, 120)
    return receipt, txh

CATEGORIES = {
    "STATICCALL":   {"STATICCALL"},
    "Memory":       {"MLOAD","MSTORE","MSTORE8","MCOPY","CALLDATACOPY","CALLDATALOAD",
                     "CALLDATASIZE","RETURNDATASIZE","RETURNDATACOPY","CODECOPY","CODESIZE"},
    "Arithmetic":   {"ADD","SUB","MUL","DIV","SDIV","MOD","SMOD","ADDMOD","MULMOD","EXP",
                     "LT","GT","SLT","SGT","EQ","ISZERO","AND","OR","XOR","NOT","BYTE","SHL","SHR","SAR"},
    "Stack":        {f"PUSH{i}" for i in range(33)} | {f"DUP{i}" for i in range(1,17)} |
                    {f"SWAP{i}" for i in range(1,17)} | {"POP"},
    "Control":      {"JUMP","JUMPI","JUMPDEST","PC","STOP","RETURN","REVERT","GAS"},
}

def bar(value, total, width=40):
    return "█" * int(value / total * width) if total else ""

def profile(label, addr, calldata):
    cd_gas = sum(4 if b == 0 else 16 for b in calldata)
    receipt, txh = send_tx(addr, calldata)
    total = receipt.gasUsed

    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"{'='*70}")
    print(f"  Total: {total:,} gas | Calldata: {len(calldata):,} bytes")

    # Trace (skip for large txs — Erigon OOMs on huge struct logs)
    result = None
    if total < 300_000:
        try:
            r = requests.post(RPC, json={"jsonrpc":"2.0","method":"debug_traceTransaction",
                "params":["0x"+txh.hex(), {}],"id":1}, timeout=30)
            result = r.json().get("result")
        except Exception:
            pass

    cat_gas = {c: 0 for c in CATEGORIES}; cat_gas["Other"] = 0
    op_gas = {}
    has_trace = result and "structLogs" in result and len(result["structLogs"]) > 0

    if has_trace:
        logs = result["structLogs"]
        for i, log in enumerate(logs):
            op = log.get("op","")
            # For STATICCALL, gasCost is the gas forwarded (huge).
            # Compute actual cost: gas_before - gas_after (next log).
            if op == "STATICCALL" and i + 1 < len(logs):
                gc = log.get("gas",0) - logs[i+1].get("gas",0)
            else:
                gc = log.get("gasCost",0)
            if gc < 0: gc = 0
            op_gas.setdefault(op, {"count":0,"gas":0})
            op_gas[op]["count"] += 1; op_gas[op]["gas"] += gc
            found = False
            for cat, ops in CATEGORIES.items():
                if op in ops: cat_gas[cat] += gc; found = True; break
            if not found: cat_gas["Other"] += gc
        evm_total = sum(cat_gas.values())

        print(f"\n  {'Component':<20} {'Gas':>10} {'%':>6}  Chart")
        print(f"  {'-'*62}")
        rows = [("Base tx", 21000), ("Calldata", cd_gas),
                ("STATICCALL", cat_gas["STATICCALL"]),
                ("Memory ops", cat_gas["Memory"]),
                ("Arithmetic", cat_gas["Arithmetic"]),
                ("Stack ops", cat_gas["Stack"]),
                ("Control flow", cat_gas["Control"]),
                ("Other EVM", cat_gas["Other"])]
        for name, gas in rows:
            print(f"  {name:<20} {gas:>10,} {gas/total*100:>5.1f}%  {bar(gas,total)}")
        print(f"  {'-'*62}")
        print(f"  {'TOTAL':<20} {total:>10,}")

        print(f"\n  Top opcodes ({len(result['structLogs']):,} total):")
        print(f"  {'Opcode':<16} {'Count':>8} {'Gas':>10} {'%':>6}")
        print(f"  {'-'*42}")
        for op, d in sorted(op_gas.items(), key=lambda x:-x[1]["gas"])[:15]:
            print(f"  {op:<16} {d['count']:>8} {d['gas']:>10,} {d['gas']/evm_total*100:>5.1f}%")
    else:
        evm_exec = total - 21000 - cd_gas
        print(f"\n  {'Component':<20} {'Gas':>10} {'%':>6}  Chart")
        print(f"  {'-'*62}")
        for name, gas in [("Base tx",21000),("Calldata",cd_gas),("EVM execution",evm_exec)]:
            print(f"  {name:<20} {gas:>10,} {gas/total*100:>5.1f}%  {bar(gas,total)}")
        print(f"  {'-'*62}")
        print(f"  {'TOTAL':<20} {total:>10,}")

    return {"contract":label, "total_gas":total, "calldata_bytes":len(calldata),
            "calldata_gas":cd_gas, "base_tx":21000, "evm_execution":total-21000-cd_gas,
            **{f"evm_{k.lower()}":v for k,v in cat_gas.items()}}

# ── Main ──

print(f"Connected to {RPC} ({w3.eth.get_balance(acct.address)/1e18:.0f} ETH)")

print("\nBuilding calldata locally...")
falcon_cd = build_falcon_cd()
print(f"  Falcon: {len(falcon_cd)} bytes")
dil_cd = build_dilithium_cd()
print(f"  Dilithium: {len(dil_cd)} bytes")

print("Building Dilithium direct calldata...")
# For DilithiumVerifierDirectVerify: pk(1312) | sig(2420) | msg(var)
# The Rust precompile expects raw dilithium2 format (no FIPS 204 context prefix).
# But the Python ml_dsa_44 adds context. So prepend 0x00||0x00 to msg.
from pqcrypto.sign.ml_dsa_44 import generate_keypair as _dk2, sign as _ds2
_dpk2, _dsk2 = _dk2()
_dmsg2 = b"gas profile dilithium direct"
_dsig2 = _ds2(_dsk2, _dmsg2)
# ml_dsa_44 internally hashes with M' = 0x00||0x00||msg, so pass that to precompile
dil_direct_cd = bytes(_dpk2) + bytes(_dsig2) + b"\x00\x00" + _dmsg2
print(f"  Dilithium direct: {len(dil_direct_cd)} bytes")

print("\nDeploying contracts...")
addrs = {}
for name in ["FalconVerifierDirectVerify","FalconVerifierNTTWithLpNorm",
             "FalconVerifierNTT","DilithiumVerifierNTT","DilithiumVerifierDirectVerify"]:
    addrs[name] = deploy(CONTRACTS / f"{name}.yul")
    print(f"  {name}: {addrs[name]}")

results = []
results.append(profile("FalconVerifierDirectVerify", addrs["FalconVerifierDirectVerify"], falcon_cd))
results.append(profile("FalconVerifierNTTWithLpNorm", addrs["FalconVerifierNTTWithLpNorm"], falcon_cd))
results.append(profile("FalconVerifierNTT", addrs["FalconVerifierNTT"], falcon_cd))
results.append(profile("DilithiumVerifierNTT", addrs["DilithiumVerifierNTT"], dil_cd))
results.append(profile("DilithiumVerifierDirectVerify", addrs["DilithiumVerifierDirectVerify"], dil_direct_cd))

# CSV
fields = ["contract","total_gas","calldata_bytes","calldata_gas","base_tx","evm_execution",
          "evm_staticcall","evm_memory","evm_arithmetic","evm_stack","evm_control","evm_other"]
with open(OUT_CSV, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in results: w.writerow(r)
print(f"\nCSV: {OUT_CSV}")

print(f"\n{'='*70}")
print(f"  {'Contract':<35} {'Gas':>10} {'Calldata':>10}")
print(f"  {'-'*58}")
for r in results:
    print(f"  {r['contract']:<35} {r['total_gas']:>10,} {r['calldata_bytes']:>8,} B")
