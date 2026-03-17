#!/usr/bin/env python3
"""
Gas profiler for NTT verifier contracts.
Builds all calldata LOCALLY. Only hits devnet for deploy + estimate + trace.

Usage:
  RPC_URL=http://127.0.0.1:PORT python3 kurtosis/scripts/gas_profile.py
"""
import os, sys, csv, subprocess, requests, hashlib
from web3 import Web3
from pathlib import Path

RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
CONTRACTS = Path(__file__).parent.parent / "contracts"
POC = CONTRACTS / "poc"
ACCT_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OUT_CSV = Path(__file__).parent.parent.parent / "docs" / "gas_profile.csv"

w3 = Web3(Web3.HTTPProvider(RPC))
acct = w3.eth.account.from_key(ACCT_KEY)

# ── Crypto helpers (all local, no RPC) ──

Q_DIL = 8380417; N_DIL = 256; K = 4; L = 4; D = 13
GAMMA1 = 1 << 17; GAMMA2 = (Q_DIL - 1) // 88; ALPHA = 2 * GAMMA2; M_HINT = (Q_DIL - 1) // ALPHA
Q_FAL = 12289; N_FAL = 512; PSI_FAL = 49; PSI_DIL = 1753

def pow_mod(b, e, m):
    r = 1; b %= m
    while e > 0:
        if e & 1: r = r * b % m
        e >>= 1; b = b * b % m
    return r

def bit_reverse(x, bits):
    r = 0
    for _ in range(bits): r = (r << 1) | (x & 1); x >>= 1
    return r

def build_twiddles(q, n, psi):
    log_n = n.bit_length() - 1; psi_inv = pow_mod(psi, q - 2, q)
    return ([pow_mod(psi, bit_reverse(i, log_n), q) for i in range(n)],
            [pow_mod(psi_inv, bit_reverse(i, log_n), q) for i in range(n)])

def ntt_fw(a, q, n, tw):
    a = list(a); t = n; m = 1
    while m < n:
        t //= 2
        for i in range(m):
            j1 = 2 * i * t; s = tw[m + i]
            for j in range(j1, j1 + t):
                u = a[j]; v = a[j + t] * s % q; a[j] = (u + v) % q; a[j + t] = (u - v) % q
        m *= 2
    return a

def ntt_inv(a, q, n, tw_inv):
    a = list(a); t = 1; m = n
    while m > 1:
        h = m // 2
        for i in range(h):
            j1 = 2 * i * t; s = tw_inv[h + i]
            for j in range(j1, j1 + t):
                u = a[j]; v = a[j + t]; a[j] = (u + v) % q; a[j + t] = (u - v) * s % q
        t *= 2; m //= 2
    ni = pow_mod(n, q - 2, q)
    return [(x * ni) % q for x in a]

def vec_mul(a, b, q): return [(ai * bi) % q for ai, bi in zip(a, b)]
def vec_add(a, b, q): return [(ai + bi) % q for ai, bi in zip(a, b)]
def vec_sub(a, b, q): return [(q + ai - bi) % q for ai, bi in zip(a, b)]
def shake256(d, n): return hashlib.shake_256(d).digest(n)
def shake128(d, n): return hashlib.shake_128(d).digest(n)
def poly_to_3be(p): return b"".join(c.to_bytes(3, "big") for c in p)

print("Precomputing twiddle tables...")
_fal_tw, _fal_tw_inv = build_twiddles(Q_FAL, N_FAL, PSI_FAL)
_dil_tw, _dil_tw_inv = build_twiddles(Q_DIL, N_DIL, PSI_DIL)

def decode_pk(pk):
    rho = pk[:32]; packed = pk[32:]; t1 = []; buf = bits = pos = 0
    for _ in range(K):
        poly = []
        for _ in range(N_DIL):
            while bits < 10: buf |= packed[pos] << bits; bits += 8; pos += 1
            poly.append(buf & 0x3FF); buf >>= 10; bits -= 10
        t1.append(poly)
    return rho, t1

def decode_sig(sig):
    ct = sig[:32]; zp = sig[32:32 + L * N_DIL * 18 // 8]; z = []; buf = bits = pos = 0
    for _ in range(L):
        poly = []
        for _ in range(N_DIL):
            while bits < 18: buf |= zp[pos] << bits; bits += 8; pos += 1
            raw = buf & 0x3FFFF; buf >>= 18; bits -= 18
            poly.append((GAMMA1 - raw) % Q_DIL)
        z.append(poly)
    hp = sig[32 + L * N_DIL * 18 // 8:]; h = [[False]*N_DIL for _ in range(K)]; idx = 0
    for i in range(K):
        lim = hp[80 + i]
        while idx < lim: h[i][hp[idx]] = True; idx += 1
    return ct, z, h

def expand_a(rho):
    a = []
    for i in range(K):
        row = []
        for j in range(L):
            xof = shake128(rho + bytes([j, i]), 840); poly = []; p = 0
            while len(poly) < N_DIL:
                val = xof[p] | (xof[p+1] << 8) | ((xof[p+2] & 0x7F) << 16); p += 3
                if val < Q_DIL: poly.append(val)
            row.append(poly)
        a.append(row)
    return a

def sample_in_ball(ct):
    xof = shake256(ct, 272); c = [0]*N_DIL
    signs = int.from_bytes(xof[:8], "little"); pos = 8; si = 0
    for i in range(N_DIL - 39, N_DIL):
        while True:
            j = xof[pos]; pos += 1
            if j <= i: c[i] = c[j]; c[j] = (Q_DIL-1) if ((signs>>si)&1) else 1; si += 1; break
    return c

def decompose(r):
    r0 = r % ALPHA; r0c = r0 - ALPHA if r0 > ALPHA//2 else r0; rmr0 = r - r0c
    return (0, r0c-1) if rmr0 == Q_DIL-1 else (rmr0//ALPHA, r0c)

def use_hint(h, rp):
    w = []
    for i in range(N_DIL):
        r1, r0 = decompose(rp[i])
        if h[i]: w.append((r1+1) % M_HINT if r0 > 0 else (r1+M_HINT-1) % M_HINT)
        else: w.append(r1)
    return w

def encode_w1(polys):
    out = bytearray()
    for p in polys:
        buf = bits = 0
        for c in p: buf |= c << bits; bits += 6
        while bits >= 8: out.append(buf & 0xFF); buf >>= 8; bits -= 8
    return bytes(out)

# ── Deploy helpers ──

def deploy_bound(yul_path, constructor_cd):
    r = subprocess.run(["solc","--strict-assembly","--optimize","--optimize-runs","10000","--bin",str(yul_path)],
                       capture_output=True, text=True)
    ih = [l for l in r.stdout.strip().split("\n") if len(l)>20 and all(c in "0123456789abcdef" for c in l)][0]
    data = bytes.fromhex(ih) + constructor_cd
    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    tx = {"from":acct.address,"nonce":nonce,"gas":5_000_000,"gasPrice":w3.eth.gas_price,
          "data":"0x"+data.hex(),"chainId":w3.eth.chain_id}
    rcpt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), 120)
    return rcpt.contractAddress

def estimate_gas(addr, cd):
    r = requests.post(RPC, json={"jsonrpc":"2.0","method":"eth_estimateGas","params":[{
        "to":addr,"data":"0x"+cd.hex(),"gas":hex(10_000_000)}],"id":1})
    res = r.json()
    if "error" in res: return None, res["error"]["message"][:80]
    return int(res["result"], 16), None

def bar(v, t, w=40): return "█" * int(v/t*w) if t else ""

# ── Main ──

if __name__ == "__main__":
    print(f"Connected to {RPC} ({w3.eth.get_balance(acct.address)/1e18:.0f} ETH)\n")

    # ── Falcon keygen ──
    from pqcrypto.sign.falcon_512 import generate_keypair as fk, sign as fsign
    fpk, fsk = fk(); pk_bytes = bytes(fpk)
    bits_data = pk_bytes[1:]; bp = bip = 0; h = []
    for _ in range(N_FAL):
        v = 0
        for _ in range(14):
            v = (v<<1)|((bits_data[bp]>>(7-bip))&1); bip += 1
            if bip == 8: bip = 0; bp += 1
        h.append(v)
    ntth = ntt_fw(h, Q_FAL, N_FAL, _fal_tw)
    ntth_bytes = b"".join(c.to_bytes(2,"big") for c in ntth)
    fmsg = b"falcon gas profile"
    fsig = fsign(fsk, fmsg)
    fn = fsig[1:41]; comp = fsig[41:]
    _rb_state = [0, 0]  # [bp, bip]
    def rb():
        b = (comp[_rb_state[0]]>>(7-_rb_state[1]))&1; _rb_state[1] += 1
        if _rb_state[1] == 8: _rb_state[1] = 0; _rb_state[0] += 1
        return b
    s2 = []
    for _ in range(N_FAL):
        s = rb(); lo = 0
        for _ in range(7): lo = (lo<<1)|rb()
        hi = 0
        while True:
            b = rb()
            if b == 1: break
            hi += 1
        s2.append(Q_FAL-((hi<<7)|lo) if s == 1 else (hi<<7)|lo)
    s2f = b"".join(c.to_bytes(2,"big") for c in s2)
    falcon_verify_cd = s2f + fn + fmsg  # no ntth (bound in code)

    # ── Dilithium keygen ──
    from pqcrypto.sign.ml_dsa_44 import generate_keypair as dk, sign as dsign
    dpk, dsk = dk(); dpk_b = bytes(dpk)
    rho, t1 = decode_pk(dpk_b)
    t1d = [ntt_fw([(x<<D)%Q_DIL for x in ti], Q_DIL, N_DIL, _dil_tw) for ti in t1]
    tr = shake256(dpk_b, 64)

    # NTTBound deploy: rho(32) + t1_d_ntt(3072) + tr(64)
    dil_ntt_deploy = bytes(rho)
    for p in t1d: dil_ntt_deploy += poly_to_3be(p)
    dil_ntt_deploy += tr

    dmsg = b"dilithium gas profile"
    dsig = dsign(dsk, dmsg)
    ct, z, hint = decode_sig(bytes(dsig))

    # Build w1 off-chain
    z_ntt = [ntt_fw(zi, Q_DIL, N_DIL, _dil_tw) for zi in z]
    a_ntt = expand_a(rho); az = []
    for i in range(K):
        acc = vec_mul(a_ntt[i][0], z_ntt[0], Q_DIL)
        for j in range(1, L): acc = vec_add(acc, vec_mul(a_ntt[i][j], z_ntt[j], Q_DIL), Q_DIL)
        az.append(acc)
    cn = ntt_fw(sample_in_ball(ct), Q_DIL, N_DIL, _dil_tw)
    w1p = []
    for i in range(K):
        ct1 = vec_mul(cn, t1d[i], Q_DIL); wn = vec_sub(az[i], ct1, Q_DIL)
        w1p.append(use_hint(hint[i], ntt_inv(wn, Q_DIL, N_DIL, _dil_tw_inv)))

    # NTTBound verify: z + w1 + c_tilde + msg_len + msg
    dil_ntt_verify = bytearray()
    for p in z: dil_ntt_verify += poly_to_3be(p)
    dil_ntt_verify += encode_w1(w1p)
    dil_ntt_verify += ct
    dil_ntt_verify += len(dmsg).to_bytes(32, "big")
    dil_ntt_verify += dmsg
    dil_ntt_verify = bytes(dil_ntt_verify)

    # DirectBound verify: sig + 0x0000 + msg
    dil_direct_verify = bytes(dsig) + b"\x00\x00" + dmsg

    print(f"Falcon verify calldata:          {len(falcon_verify_cd)} bytes")
    print(f"Dilithium NTT verify calldata:   {len(dil_ntt_verify)} bytes")
    print(f"Dilithium direct verify calldata: {len(dil_direct_verify)} bytes")

    # ── Deploy ──
    print("\nDeploying contracts...")
    addrs = {}
    addrs["FalconNTTBound"] = deploy_bound(CONTRACTS/"FalconVerifierNTTBound.yul", ntth_bytes)
    addrs["FalconDirectBound"] = deploy_bound(CONTRACTS/"FalconVerifierDirectBound.yul", ntth_bytes)
    addrs["DilithiumNTTBound"] = deploy_bound(CONTRACTS/"DilithiumVerifierNTTBound.yul", dil_ntt_deploy)
    addrs["DilithiumDirectBound"] = deploy_bound(CONTRACTS/"DilithiumVerifierDirectBound.yul", dpk_b)

    for name, addr in addrs.items():
        print(f"  {name}: {addr} ({len(w3.eth.get_code(addr))}B)")

    # ── Benchmark ──
    results = []
    benchmarks = [
        ("FalconVerifierNTTBound", addrs["FalconNTTBound"], falcon_verify_cd),
        ("FalconVerifierDirectBound", addrs["FalconDirectBound"], falcon_verify_cd),
        ("DilithiumVerifierNTTBound", addrs["DilithiumNTTBound"], dil_ntt_verify),
        ("DilithiumVerifierDirectBound", addrs["DilithiumDirectBound"], dil_direct_verify),
    ]

    print(f"\n{'='*65}")
    print(f"  {'Contract':<35} {'Gas':>10} {'Calldata':>10}")
    print(f"{'='*65}")
    for name, addr, cd in benchmarks:
        gas, err = estimate_gas(addr, cd)
        if gas:
            cd_gas = sum(4 if b==0 else 16 for b in cd)
            evm = gas - 21000 - cd_gas
            print(f"  {name:<35} {gas:>10,} {len(cd):>8} B")
            print(f"    base=21K  cd={cd_gas:,}  evm={evm:,}")
            results.append({"contract":name, "total_gas":gas, "calldata_bytes":len(cd),
                           "calldata_gas":cd_gas, "base_tx":21000, "evm_execution":evm})
        else:
            print(f"  {name:<35} {'ERROR':>10} {err}")
    print(f"{'='*65}")

    # CSV
    fields = ["contract","total_gas","calldata_bytes","calldata_gas","base_tx","evm_execution"]
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in results: w.writerow(r)
    print(f"\nCSV: {OUT_CSV}")
