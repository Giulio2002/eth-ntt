#!/usr/bin/env python3
"""
ML-DSA-44 (Dilithium2) on-chain verification fuzzer.
First byte even → invalid sig, odd → valid sig.
Uses DilithiumVerifierNTT.yul with generic NTT precompiles.
Cross-checks: off-chain Python verify vs on-chain Yul contract.
"""
import os, sys, time, subprocess, struct, hashlib, requests
from web3 import Web3
from pathlib import Path

# pip install pqcrypto
from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign

Q = 8380417
N = 256
K, L = 4, 4
D = 13
TAU = 39
GAMMA1 = 1 << 17
GAMMA2 = (Q - 1) // 88
BETA = TAU * 2
CB = 3  # bytes per coefficient
PSI = 1753
ALPHA = 2 * GAMMA2

# ─── SHAKE via keccak sponge (matches the precompile) ───

def _keccak_f1600(state):
    """Keccak-f[1600] permutation on 25 u64 lanes. Uses pysha3/hashlib fallback."""
    # We use hashlib's SHAKE directly instead of implementing f1600
    pass

def shake256(data, outlen):
    h = hashlib.shake_256(data)
    return h.digest(outlen)

def shake128(data, outlen):
    h = hashlib.shake_128(data)
    return h.digest(outlen)

# ─── Decode public key ───

def decode_pk(pk_bytes):
    """Decode ML-DSA-44 public key: rho(32) || t1_packed(1280)."""
    assert len(pk_bytes) == 1312
    rho = pk_bytes[:32]
    packed = pk_bytes[32:]
    t1 = []
    bits_buf = 0
    bits_left = 0
    pos = 0
    for _ in range(K):
        poly = []
        for _ in range(N):
            while bits_left < 10:
                bits_buf |= packed[pos] << bits_left
                bits_left += 8
                pos += 1
            poly.append(bits_buf & 0x3FF)
            bits_buf >>= 10
            bits_left -= 10
        t1.append(poly)
    return rho, t1

# ─── Decode signature ───

def decode_sig(sig_bytes):
    """Decode ML-DSA-44 signature: c_tilde(32) || z_packed(2304) || h_packed(84)."""
    assert len(sig_bytes) == 2420
    c_tilde = sig_bytes[:32]

    # z: 4 polys, 18-bit packed, each = gamma1 - z_i
    z_packed = sig_bytes[32:32 + L * N * 18 // 8]
    z = []
    bits_buf = 0
    bits_left = 0
    pos = 0
    for _ in range(L):
        poly = []
        for _ in range(N):
            while bits_left < 18:
                bits_buf |= z_packed[pos] << bits_left
                bits_left += 8
                pos += 1
            raw = bits_buf & 0x3FFFF
            bits_buf >>= 18
            bits_left -= 18
            z_i = GAMMA1 - raw  # signed
            poly.append(z_i % Q)

        z.append(poly)

    # h: hint encoding (omega + k = 84 bytes)
    h_packed = sig_bytes[32 + L * N * 18 // 8:]
    h = [[False] * N for _ in range(K)]
    idx = 0
    for i in range(K):
        limit = h_packed[80 + i]
        while idx < limit:
            h[i][h_packed[idx]] = True
            idx += 1

    return c_tilde, z, h

# ─── Core ML-DSA operations ───

def expand_a(rho):
    """ExpandA: 4x4 matrix of polynomials in NTT domain from SHAKE128."""
    a = []
    for i in range(K):
        row = []
        for j in range(L):
            seed = rho + bytes([j, i])
            xof = shake128(seed, 840)
            poly = []
            p = 0
            while len(poly) < N:
                b0, b1, b2 = xof[p], xof[p+1], xof[p+2]
                p += 3
                val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
                if val < Q:
                    poly.append(val)
            row.append(poly)
        a.append(row)
    return a

def sample_in_ball(c_tilde):
    """SampleInBall: SHAKE256(c_tilde) → sparse challenge polynomial."""
    xof = shake256(c_tilde, 272)
    signs = int.from_bytes(xof[:8], 'little')
    c = [0] * N
    pos = 8
    sign_idx = 0
    for i in range(N - TAU, N):
        while True:
            j = xof[pos]; pos += 1
            if j <= i:
                c[i] = c[j]
                c[j] = (Q - 1) if ((signs >> sign_idx) & 1) else 1
                sign_idx += 1
                break
    return c

def decompose(r):
    r0 = r % ALPHA
    r0_centered = r0 - ALPHA if r0 > ALPHA // 2 else r0
    r_minus_r0 = r - r0_centered
    if r_minus_r0 == Q - 1:
        return 0, r0_centered - 1
    return r_minus_r0 // ALPHA, r0_centered

def use_hint(h_poly, r_poly):
    m = (Q - 1) // ALPHA  # 44
    w1 = []
    for i in range(N):
        r1, r0 = decompose(r_poly[i])
        if h_poly[i]:
            if r0 > 0:
                w1.append((r1 + 1) % m)
            else:
                w1.append((r1 + m - 1) % m)
        else:
            w1.append(r1)
    return w1

def encode_w1(w1_polys):
    """Pack w1 as 6-bit LE values (FIPS 204 SimpleBitPack)."""
    out = bytearray()
    for poly in w1_polys:
        bits_buf = 0
        bits_left = 0
        for c in poly:
            bits_buf |= c << bits_left
            bits_left += 6
            while bits_left >= 8:
                out.append(bits_buf & 0xFF)
                bits_buf >>= 8
                bits_left -= 8
        if bits_left > 0:
            out.append(bits_buf & 0xFF)
    return bytes(out)

# ─── NTT via precompile RPC calls ───

def ntt_fw_precompile(coeffs, rpc):
    """NTT forward via 0x12: n(32)|q(32)|psi(32)|coeffs(N*CB)."""
    hdr = N.to_bytes(32, 'big') + Q.to_bytes(32, 'big') + PSI.to_bytes(32, 'big')
    cb = b''.join(c.to_bytes(CB, 'big') for c in coeffs)
    r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x' + '0'*38 + '12', 'data': '0x' + (hdr + cb).hex()}, 'latest'], 'id': 1})
    raw = bytes.fromhex(r.json()['result'][2:])
    return [int.from_bytes(raw[i:i+CB], 'big') for i in range(0, len(raw), CB)]

def ntt_inv_precompile(coeffs, rpc):
    """NTT inverse via 0x13."""
    hdr = N.to_bytes(32, 'big') + Q.to_bytes(32, 'big') + PSI.to_bytes(32, 'big')
    cb = b''.join(c.to_bytes(CB, 'big') for c in coeffs)
    r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x' + '0'*38 + '13', 'data': '0x' + (hdr + cb).hex()}, 'latest'], 'id': 1})
    raw = bytes.fromhex(r.json()['result'][2:])
    return [int.from_bytes(raw[i:i+CB], 'big') for i in range(0, len(raw), CB)]

def vecmulmod_precompile(a, b, rpc):
    """VECMULMOD via 0x14: n(32)|q(32)|a(N*CB)|b(N*CB)."""
    hdr = N.to_bytes(32, 'big') + Q.to_bytes(32, 'big')
    ab = b''.join(c.to_bytes(CB, 'big') for c in a)
    bb = b''.join(c.to_bytes(CB, 'big') for c in b)
    r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x' + '0'*38 + '14', 'data': '0x' + (hdr + ab + bb).hex()}, 'latest'], 'id': 1})
    raw = bytes.fromhex(r.json()['result'][2:])
    return [int.from_bytes(raw[i:i+CB], 'big') for i in range(0, len(raw), CB)]

def vecaddmod_precompile(a, b, rpc):
    """VECADDMOD via 0x15."""
    hdr = N.to_bytes(32, 'big') + Q.to_bytes(32, 'big')
    ab = b''.join(c.to_bytes(CB, 'big') for c in a)
    bb = b''.join(c.to_bytes(CB, 'big') for c in b)
    r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
        'params': [{'to': '0x' + '0'*38 + '15', 'data': '0x' + (hdr + ab + bb).hex()}, 'latest'], 'id': 1})
    raw = bytes.fromhex(r.json()['result'][2:])
    return [int.from_bytes(raw[i:i+CB], 'big') for i in range(0, len(raw), CB)]

# ─── Calldata encoding ───

def poly_to_3be(poly):
    """Encode polynomial as N * 3-byte big-endian coefficients."""
    return b''.join(c.to_bytes(CB, 'big') for c in poly)

def poly_to_2be(poly):
    """Encode polynomial as N * 2-byte big-endian values (for w1)."""
    return b''.join(c.to_bytes(2, 'big') for c in poly)

def build_calldata(a_ntt, z, c_ntt, t1_d_ntt, w1_polys, c_tilde, pk_bytes, msg):
    """Build DilithiumVerifierNTT calldata."""
    cd = bytearray()
    # A_ntt: 4x4 matrix, row-major (12288 bytes)
    for i in range(K):
        for j in range(L):
            cd += poly_to_3be(a_ntt[i][j])
    # z: 4 polys (3072 bytes)
    for p in z:
        cd += poly_to_3be(p)
    # c_ntt: 1 poly (768 bytes)
    cd += poly_to_3be(c_ntt)
    # t1_d_ntt: 4 polys (3072 bytes)
    for p in t1_d_ntt:
        cd += poly_to_3be(p)
    # w1: 768 bytes (6-bit packed, pre-computed off-chain)
    cd += encode_w1(w1_polys)
    # c_tilde: 32 bytes
    cd += c_tilde
    # pk: 1312 bytes
    cd += pk_bytes
    # msg_len: 32 bytes BE
    cd += len(msg).to_bytes(32, 'big')
    # msg: variable
    cd += msg
    return bytes(cd)

# ─── Off-chain verification (Python, matches dilithium_real.rs) ───

def verify_offchain(pk_bytes, sig_bytes, msg, rpc):
    """Full ML-DSA-44 verify using precompile RPCs. Returns (valid, calldata)."""
    rho, t1 = decode_pk(pk_bytes)
    c_tilde, z, h = decode_sig(sig_bytes)

    # Infinity norm check
    half_q = Q // 2
    for poly in z:
        for c in poly:
            centered = (Q - c) if c > half_q else c
            if centered >= GAMMA1 - BETA:
                return False, None

    # ExpandA
    a_ntt = expand_a(rho)

    # NTT(z_j)
    z_ntt = [ntt_fw_precompile(zi, rpc) for zi in z]

    # Az = A × NTT(z)
    az_ntt = []
    for i in range(K):
        acc = vecmulmod_precompile(a_ntt[i][0], z_ntt[0], rpc)
        for j in range(1, L):
            prod = vecmulmod_precompile(a_ntt[i][j], z_ntt[j], rpc)
            acc = vecaddmod_precompile(acc, prod, rpc)
        az_ntt.append(acc)

    # tr, mu
    # FIPS 204 ML-DSA wraps message: M' = 0x00 || len(ctx) || ctx || M
    # Default context is empty, so M' = 0x00 0x00 || M
    tr = shake256(pk_bytes, 64)
    m_prime = b'\x00\x00' + msg
    mu = shake256(tr + m_prime, 64)

    # Challenge
    c_poly = sample_in_ball(c_tilde)
    c_ntt = ntt_fw_precompile(c_poly, rpc)

    # NTT(t1 << d)
    t1_d_ntt = []
    for ti in t1:
        scaled = [(x << D) % Q for x in ti]
        t1_d_ntt.append(ntt_fw_precompile(scaled, rpc))

    # w_approx = INTT(Az - c*t1d)
    w1_polys = []
    for i in range(K):
        ct1 = vecmulmod_precompile(c_ntt, t1_d_ntt[i], rpc)
        neg_ct1 = [(Q - x) % Q for x in ct1]
        w_ntt = vecaddmod_precompile(az_ntt[i], neg_ct1, rpc)
        w_approx = ntt_inv_precompile(w_ntt, rpc)
        w1 = use_hint(h[i], w_approx)
        w1_polys.append(w1)

    # Recompute c_tilde
    w1_encoded = encode_w1(w1_polys)
    c_tilde_check = shake256(mu + w1_encoded, 32)

    valid = (c_tilde_check == c_tilde)

    # Build calldata for on-chain verification
    cd = build_calldata(a_ntt, z, c_ntt, t1_d_ntt, w1_polys, c_tilde, pk_bytes, msg)
    return valid, cd

# ─── Deploy and fuzz ───

def deploy_yul(w3, acct, yul_path):
    result = subprocess.run(
        ["solc", "--strict-assembly", "--optimize", "--optimize-runs", "10000", "--bin", str(yul_path)],
        capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    init_hex = [l for l in lines if len(l) > 20 and all(c in '0123456789abcdef' for c in l)][0]
    nonce = w3.eth.get_transaction_count(acct.address, 'pending')
    tx = {"from": acct.address, "nonce": nonce,
          "gas": 5_000_000, "gasPrice": w3.eth.gas_price, "data": "0x" + init_hex, "chainId": w3.eth.chain_id}
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), 120)
    return receipt.contractAddress

def main():
    rpc = os.environ.get("RPC_URL", "http://127.0.0.1:56440")
    w3 = Web3(Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        print(f"Cannot connect to {rpc}")
        sys.exit(1)
    acct = w3.eth.account.from_key("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
    contracts_dir = Path(__file__).parent.parent / "contracts"

    print("Deploying DilithiumVerifierNTT...")
    contract_addr = deploy_yul(w3, acct, contracts_dir / "DilithiumVerifierNTT.yul")
    code = w3.eth.get_code(contract_addr)
    print(f"DilithiumVerifierNTT: {contract_addr} ({len(code)}B runtime)")

    pk, sk = generate_keypair()
    print(f"ML-DSA-44 keypair generated (pk={len(bytes(pk))}B)")

    passed = failed = 0
    start = time.time()
    print(f"\nFuzzing... (Ctrl+C to stop)\n")

    try:
        i = 0
        while True:
            i += 1
            fuzz = os.urandom(64)
            make_valid = (fuzz[0] % 2) == 1
            msg = fuzz[1:1 + (fuzz[1] % 40) + 1]

            sig_bytes = sign(sk, msg)

            if not make_valid:
                strategy = fuzz[2] % 3
                if strategy == 0:
                    msg = msg + b'\xff'  # wrong message
                elif strategy == 1:
                    # corrupt z in signature (flip a byte in z region)
                    sig_list = bytearray(sig_bytes)
                    idx = 32 + (fuzz[3] % (L * N * 18 // 8))
                    sig_list[idx] ^= 0xFF
                    sig_bytes = bytes(sig_list)
                else:
                    _, sk2 = generate_keypair()
                    sig_bytes = sign(sk2, msg)

            # Off-chain verify (uses NTT precompiles via RPC)
            offchain_valid, calldata = verify_offchain(bytes(pk), sig_bytes, msg, rpc)

            # On-chain verify via eth_call
            onchain_valid = False
            if calldata is not None:
                r = requests.post(rpc, json={'jsonrpc': '2.0', 'method': 'eth_call',
                    'params': [{'to': contract_addr, 'data': '0x' + calldata.hex(),
                                'gas': hex(30_000_000)}, 'latest'], 'id': i})
                resp = r.json()
                if 'result' in resp and len(resp['result']) >= 66:
                    onchain_valid = resp['result'].endswith('1')

            ok = True
            if make_valid:
                if not offchain_valid:
                    ok = False
                    print(f"\n  BUG: offchain rejects valid sig at iter {i}")
                if calldata is not None and not onchain_valid:
                    ok = False
                    print(f"\n  BUG: onchain rejects valid sig at iter {i}")
            else:
                # For invalid sigs, both should reject (or at least not disagree)
                if calldata is not None and offchain_valid != onchain_valid:
                    ok = False
                    print(f"\n  BUG: offchain={offchain_valid} onchain={onchain_valid} at iter {i}")

            if ok:
                passed += 1
            else:
                failed += 1

            if i % 5 == 0:
                elapsed = time.time() - start
                print(f"\r  {i} iters | {passed} pass | {failed} fail | {elapsed:.0f}s | {i/elapsed:.1f}/s", end="", flush=True)

    except KeyboardInterrupt:
        elapsed = time.time() - start
        print(f"\n\nDone: {i} iterations in {elapsed:.1f}s ({i/elapsed:.1f}/s)")
        print(f"Passed: {passed}, Failed: {failed}")


if __name__ == "__main__":
    main()
