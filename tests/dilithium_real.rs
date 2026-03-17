use pq_eth_precompiles::{
    FastNttParams, ntt_fw_fast, ntt_inv_fast, vec_mul_mod_fast, vec_add_mod_fast, shake_n,
};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

const Q: u64 = 8380417;
const N: usize = 256;
const PSI: u64 = 1753; // FIPS 204 zeta
const K: usize = 4;
const L: usize = 4;
const D: u32 = 13;
const TAU: usize = 39;
const GAMMA1: u64 = 1 << 17; // 131072
const GAMMA2: u64 = (Q - 1) / 88; // 95232
const BETA: u64 = TAU as u64 * 2; // 78

fn dilithium_params() -> FastNttParams {
    FastNttParams::new(Q, N, PSI).unwrap()
}

// ─── Decoding ───

fn decode_pk(pk: &[u8]) -> (Vec<u8>, Vec<Vec<u64>>) {
    assert_eq!(pk.len(), 1312);
    let rho = pk[0..32].to_vec();
    let mut t1 = Vec::with_capacity(K);
    let packed = &pk[32..];
    // t1 coefficients are 10-bit packed
    let mut bits_buf: u32 = 0;
    let mut bits_left: u32 = 0;
    let mut pos = 0;
    for _ in 0..K {
        let mut poly = Vec::with_capacity(N);
        for _ in 0..N {
            while bits_left < 10 {
                bits_buf |= (packed[pos] as u32) << bits_left;
                bits_left += 8;
                pos += 1;
            }
            poly.push((bits_buf & 0x3FF) as u64);
            bits_buf >>= 10;
            bits_left -= 10;
        }
        t1.push(poly);
    }
    (rho, t1)
}

fn decode_sig(sig: &[u8]) -> (Vec<u8>, Vec<Vec<u64>>, Vec<Vec<bool>>) {
    assert_eq!(sig.len(), 2420);
    let c_tilde = sig[0..32].to_vec();

    // z: 4 polynomials, each coefficient in [-(gamma1-1), gamma1], stored as gamma1 - z_i (18-bit)
    let z_packed = &sig[32..32 + L * N * 18 / 8];
    let mut z = Vec::with_capacity(L);
    let mut bits_buf: u64 = 0;
    let mut bits_left: u32 = 0;
    let mut pos = 0;
    for _ in 0..L {
        let mut poly = Vec::with_capacity(N);
        for _ in 0..N {
            while bits_left < 18 {
                bits_buf |= (z_packed[pos] as u64) << bits_left;
                bits_left += 8;
                pos += 1;
            }
            let raw = (bits_buf & 0x3FFFF) as u64; // 18-bit value = gamma1 - z_i
            bits_buf >>= 18;
            bits_left -= 18;
            // z_i = gamma1 - raw, centered to [0, q)
            let z_i = if GAMMA1 >= raw {
                (Q + GAMMA1 - raw) % Q
            } else {
                Q - ((raw - GAMMA1) % Q)
            };
            poly.push(z_i);
        }
        z.push(poly);
    }

    // h: hint bit-packing (omega + k = 84 bytes)
    let h_packed = &sig[32 + L * N * 18 / 8..];
    let mut h = vec![vec![false; N]; K];
    let omega = 80usize;
    let mut idx = 0;
    for i in 0..K {
        let limit = h_packed[omega + i] as usize;
        while idx < limit {
            h[i][h_packed[idx] as usize] = true;
            idx += 1;
        }
    }

    (c_tilde, z, h)
}

// ─── Core ML-DSA operations ───

fn expand_a(rho: &[u8], params: &FastNttParams) -> Vec<Vec<Vec<u64>>> {
    // A[i][j] = NTT(SHAKE128(rho || j || i)) with rejection sampling
    let mut a = Vec::with_capacity(K);
    for i in 0..K {
        let mut row = Vec::with_capacity(L);
        for j in 0..L {
            let mut seed = Vec::with_capacity(34);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);

            // SHAKE128, enough output for rejection sampling
            // Need ~256 coefficients, each from 3 bytes, rejection rate ~0.1%
            // 256 * 3 * 1.01 ≈ 776 bytes should be plenty
            let mut xof_out = [0u8; 840];
            shake_n(128, &seed, &mut xof_out);

            let mut poly = Vec::with_capacity(N);
            let mut p = 0;
            while poly.len() < N {
                let b0 = xof_out[p] as u64;
                let b1 = xof_out[p + 1] as u64;
                let b2 = xof_out[p + 2] as u64;
                p += 3;
                let val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16); // 23-bit
                if val < Q {
                    poly.push(val);
                }
            }
            // A is already in NTT domain per FIPS 204
            row.push(poly);
        }
        a.push(row);
    }
    a
}

fn sample_in_ball(c_tilde: &[u8]) -> Vec<u64> {
    // FIPS 204 Algorithm 31: SHAKE256(c_tilde) → challenge polynomial
    let mut xof_out = [0u8; 272]; // plenty for tau=39 with rejections
    shake_n(256, c_tilde, &mut xof_out);

    let mut c = vec![0u64; N];
    let signs: u64 = u64::from_le_bytes(xof_out[0..8].try_into().unwrap());
    let mut pos = 8;
    let mut sign_idx = 0;

    for i in (N - TAU)..N {
        loop {
            assert!(pos < xof_out.len(), "ran out of XOF output in SampleInBall");
            let j = xof_out[pos] as usize;
            pos += 1;
            if j <= i {
                c[i] = c[j];
                c[j] = if (signs >> sign_idx) & 1 == 1 { Q - 1 } else { 1 };
                sign_idx += 1;
                break;
            }
        }
    }
    c
}

/// FIPS 204 Algorithm 37: Decompose(r) → (r1, r0) where r0 is centered.
fn decompose(r: u64) -> (u64, i64) {
    let alpha = 2 * GAMMA2; // 190464
    let r0_unsigned = r % alpha;
    let r0_centered = if r0_unsigned > alpha / 2 {
        r0_unsigned as i64 - alpha as i64
    } else {
        r0_unsigned as i64
    };

    let r_minus_r0 = (r as i64 - r0_centered) as u64;
    if r_minus_r0 == Q - 1 {
        (0, r0_centered - 1)
    } else {
        (r_minus_r0 / alpha, r0_centered)
    }
}

/// FIPS 204 Algorithm 39: UseHint.
fn use_hint(h: &[bool], r: &[u64]) -> Vec<u64> {
    let alpha = 2 * GAMMA2;
    let m = (Q - 1) / alpha; // 44 (number of high-order representatives)
    let mut w1 = Vec::with_capacity(N);
    for i in 0..N {
        let (r1, r0) = decompose(r[i]);
        if h[i] {
            if r0 > 0 {
                w1.push((r1 + 1) % m);
            } else {
                w1.push((r1 + m - 1) % m); // r1 - 1 mod m
            }
        } else {
            w1.push(r1);
        }
    }
    w1
}

fn vec_sub_mod(a: &[u64], b: &[u64], q: u64) -> Vec<u64> {
    a.iter().zip(b.iter()).map(|(&ai, &bi)| (q + ai - bi) % q).collect()
}

fn encode_w1(w1_polys: &[Vec<u64>]) -> Vec<u8> {
    // Pack w1 coefficients (each in [0, 43]) as 6-bit values
    let mut out = Vec::new();
    for poly in w1_polys {
        let mut bits_buf: u32 = 0;
        let mut bits_left: u32 = 0;
        for &c in poly {
            bits_buf |= (c as u32) << bits_left;
            bits_left += 6;
            while bits_left >= 8 {
                out.push((bits_buf & 0xFF) as u8);
                bits_buf >>= 8;
                bits_left -= 8;
            }
        }
        if bits_left > 0 {
            out.push((bits_buf & 0xFF) as u8);
        }
    }
    out
}

/// Verify ML-DSA-44 using our NTT precompile functions.
fn verify_dilithium_via_precompiles(
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<(), String> {
    let params = dilithium_params();
    let (rho, t1) = decode_pk(pk_bytes);
    let (c_tilde, z, h) = decode_sig(sig_bytes);

    // 1. Check infinity norm of z
    let half_q = Q / 2;
    for (pi, poly) in z.iter().enumerate() {
        for (ci, &coeff) in poly.iter().enumerate() {
            let centered = if coeff > half_q { Q - coeff } else { coeff };
            if centered >= GAMMA1 - BETA {
                return Err(format!("z[{}][{}] infinity norm failed: {} >= {}", pi, ci, centered, GAMMA1 - BETA));
            }
        }
    }

    // 2. Expand A from rho
    let a_ntt = expand_a(&rho, &params);

    // 3. Compute NTT(z_j) for each j
    let z_ntt: Vec<Vec<u64>> = z.iter()
        .map(|zi| ntt_fw_fast(zi, &params))
        .collect();

    // 4. Compute Az_ntt = A × NTT(z) (matrix-vector in NTT domain)
    let mut az_ntt = Vec::with_capacity(K);
    for i in 0..K {
        let mut acc = vec_mul_mod_fast(&a_ntt[i][0], &z_ntt[0], Q);
        for j in 1..L {
            let prod = vec_mul_mod_fast(&a_ntt[i][j], &z_ntt[j], Q);
            acc = vec_add_mod_fast(&acc, &prod, Q);
        }
        az_ntt.push(acc);
    }

    // 5. Compute tr = SHAKE256(pk)[:64], mu = SHAKE256(tr || msg)
    let mut tr = [0u8; 64];
    shake_n(256, pk_bytes, &mut tr);
    let mut mu_input = Vec::with_capacity(64 + message.len());
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(message);
    let mut mu = [0u8; 64];
    shake_n(256, &mu_input, &mut mu);

    // 6. Sample challenge c from c_tilde (FIPS 204 Algorithm 3, step 7)
    let c = sample_in_ball(&c_tilde);
    let c_ntt = ntt_fw_fast(&c, &params);

    // 7. NTT(t1 << d)
    let t1_d_ntt: Vec<Vec<u64>> = t1.iter()
        .map(|ti| {
            let scaled: Vec<u64> = ti.iter().map(|&x| (x << D) % Q).collect();
            ntt_fw_fast(&scaled, &params)
        })
        .collect();

    // 8. w_approx = INTT(Az - c*t1*2^d) for each row
    let mut w1_polys = Vec::with_capacity(K);
    for i in 0..K {
        let ct1 = vec_mul_mod_fast(&c_ntt, &t1_d_ntt[i], Q);
        let w_ntt = vec_sub_mod(&az_ntt[i], &ct1, Q);
        let w_approx = ntt_inv_fast(&w_ntt, &params);
        let w1 = use_hint(&h[i], &w_approx);
        w1_polys.push(w1);
    }

    // 9. Recompute c_tilde and compare
    let w1_encoded = encode_w1(&w1_polys);
    let mut c_tilde_input = Vec::with_capacity(64 + w1_encoded.len());
    c_tilde_input.extend_from_slice(&mu);
    c_tilde_input.extend_from_slice(&w1_encoded);
    let mut c_tilde_check = [0u8; 32];
    shake_n(256, &c_tilde_input, &mut c_tilde_check);

    if c_tilde_check != c_tilde.as_slice() {
        return Err(format!(
            "challenge hash mismatch:\n  expected: {:02x?}\n  got:      {:02x?}",
            &c_tilde[..8], &c_tilde_check[..8]
        ));
    }

    Ok(())
}

#[test]
fn dilithium_real_multiple_messages() {
    let (pk, sk) = dilithium2::keypair();

    let messages: &[&[u8]] = &[
        b"",
        b"a",
        b"The quick brown fox jumps over the lazy dog",
        &[0u8; 1024],
        &(0..=255).collect::<Vec<u8>>(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let sig = dilithium2::detached_sign(msg, &sk);

        dilithium2::verify_detached_signature(&sig, msg, &pk)
            .unwrap_or_else(|_| panic!("library verify failed for message {}", i));

        verify_dilithium_via_precompiles(pk.as_bytes(), sig.as_bytes(), msg)
            .unwrap_or_else(|e| panic!("precompile verify failed for message {}: {}", i, e));

        // Test the direct DILITHIUM_VERIFY precompile
        let mut precompile_input = Vec::new();
        precompile_input.extend_from_slice(pk.as_bytes());
        precompile_input.extend_from_slice(sig.as_bytes());
        precompile_input.extend_from_slice(msg);
        let result = pq_eth_precompiles::falcon::dilithium_verify_precompile(&precompile_input)
            .unwrap_or_else(|| panic!("dilithium_verify_precompile returned None for message {}", i));
        assert_eq!(result[31], 1, "dilithium_verify_precompile rejected valid sig for message {}", i);
    }
}
