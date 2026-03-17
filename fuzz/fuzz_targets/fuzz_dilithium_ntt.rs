#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_eth_precompiles::{FastNttParams, ntt_fw_fast, ntt_inv_fast, vec_mul_mod_fast, vec_add_mod_fast};

const Q: u64 = 8380417;
const N: usize = 256;
const PSI: u64 = 1753; // FIPS 204 zeta, primitive 512th root of unity mod q

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let params = FastNttParams::new(Q, N, PSI).unwrap();

    // Generate two polynomials from fuzz input
    let mut a = vec![0u64; N];
    let mut b = vec![0u64; N];
    for i in 0..N {
        let idx = i % data.len();
        a[i] = (data[idx] as u64 * 37 + i as u64 * 13 + data[0] as u64) % Q;
        b[i] = (data[idx] as u64 * 53 + i as u64 * 7 + data[1] as u64) % Q;
    }

    // NTT roundtrip: INTT(NTT(a)) == a
    let ntt_a = ntt_fw_fast(&a, &params);
    let recovered = ntt_inv_fast(&ntt_a, &params);
    assert_eq!(a, recovered, "NTT roundtrip failed for Dilithium params");

    // Polynomial multiplication via NTT
    let ntt_b = ntt_fw_fast(&b, &params);
    let product_ntt = vec_mul_mod_fast(&ntt_a, &ntt_b, Q);
    let product = ntt_inv_fast(&product_ntt, &params);

    // Verify product coefficients are in [0, q)
    for (i, &c) in product.iter().enumerate() {
        assert!(c < Q, "product[{}] = {} >= q", i, c);
    }

    // Verify against schoolbook multiplication mod X^n+1
    let mut expected = vec![0u64; N];
    for i in 0..N {
        for j in 0..N {
            let c = ((a[i] as u128 * b[j] as u128) % Q as u128) as u64;
            if i + j < N {
                expected[i + j] = (expected[i + j] + c) % Q;
            } else {
                let idx = i + j - N;
                expected[idx] = (expected[idx] + Q - c) % Q;
            }
        }
    }
    assert_eq!(product, expected, "NTT polymul mismatch for Dilithium params");

    // VECADDMOD check
    let sum = vec_add_mod_fast(&a, &b, Q);
    for i in 0..N {
        assert_eq!(sum[i], (a[i] + b[i]) % Q, "vecaddmod mismatch at {}", i);
    }

    // Test SHAKE precompile with Dilithium-relevant calls
    // SHAKE128 for ExpandA pattern
    let mode = data[2] % 2;
    let security: usize = if mode == 0 { 128 } else { 256 };
    let output_len: usize = (data[3] as usize % 128) + 1;

    let mut shake_input = Vec::new();
    // security (32 bytes BE)
    shake_input.extend_from_slice(&[0u8; 24]);
    shake_input.extend_from_slice(&(security as u64).to_be_bytes());
    // output_len (32 bytes BE)
    shake_input.extend_from_slice(&[0u8; 24]);
    shake_input.extend_from_slice(&(output_len as u64).to_be_bytes());
    // data
    shake_input.extend_from_slice(&data[4..]);

    let result = pq_eth_precompiles::shake_precompile(&shake_input).unwrap();
    assert_eq!(result.len(), output_len, "SHAKE output length mismatch");

    // Deterministic: same input → same output
    let result2 = pq_eth_precompiles::shake_precompile(&shake_input).unwrap();
    assert_eq!(result, result2, "SHAKE not deterministic");
});
