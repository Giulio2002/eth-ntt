#ifndef ETH_NTT_H
#define ETH_NTT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Precompile entry points ──
 *
 * Take raw EVM calldata, return output_bytes.
 * Return 0 on success, negative on error:
 *   -1: input too short
 *   -2: invalid field parameters
 *   -3: unexpected input length
 *   -4: parameter overflow
 *
 * On success, *output_out and *output_len_out are set to a heap-allocated
 * buffer that the caller must free with eth_ntt_free_buffer().
 */

int32_t eth_ntt_fw_precompile(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_inv_precompile(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_vecmulmod_precompile(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_vecaddmod_precompile(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

void eth_ntt_free_buffer(uint8_t *ptr, size_t len);

/* ── Fast direct API ──
 *
 * For callers who want to avoid precompile encoding overhead.
 * FastNttParams precomputes twiddle tables and is safe to share
 * across threads (read-only after creation).
 */

typedef struct FastNttParams FastNttParams;

FastNttParams *eth_ntt_fast_params_new(uint64_t q, size_t n, uint64_t psi);
void eth_ntt_fast_params_free(FastNttParams *params);
uint64_t eth_ntt_fast_params_q(const FastNttParams *params);
size_t eth_ntt_fast_params_n(const FastNttParams *params);
size_t eth_ntt_fast_params_coeff_bytes(const FastNttParams *params);

void eth_ntt_fw(
    const FastNttParams *params,
    const uint64_t *input, uint64_t *output, size_t n);

void eth_ntt_inv(
    const FastNttParams *params,
    const uint64_t *input, uint64_t *output, size_t n);

void eth_ntt_vec_mul_mod(
    const uint64_t *a, const uint64_t *b,
    uint64_t *output, size_t n, uint64_t q);

void eth_ntt_vec_add_mod(
    const uint64_t *a, const uint64_t *b,
    uint64_t *output, size_t n, uint64_t q);

/* ── EVM compact format (Falcon-512 specific) ──
 *
 * Compact: 1024 bytes = 32 big-endian uint256 words, each packing
 * 16 little-endian uint16 coefficients. Falcon-512 params hardcoded
 * (q=12289, n=512, psi=49).
 */

int32_t eth_ntt_fw_compact(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_inv_compact(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

int32_t eth_ntt_vecmulmod_compact(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

/* SHAKE256 hash-to-point: input = salt||msg, output = 1024 bytes compact */
int32_t eth_ntt_shake256_htp(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

/* Falcon-512 norm check on compact data.
 * Input: s1(1024) || s2(1024) || hashed(1024) = 3072 bytes
 * Output: 32 bytes (0x00..01 valid, 0x00..00 invalid) */
int32_t eth_ntt_falcon_norm(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

/* Full Falcon-512 verify: SHAKE256 HTP + NTT + VECMUL + INTT + norm check.
 * Input: salt_msg_len(32 BE) | s2_compact(1024) | ntth_compact(1024) | salt_msg(salt_msg_len)
 * Output: 32 bytes (0x00..01 valid, 0x00..00 invalid) */
int32_t eth_ntt_falcon_verify(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

/* Falcon-512 verify v2: zero-copy layout.
 * Input: s2_compact(1024) | ntth_compact(1024) | salt_msg(var)
 * Output: 32 bytes bool */
int32_t eth_ntt_falcon_verify_v2(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

/* Generalized LpNorm for any lattice-based signature.
 * Input: q(32 BE) | n(32 BE) | bound(32 BE) | cb(32 BE) | s1(n*cb) | s2(n*cb) | hashed(n*cb)
 * Computes centered L2: ||(hashed - s1) mod q||^2 + ||s2||^2 < bound
 * Output: 32 bytes (0x00..01 valid, 0x00..00 invalid) */
int32_t eth_ntt_lp_norm(
    const uint8_t *input, size_t input_len,
    uint8_t **output_out, size_t *output_len_out);

#ifdef __cplusplus
}
#endif

#endif /* ETH_NTT_H */
