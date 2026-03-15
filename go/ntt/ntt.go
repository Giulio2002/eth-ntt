// Package ntt provides Go bindings for the eth-ntt Rust library,
// implementing Number Theoretic Transform operations for Ethereum
// EVM precompiles with Montgomery-optimized arithmetic.

package ntt

/*
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -leth_ntt
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -leth_ntt
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -leth_ntt
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -leth_ntt
#cgo linux,riscv64 LDFLAGS: -L${SRCDIR}/lib/linux_riscv64 -leth_ntt
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -leth_ntt
#cgo windows,arm64 LDFLAGS: -L${SRCDIR}/lib/windows_arm64 -leth_ntt
#cgo linux LDFLAGS: -ldl -lpthread -lm
#cgo windows LDFLAGS: -lws2_32 -luserenv -lbcrypt -lntdll
#include "eth_ntt.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

var (
	ErrInputTooShort = errors.New("ntt: input too short")
	ErrInvalidParams = errors.New("ntt: invalid field parameters")
	ErrBadLength     = errors.New("ntt: unexpected input length")
	ErrOverflow      = errors.New("ntt: parameter overflow")
)

func precompileError(rc C.int32_t) error {
	switch rc {
	case -1:
		return ErrInputTooShort
	case -2:
		return ErrInvalidParams
	case -3:
		return ErrBadLength
	case -4:
		return ErrOverflow
	default:
		return errors.New("ntt: unknown error")
	}
}

func collectOutput(rc C.int32_t, outPtr *C.uint8_t, outLen C.size_t) ([]byte, error) {
	if rc != 0 {
		return nil, precompileError(rc)
	}
	output := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	C.eth_ntt_free_buffer(outPtr, outLen)
	return output, nil
}

// ── Precompile API ──

// NttFwPrecompile executes the NTT forward precompile on raw EVM calldata.
func NttFwPrecompile(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_fw_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// NttInvPrecompile executes the NTT inverse precompile on raw EVM calldata.
func NttInvPrecompile(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_inv_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// VecMulModPrecompile executes the vector modular multiply precompile.
func VecMulModPrecompile(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_vecmulmod_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// VecAddModPrecompile executes the vector modular add precompile.
func VecAddModPrecompile(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_vecaddmod_precompile((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// ── Fast direct API ──

// FastParams holds pre-computed NTT parameters with Montgomery-optimized
// twiddle factor tables. It is safe for concurrent use across goroutines.
type FastParams struct {
	ptr *C.FastNttParams
}

// NewFastParams creates NTT parameters for the given prime field.
//   - q: prime modulus (must be < 2^63, odd, and q ≡ 1 mod 2n)
//   - n: polynomial dimension (must be a power of 2)
//   - psi: primitive 2n-th root of unity mod q
func NewFastParams(q uint64, n int, psi uint64) (*FastParams, error) {
	ptr := C.eth_ntt_fast_params_new(C.uint64_t(q), C.size_t(n), C.uint64_t(psi))
	if ptr == nil {
		return nil, ErrInvalidParams
	}
	p := &FastParams{ptr: ptr}
	runtime.SetFinalizer(p, (*FastParams).free)
	return p, nil
}

func (p *FastParams) free() {
	if p.ptr != nil {
		C.eth_ntt_fast_params_free(p.ptr)
		p.ptr = nil
	}
}

// Close explicitly frees the underlying Rust resources.
func (p *FastParams) Close() {
	p.free()
	runtime.SetFinalizer(p, nil)
}

func (p *FastParams) Q() uint64       { return uint64(C.eth_ntt_fast_params_q(p.ptr)) }
func (p *FastParams) N() int          { return int(C.eth_ntt_fast_params_n(p.ptr)) }
func (p *FastParams) CoeffBytes() int { return int(C.eth_ntt_fast_params_coeff_bytes(p.ptr)) }

// Forward performs a forward NTT on the given coefficients.
func (p *FastParams) Forward(a []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_fw(p.ptr, u64ptr(a), u64ptr(out), C.size_t(n))
	return out
}

// Inverse performs an inverse NTT on the given coefficients.
func (p *FastParams) Inverse(a []uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_inv(p.ptr, u64ptr(a), u64ptr(out), C.size_t(n))
	return out
}

// VecMulMod computes element-wise (a[i] * b[i]) mod q.
func VecMulMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_vec_mul_mod(u64ptr(a), u64ptr(b), u64ptr(out), C.size_t(n), C.uint64_t(q))
	return out
}

// VecAddMod computes element-wise (a[i] + b[i]) mod q.
func VecAddMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	out := make([]uint64, n)
	C.eth_ntt_vec_add_mod(u64ptr(a), u64ptr(b), u64ptr(out), C.size_t(n), C.uint64_t(q))
	return out
}

func u64ptr(s []uint64) *C.uint64_t {
	return (*C.uint64_t)(unsafe.Pointer(&s[0]))
}

// ── EVM compact format (Falcon-512 specific) ──

// NttFwCompact runs NTT forward on 1024 bytes of compact EVM data.
func NttFwCompact(input []byte) ([]byte, error) {
	if len(input) != 1024 {
		return nil, ErrBadLength
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_fw_compact((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// NttInvCompact runs NTT inverse on 1024 bytes of compact EVM data.
func NttInvCompact(input []byte) ([]byte, error) {
	if len(input) != 1024 {
		return nil, ErrBadLength
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_inv_compact((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// VecMulModCompact runs pointwise multiply on 2048 bytes (two compact vectors).
func VecMulModCompact(input []byte) ([]byte, error) {
	if len(input) != 2048 {
		return nil, ErrBadLength
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_vecmulmod_compact((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// Shake256HTP runs SHAKE256 hash-to-point, returning 1024 bytes compact.
func Shake256HTP(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_shake256_htp((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// FalconNorm checks the Falcon-512 norm. Input: s1(1024)||s2(1024)||hashed(1024).
// Returns 32 bytes: 0x00..01 if valid, 0x00..00 if invalid.
func FalconNorm(input []byte) ([]byte, error) {
	if len(input) != 3072 {
		return nil, ErrBadLength
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_falcon_norm((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// FalconVerify runs full Falcon-512 verification in a single call.
// Input: salt_msg_len(32) | s2_compact(1024) | ntth_compact(1024) | salt_msg(salt_msg_len)
func FalconVerify(input []byte) ([]byte, error) {
	if len(input) < 32+2048 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_falcon_verify((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// FalconVerifyV2 runs Falcon-512 verification with zero-copy layout.
// Input: s2_compact(1024) | ntth_compact(1024) | salt_msg(var)
func FalconVerifyV2(input []byte) ([]byte, error) {
	if len(input) < 2048 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_falcon_verify_v2((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}

// LpNorm runs the generalized lattice norm check.
// Input: q(32) | n(32) | bound(32) | cb(32) | s1(n×cb) | s2(n×cb) | hashed(n×cb)
// Returns 32 bytes: 0x00..01 if valid, 0x00..00 if invalid.
func LpNorm(input []byte) ([]byte, error) {
	if len(input) < 128 {
		return nil, ErrInputTooShort
	}
	var outPtr *C.uint8_t
	var outLen C.size_t
	rc := C.eth_ntt_lp_norm((*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), &outPtr, &outLen)
	return collectOutput(rc, outPtr, outLen)
}
