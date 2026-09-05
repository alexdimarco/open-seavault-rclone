// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

func scryptKey(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt N must be a power of two greater than 1")
	}
	if r <= 0 || p <= 0 || keyLen <= 0 {
		return nil, errors.New("scrypt r, p, and key length must be positive")
	}
	if N > 1<<24 {
		return nil, fmt.Errorf("scrypt N %d is too large for this build", N)
	}
	if uint64(r)*uint64(p) >= 1<<30 {
		return nil, errors.New("scrypt parameters are too large")
	}
	B := pbkdf2Key(password, salt, 1, p*128*r, sha256.New)
	for i := 0; i < p; i++ {
		start := i * 128 * r
		smix(B[start:start+128*r], r, N)
	}
	return pbkdf2Key(password, B, 1, keyLen, sha256.New), nil
}

func smix(B []byte, r int, N int) {
	X := append([]byte(nil), B...)
	Y := make([]byte, len(B))
	V := make([]byte, N*len(B))
	for i := 0; i < N; i++ {
		copy(V[i*len(B):(i+1)*len(B)], X)
		blockMix(X, Y, r)
	}
	for i := 0; i < N; i++ {
		j := int(integerify(X, r) & uint64(N-1))
		xorBytes(X, V[j*len(B):(j+1)*len(B)])
		blockMix(X, Y, r)
	}
	copy(B, X)
}

func blockMix(B, Y []byte, r int) {
	var X [64]byte
	copy(X[:], B[(2*r-1)*64:2*r*64])
	for i := 0; i < 2*r; i++ {
		xorBytes(X[:], B[i*64:(i+1)*64])
		salsa208(&X)
		copy(Y[i*64:(i+1)*64], X[:])
	}
	for i := 0; i < r; i++ {
		copy(B[i*64:(i+1)*64], Y[(2*i)*64:(2*i+1)*64])
	}
	for i := 0; i < r; i++ {
		copy(B[(i+r)*64:(i+r+1)*64], Y[(2*i+1)*64:(2*i+2)*64])
	}
}

func integerify(B []byte, r int) uint64 {
	return binary.LittleEndian.Uint64(B[(2*r-1)*64:])
}

func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func salsa208(block *[64]byte) {
	var x [16]uint32
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	z := x
	for i := 0; i < 8; i += 2 {
		z[4] ^= bitsRotateLeft32(z[0]+z[12], 7)
		z[8] ^= bitsRotateLeft32(z[4]+z[0], 9)
		z[12] ^= bitsRotateLeft32(z[8]+z[4], 13)
		z[0] ^= bitsRotateLeft32(z[12]+z[8], 18)

		z[9] ^= bitsRotateLeft32(z[5]+z[1], 7)
		z[13] ^= bitsRotateLeft32(z[9]+z[5], 9)
		z[1] ^= bitsRotateLeft32(z[13]+z[9], 13)
		z[5] ^= bitsRotateLeft32(z[1]+z[13], 18)

		z[14] ^= bitsRotateLeft32(z[10]+z[6], 7)
		z[2] ^= bitsRotateLeft32(z[14]+z[10], 9)
		z[6] ^= bitsRotateLeft32(z[2]+z[14], 13)
		z[10] ^= bitsRotateLeft32(z[6]+z[2], 18)

		z[3] ^= bitsRotateLeft32(z[15]+z[11], 7)
		z[7] ^= bitsRotateLeft32(z[3]+z[15], 9)
		z[11] ^= bitsRotateLeft32(z[7]+z[3], 13)
		z[15] ^= bitsRotateLeft32(z[11]+z[7], 18)

		z[1] ^= bitsRotateLeft32(z[0]+z[3], 7)
		z[2] ^= bitsRotateLeft32(z[1]+z[0], 9)
		z[3] ^= bitsRotateLeft32(z[2]+z[1], 13)
		z[0] ^= bitsRotateLeft32(z[3]+z[2], 18)

		z[6] ^= bitsRotateLeft32(z[5]+z[4], 7)
		z[7] ^= bitsRotateLeft32(z[6]+z[5], 9)
		z[4] ^= bitsRotateLeft32(z[7]+z[6], 13)
		z[5] ^= bitsRotateLeft32(z[4]+z[7], 18)

		z[11] ^= bitsRotateLeft32(z[10]+z[9], 7)
		z[8] ^= bitsRotateLeft32(z[11]+z[10], 9)
		z[9] ^= bitsRotateLeft32(z[8]+z[11], 13)
		z[10] ^= bitsRotateLeft32(z[9]+z[8], 18)

		z[12] ^= bitsRotateLeft32(z[15]+z[14], 7)
		z[13] ^= bitsRotateLeft32(z[12]+z[15], 9)
		z[14] ^= bitsRotateLeft32(z[13]+z[12], 13)
		z[15] ^= bitsRotateLeft32(z[14]+z[13], 18)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(block[i*4:], z[i]+x[i])
	}
}

func bitsRotateLeft32(x uint32, k int) uint32 { return x<<k | x>>(32-k) }
