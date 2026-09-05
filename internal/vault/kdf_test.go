// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture %q: %v", s, err)
	}
	return b
}

func TestScryptRFC7914Vector(t *testing.T) {
	got, err := scryptKey([]byte(""), []byte(""), 16, 1, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("scrypt vector mismatch\n got %x\nwant %x", got, want)
	}
}

// TestPBKDF2RFC6070SHA1Vectors pins pbkdf2Key against the published RFC 6070
// PBKDF2-HMAC-SHA-1 known-answer tests, driving the same generic PBKDF2 core
// the vault uses (via sha1.New here). The c=16777216 vector is intentionally
// omitted: it adds ~12s per run for no additional algorithmic coverage (the
// identical loop, more iterations). Every row is asserted; an empty table fails.
func TestPBKDF2RFC6070SHA1Vectors(t *testing.T) {
	cases := []struct {
		name     string
		password string
		salt     string
		iter     int
		dkLen    int
		want     string
	}{
		{"c1", "password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{"c2", "password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{"c4096", "password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
		{"long-25", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{"embedded-nul", "pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
	}
	reached := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pbkdf2Key([]byte(tc.password), []byte(tc.salt), tc.iter, tc.dkLen, sha1.New)
			if len(got) != tc.dkLen {
				t.Fatalf("length: got %d want %d", len(got), tc.dkLen)
			}
			if !bytes.Equal(got, mustDecodeHex(t, tc.want)) {
				t.Fatalf("RFC 6070 %s mismatch:\n got %x\nwant %s", tc.name, got, tc.want)
			}
		})
		reached++
	}
	if reached == 0 {
		t.Fatal("no RFC 6070 vectors were asserted")
	}
}

// TestPBKDF2HMACSHA256KATs pins pbkdf2Key with sha256.New — the exact PRF the
// vault's PBKDF2 KDF uses — against the RFC 7914 (scrypt) PBKDF2-HMAC-SHA-256
// known-answer tests. Every row is asserted; an empty table fails.
func TestPBKDF2HMACSHA256KATs(t *testing.T) {
	cases := []struct {
		name     string
		password string
		salt     string
		iter     int
		dkLen    int
		want     string
	}{
		{"passwd-c1", "passwd", "salt", 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password-c80000", "Password", "NaCl", 80000, 64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	}
	reached := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pbkdf2Key([]byte(tc.password), []byte(tc.salt), tc.iter, tc.dkLen, sha256.New)
			if len(got) != tc.dkLen {
				t.Fatalf("length: got %d want %d", len(got), tc.dkLen)
			}
			if !bytes.Equal(got, mustDecodeHex(t, tc.want)) {
				t.Fatalf("PBKDF2-HMAC-SHA256 %s mismatch:\n got %x\nwant %s", tc.name, got, tc.want)
			}
		})
		reached++
	}
	if reached == 0 {
		t.Fatal("no PBKDF2-HMAC-SHA256 KATs were asserted")
	}
}

// TestHKDFRFC5869Vectors pins hkdfSHA256 (used by deriveSubkey) against the
// RFC 5869 Appendix A test cases A.1-A.3. For each case the PRK is recomputed
// independently here with hmac.New so the extract step is cross-checked against
// the RFC's stated PRK, then the full OKM is asserted. RFC 5869 treats an absent
// salt as HashLen zero bytes; hkdfSHA256 does the same for a nil salt, which is
// A.3. Every row is asserted; an empty table fails.
func TestHKDFRFC5869Vectors(t *testing.T) {
	// bytesSeq returns n bytes starting at `start` and incrementing (A.2 inputs).
	bytesSeq := func(start, n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(start + i)
		}
		return b
	}
	cases := []struct {
		name       string
		ikm        []byte
		salt       []byte // nil means "not provided" (A.3)
		saltForPRK []byte // salt actually fed to the independent PRK HMAC key
		info       []byte
		length     int
		wantPRK    string
		wantOKM    string
	}{
		{
			name:       "A.1",
			ikm:        bytes.Repeat([]byte{0x0b}, 22),
			salt:       mustDecodeHex(t, "000102030405060708090a0b0c"),
			saltForPRK: mustDecodeHex(t, "000102030405060708090a0b0c"),
			info:       mustDecodeHex(t, "f0f1f2f3f4f5f6f7f8f9"),
			length:     42,
			wantPRK:    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			wantOKM:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name:       "A.2",
			ikm:        bytesSeq(0x00, 80),
			salt:       bytesSeq(0x60, 80),
			saltForPRK: bytesSeq(0x60, 80),
			info:       bytesSeq(0xb0, 80),
			length:     82,
			wantPRK:    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			wantOKM:    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:       "A.3",
			ikm:        bytes.Repeat([]byte{0x0b}, 22),
			salt:       nil,                       // "not provided" -> hkdfSHA256 uses HashLen zeros
			saltForPRK: make([]byte, sha256.Size), // RFC 5869: absent salt == HashLen zeros
			info:       []byte{},
			length:     42,
			wantPRK:    "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			wantOKM:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	reached := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Independent PRK: HMAC-SHA256(salt, IKM) recomputed here, no reuse of
			// the code under test, and compared to the RFC's PRK.
			mac := hmac.New(sha256.New, tc.saltForPRK)
			mac.Write(tc.ikm)
			prk := mac.Sum(nil)
			if !bytes.Equal(prk, mustDecodeHex(t, tc.wantPRK)) {
				t.Fatalf("%s PRK mismatch:\n got %x\nwant %s", tc.name, prk, tc.wantPRK)
			}
			okm := hkdfSHA256(tc.ikm, tc.salt, tc.info, tc.length)
			if len(okm) != tc.length {
				t.Fatalf("%s OKM length: got %d want %d", tc.name, len(okm), tc.length)
			}
			if !bytes.Equal(okm, mustDecodeHex(t, tc.wantOKM)) {
				t.Fatalf("%s OKM mismatch:\n got %x\nwant %s", tc.name, okm, tc.wantOKM)
			}
		})
		reached++
	}
	if reached == 0 {
		t.Fatal("no RFC 5869 vectors were asserted")
	}
}

// R12 (design D6.2): ValidateKDFStrength on NORMALISED configs. Below-floor rows
// error naming the floor; defaults and algorithm-only requests pass. The check
// must be run on a config already passed through NormalizeKDFConfig(cfg, true),
// exactly as the creation entrypoints do.
func TestValidateKDFStrengthOnNormalisedConfigs(t *testing.T) {
	rows := []struct {
		name    string
		in      KDFConfig
		wantErr bool
		floor   string // substring the error must name when wantErr
	}{
		{"argon2id defaults", DefaultKDFConfig(), false, ""},
		{"argon2id algorithm-only", KDFConfig{Algorithm: "ARGON2ID"}, false, ""},
		{"argon2id minimum compliant", KDFConfig{Algorithm: "ARGON2ID", Time: 2, MemoryKiB: 19456, Parallelism: 1}, false, ""},
		{"argon2id high-memory low-time", KDFConfig{Algorithm: "ARGON2ID", Time: 1, MemoryKiB: 65536, Parallelism: 1}, false, ""},
		{"argon2id time below floor", KDFConfig{Algorithm: "ARGON2ID", Time: 1, MemoryKiB: 19456, Parallelism: 1}, true, "19456"},
		{"argon2id memory below floor", KDFConfig{Algorithm: "ARGON2ID", Time: 2, MemoryKiB: 8192, Parallelism: 1}, true, "19456"},
		{"scrypt algorithm-only", KDFConfig{Algorithm: "SCRYPT"}, false, ""},
		{"scrypt defaults", KDFConfig{Algorithm: "SCRYPT", ScryptN: 32768, ScryptR: 8, ScryptP: 1}, false, ""},
		{"scrypt N below floor", KDFConfig{Algorithm: "SCRYPT", ScryptN: 16384, ScryptR: 8, ScryptP: 1}, true, "32768"},
		{"scrypt r below floor", KDFConfig{Algorithm: "SCRYPT", ScryptN: 32768, ScryptR: 1, ScryptP: 1}, true, "r="},
		{"pbkdf2 algorithm-only", KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256"}, false, ""},
		{"pbkdf2 defaults", KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: 600000}, false, ""},
		{"pbkdf2 iterations below floor", KDFConfig{Algorithm: "PBKDF2-HMAC-SHA256", Iterations: 1}, true, "600000"},
	}
	if len(rows) == 0 {
		t.Fatal("empty table exercises nothing")
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			normalized, err := NormalizeKDFConfig(r.in, true)
			if err != nil {
				t.Fatalf("normalize %+v: %v", r.in, err)
			}
			err = ValidateKDFStrength(normalized)
			if r.wantErr {
				if err == nil {
					t.Fatalf("expected a floor error for %+v", normalized)
				}
				if !strings.Contains(err.Error(), r.floor) {
					t.Fatalf("error %q must name the floor %q", err.Error(), r.floor)
				}
			} else if err != nil {
				t.Fatalf("expected %+v to pass the floor, got %v", normalized, err)
			}
		})
	}
}
