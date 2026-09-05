package argon2

import (
	"bytes"
	"encoding/hex"
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

// TestArgon2idRFC9106Vector pins the unexported deriveKey against the RFC 9106
// Section 5.3 Argon2id known-answer test: password = 32 x 0x01, salt = 16 x 0x02,
// secret key = 8 x 0x03, associated data = 12 x 0x04, t=3, m=32 KiB, p=4, tag=32.
// This is the only Argon2 vector that exercises the secret and associated-data
// inputs, so it is asserted through deriveKey directly (IDKey passes nil for both).
func TestArgon2idRFC9106Vector(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)
	secret := bytes.Repeat([]byte{0x03}, 8)
	ad := bytes.Repeat([]byte{0x04}, 12)

	tag := deriveKey(argon2id, password, salt, secret, ad, 3, 32, 4, 32)
	want := mustDecodeHex(t, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
	if len(tag) != len(want) {
		t.Fatalf("tag length: got %d want %d", len(tag), len(want))
	}
	if !bytes.Equal(tag, want) {
		t.Fatalf("RFC 9106 Argon2id tag mismatch:\n got %x\nwant %x", tag, want)
	}
}

// TestArgon2idIDKeyNoSecretAD pins IDKey — the public entry point the vault's
// KDF uses — for the RFC 9106 parameters but with no secret and no associated
// data (the vault never supplies either). It fixes the exact output so a change
// to the Argon2id core or to IDKey's mode/nil wiring is caught, and confirms
// IDKey routes to deriveKey(argon2id, ..., nil, nil, ...).
func TestArgon2idIDKeyNoSecretAD(t *testing.T) {
	password := bytes.Repeat([]byte{0x01}, 32)
	salt := bytes.Repeat([]byte{0x02}, 16)

	got := IDKey(password, salt, 3, 32, 4, 32)
	want := mustDecodeHex(t, "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e")
	if !bytes.Equal(got, want) {
		t.Fatalf("IDKey (no secret/AD) mismatch:\n got %x\nwant %x", got, want)
	}

	viaDerive := deriveKey(argon2id, password, salt, nil, nil, 3, 32, 4, 32)
	if !bytes.Equal(got, viaDerive) {
		t.Fatalf("IDKey does not equal deriveKey(argon2id, ..., nil, nil, ...):\n IDKey     %x\n deriveKey %x", got, viaDerive)
	}
}
