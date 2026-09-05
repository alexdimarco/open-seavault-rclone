package blake2b

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestBlake2b512RFC7693Vectors pins Sum512 against the RFC 7693 BLAKE2b-512
// digests for "abc" (Appendix A) and the empty input. Both rows are asserted;
// an empty table fails.
func TestBlake2b512RFC7693Vectors(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{"abc", []byte("abc"), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
		{"empty", []byte(""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"},
	}
	reached := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("bad hex fixture: %v", err)
			}
			sum := Sum512(tc.input)
			if len(sum) != Size {
				t.Fatalf("digest length: got %d want %d", len(sum), Size)
			}
			if !bytes.Equal(sum[:], want) {
				t.Fatalf("BLAKE2b-512(%q) mismatch:\n got %x\nwant %s", tc.name, sum[:], tc.want)
			}
		})
		reached++
	}
	if reached == 0 {
		t.Fatal("no RFC 7693 BLAKE2b vectors were asserted")
	}
}
