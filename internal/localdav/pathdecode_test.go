// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package localdav

import (
	"net/http"
	"testing"
)

// net/http has already percent-decoded r.URL.Path (and url.Parse has decoded a
// Destination's Path) by the time the handlers see them. Decoding a second time
// turns a literal "%" in a file name into an escape: "My%20Doc" resolves to
// "My Doc", and a file literally named "%2e%2e" resolves to "..", which path
// cleaning then collapses onto its parent so one DELETE tombstones a whole folder.

func TestRequestPathIsDecodedExactlyOnce(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/My%20Doc.pdf", []byte("literal-percent"))
	putFile(t, v, "docs/My Doc.pdf", []byte("with-space"))
	putFile(t, v, "docs/100%.txt", []byte("bare-percent"))
	s := &Server{Vault: v}

	cases := []struct {
		name   string
		target string // as a client sends it: each literal % encoded as %25
		want   string
	}{
		{"literal %20 in the name", "/docs/My%2520Doc.pdf", "literal-percent"},
		{"encoded space", "/docs/My%20Doc.pdf", "with-space"},
		{"bare percent", "/docs/100%25.txt", "bare-percent"},
	}
	for _, c := range cases {
		rr := serve(s, req(http.MethodGet, c.target, nil))
		if rr.Code != http.StatusOK || rr.Body.String() != c.want {
			t.Errorf("%s: GET %s = %d %q, want 200 %q", c.name, c.target, rr.Code, rr.Body.String(), c.want)
		}
	}
}

func TestDeleteOfDotDotNamedFileDoesNotDeleteParent(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/A/keep.txt", []byte("keep"))
	putFile(t, v, "docs/A/B/%2e%2e", []byte("odd-name"))
	s := &Server{Vault: v}

	// The client names the file "%2e%2e" literally, so it sends %252e%252e.
	rr := serve(s, req(http.MethodDelete, "/docs/A/B/%252e%252e", nil))
	if rr.Code != http.StatusNoContent && rr.Code != http.StatusOK {
		t.Fatalf("DELETE of the oddly named file: code=%d", rr.Code)
	}
	if got := serve(s, req(http.MethodGet, "/docs/A/keep.txt", nil)); got.Code != http.StatusOK || got.Body.String() != "keep" {
		t.Fatalf("sibling docs/A/keep.txt was lost: %d %q", got.Code, got.Body.String())
	}
	if got := serve(s, req(http.MethodGet, "/docs/A/B/%252e%252e", nil)); got.Code != http.StatusNotFound {
		t.Fatalf("the named file should be gone: code=%d", got.Code)
	}
}

func TestDestinationHeaderIsDecodedExactlyOnce(t *testing.T) {
	v := newTestVault(t)
	putFile(t, v, "docs/a.txt", []byte("alpha"))
	s := &Server{Vault: v}

	for _, dest := range []string{
		"/docs/50%25off.txt",
		"http://127.0.0.1/docs/50%25off.txt",
	} {
		r := req("COPY", "/docs/a.txt", nil)
		r.Header.Set("Destination", dest)
		if rr := serve(s, r); rr.Code != http.StatusCreated && rr.Code != http.StatusNoContent {
			t.Fatalf("COPY to %q: code=%d", dest, rr.Code)
		}
		got := serve(s, req(http.MethodGet, "/docs/50%25off.txt", nil))
		if got.Code != http.StatusOK || got.Body.String() != "alpha" {
			t.Fatalf("COPY to %q: copy not at the literal name: %d %q", dest, got.Code, got.Body.String())
		}
		serve(s, req(http.MethodDelete, "/docs/50%25off.txt", nil))
	}
}
