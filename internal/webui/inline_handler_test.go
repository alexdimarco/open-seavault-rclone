// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The file list built its Download/Delete buttons as
//   onclick="downloadFile('"+encodeURIComponent(f.path)+"')"
// encodeURIComponent leaves ' ( ) ! * - unescaped, so a file named x'-alert(1)-'
// ran attacker script when clicked (and a name with an apostrophe silently broke
// its own buttons). Likewise openDavFolder(JSON.stringify(parent)) put a double
// quote inside a double-quoted attribute. The rule these tests enforce: file/
// folder data reaches a handler only through a data-* attribute passed through
// esc(), read back with this.dataset - never concatenated into handler code.

func guiPageSource(t *testing.T) string {
	t.Helper()
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, authReq(s, httptest.NewRequest(http.MethodGet, "/", nil)))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /: code=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "function refreshFiles") {
		t.Fatalf("the served page does not contain the GUI script; the test would be vacuous")
	}
	return body
}

func TestNoInlineHandlerConcatenatesData(t *testing.T) {
	page := guiPageSource(t)
	attr := regexp.MustCompile(`onclick="([^"]*)"`)
	matches := attr.FindAllStringSubmatch(page, -1)
	if len(matches) < 10 {
		t.Fatalf("found only %d onclick attributes; the scan is not seeing the page", len(matches))
	}
	for _, m := range matches {
		if strings.Contains(m[1], "+") {
			t.Errorf("inline handler builds code from data (script injection): onclick=%q", m[1])
		}
	}
}

func TestEscEscapesSingleQuote(t *testing.T) {
	page := guiPageSource(t)
	i := strings.Index(page, "function esc(")
	if i < 0 {
		t.Fatal("esc() not found in the page")
	}
	end := strings.Index(page[i:], "\n")
	if end < 0 {
		t.Fatal("esc() definition not terminated")
	}
	def := page[i : i+end]
	for _, want := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&#39;"} {
		if !strings.Contains(def, want) {
			t.Errorf("esc() does not produce %s: %s", want, def)
		}
	}
}
