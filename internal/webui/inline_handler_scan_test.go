// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package webui

import (
	"regexp"
	"strings"
	"testing"
)

// Stronger guards for the stored-XSS class fixed in inline_handler_test.go. That
// test only looked at double-quoted onclick values containing a plus sign. These
// cover every event-handler attribute and every data-* attribute built from data.
//
// They scan the served page source (there is no JS engine in the test
// environment), so they pin the SHAPE of safe code, not its execution.

var (
	// A handler attribute written as  on<event>="..."  (the page's only form).
	handlerDouble = regexp.MustCompile(`\son[a-z]+="([^"]*)"`)
	// Forms the page must not use at all: single-quoted or unquoted handler
	// attributes are easy to break out of and were never needed.
	handlerSingle   = regexp.MustCompile(`\son[a-z]+=\\?'`)
	handlerUnquoted = regexp.MustCompile(`\son[a-z]+=[A-Za-z_$(]`)
	// A data-* attribute whose value is concatenated into the HTML string:
	//   data-path="'+EXPR+'"
	dataConcat = regexp.MustCompile(`\sdata-[a-z-]+="'\s*\+\s*(.+?)\s*\+\s*'"`)
)

func TestEveryHandlerAttributeIsFreeOfBuiltCode(t *testing.T) {
	page := guiPageSource(t)

	doubles := handlerDouble.FindAllStringSubmatch(page, -1)
	if len(doubles) < 10 {
		t.Fatalf("found only %d double-quoted handler attributes; the scan is not seeing the page", len(doubles))
	}
	for _, m := range doubles {
		v := m[1]
		for _, bad := range []string{"+", "${", ".concat(", ".join(", ".replace(", "JSON.stringify"} {
			if strings.Contains(v, bad) {
				t.Errorf("handler attribute builds code from data (contains %q): %q", bad, v)
			}
		}
	}
	if m := handlerSingle.FindString(page); m != "" {
		t.Errorf("single-quoted event-handler attribute found near %q", m)
	}
	if m := handlerUnquoted.FindString(page); m != "" {
		t.Errorf("unquoted event-handler attribute found near %q", m)
	}
}

// Any data-* value assembled from data must pass through a known-safe transform.
func TestDataAttributeValuesAreEscaped(t *testing.T) {
	page := guiPageSource(t)
	matches := dataConcat.FindAllStringSubmatch(page, -1)
	if len(matches) < 5 {
		t.Fatalf("found only %d concatenated data-* attributes; the scan is not seeing the page", len(matches))
	}
	safe := []string{"esc(", "encodeURIComponent(", "slug(", "Number("}
	// A ternary choosing between two constant strings carries no data, e.g.
	// (canKey?'1':'0').
	constTernary := regexp.MustCompile(`^\([A-Za-z_][\w.]*\?'[^']*':'[^']*'\)$`)
	for _, m := range matches {
		expr := strings.TrimSpace(m[1])
		// passwordId is only ever 'vault-card-password-' / 'profile-password-' + slug(...),
		// i.e. [A-Za-z0-9_-]; allowed by exact name, not as "any bare variable".
		ok := expr == "passwordId" || constTernary.MatchString(expr)
		for _, p := range safe {
			if strings.HasPrefix(expr, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("data-* attribute value %q is not wrapped in esc()/encodeURIComponent()/slug()/Number()", expr)
		}
	}
}
