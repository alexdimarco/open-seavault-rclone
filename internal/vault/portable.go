// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"fmt"
	"strings"
)

// portableIllegalChars are the printable characters Windows forbids in a file
// name. A path segment carrying any of them cannot be recreated on a Windows
// checkout even though POSIX would accept it. ':' is the
// most dangerous: a colon that reaches a Windows path opens an alternate data
// stream of an otherwise-empty file, so export must never let one through
// .
const portableIllegalChars = `<>:"|?*`

// reservedStems are the Windows reserved device names. A segment whose stem
// (the part before the first '.') equals one of these — with OR without an
// extension, e.g. both "CON" and "CON.txt" — cannot be created on Windows
// . The check is case-insensitive.
var reservedStems = func() map[string]bool {
	m := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
	for i := 1; i <= 9; i++ {
		m[fmt.Sprintf("COM%d", i)] = true
		m[fmt.Sprintf("LPT%d", i)] = true
	}
	return m
}()

// isReservedStem reports whether a segment's stem is a Windows reserved device
// name. The stem is the portion before the first '.', so
// "CON.txt" is reserved but "console.txt" is not.
func isReservedStem(segment string) bool {
	stem := segment
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	return reservedStems[strings.ToUpper(stem)]
}

// ValidatePortableName reports whether a single path segment can be created on
// this vault and later restored on Windows as well as POSIX. It
// rejects the Windows-illegal characters <>:"|?*, control characters 0x00-0x1F
// and 0x7F, a trailing '.' or ' ', the reserved device stems
// (CON PRN AUX NUL COM1-COM9 LPT1-LPT9, with or without an extension), and the
// empty segment. The returned error names the offending character or rule, the
// reason ("cannot be restored on Windows"), and — as the fix — the sanitised
// form ValidatePortableName's export counterpart would write.
//
// It is a POLICY gate for NEW virtual paths only: the callers
// apply it when a path is being created (an upload/put target absent from the
// index, a new directory, a new WebDAV/webui move/copy/rename destination).
// Overwriting, reading, deleting and exporting an EXISTING illegal name (one a
// 0.15 peer or another OS created, e.g. content/a:b.txt) must keep working, so
// those paths never call this.
func ValidatePortableName(segment string) error {
	if segment == "" {
		return fmt.Errorf("an empty name cannot be restored on Windows; use %q", sanitizePortableSegment(segment))
	}
	for _, r := range segment {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("the control character %#U in %q cannot be restored on Windows; use %q", r, segment, sanitizePortableSegment(segment))
		}
		if strings.ContainsRune(portableIllegalChars, r) {
			return fmt.Errorf("the character %q in %q cannot be restored on Windows; use %q", string(r), segment, sanitizePortableSegment(segment))
		}
	}
	if last := segment[len(segment)-1]; last == '.' || last == ' ' {
		return fmt.Errorf("a trailing %q in %q cannot be restored on Windows; use %q", string(rune(last)), segment, sanitizePortableSegment(segment))
	}
	if isReservedStem(segment) {
		return fmt.Errorf("%q is a reserved device name on Windows; use %q", segment, sanitizePortableSegment(segment))
	}
	return nil
}

// sanitizePortableSegment maps a segment that fails ValidatePortableName to the
// nearest portable form: every illegal or control character
// becomes '_', trailing dots and spaces are trimmed, and a reserved stem gains a
// leading '_'. The result is always a non-empty portable segment; a segment made
// up entirely of illegal/trimmed characters collapses to "_". It never appends a
// disambiguating suffix — that is the caller's job when the sanitised name
// collides with another target in the same export batch.
func sanitizePortableSegment(segment string) string {
	var b strings.Builder
	for _, r := range segment {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(portableIllegalChars, r) {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimRight(b.String(), ". ")
	if out == "" {
		out = "_"
	}
	if isReservedStem(out) {
		out = "_" + out
	}
	return out
}
