// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package rclonebin

import (
	"strings"
	"testing"
)

// RedactText scrubs rclone output shown to the user (config show, error text).
// It matches on the WHOLE line, so the sample values here are deliberately
// opaque (no "secret"/"token"/"pass" substrings) - otherwise a leak would be
// hidden by an unrelated word in the value.

func TestRedactTextCoversKeysAndCredentials(t *testing.T) {
	rows := []struct{ line, leak string }{
		{`private_key = -----BEGIN PRIVATE KEY-----ZQXPEM`, "ZQXPEM"},
		{`secret_access_key = ZQXACCESS`, "ZQXACCESS"},
		{`service_account_credentials = {"private_key":"ZQXSA"}`, "ZQXSA"},
		{`sas_url = https://x.blob.core.windows.net/c?sig=ZQXSIG`, "ZQXSIG"},
		{`connection_string = AccountName=a;AccountKey=ZQXCONN`, "ZQXCONN"},
		{`pass = ZQXPASS`, "ZQXPASS"},
		{`access_token = ZQXTOKEN`, "ZQXTOKEN"},
	}
	for _, r := range rows {
		out := RedactText("before\n" + r.line + "\nafter region=us-east-1")
		if strings.Contains(out, r.leak) {
			t.Errorf("%q survived RedactText of %q: %q", r.leak, r.line, out)
		}
		if !strings.Contains(out, "before") || !strings.Contains(out, "after region=us-east-1") {
			t.Errorf("unrelated lines must be preserved: %q", out)
		}
	}
}
