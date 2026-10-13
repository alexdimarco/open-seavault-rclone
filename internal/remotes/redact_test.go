// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package remotes

import (
	"strings"
	"testing"
)

// "Redacted" exports are meant to be safe to paste into a bug report. These
// rclone options carry credentials but matched none of looksSecret's patterns.

func TestRedactConfigCoversCredentialBearingOptions(t *testing.T) {
	rows := []struct{ line, secret string }{
		{`service_account_credentials = {"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----ABC"}`, "BEGIN PRIVATE KEY"},
		{`sas_url = https://acct.blob.core.windows.net/c?sv=2020&sig=SECRETSIG`, "SECRETSIG"},
		{`connection_string = DefaultEndpointsProtocol=https;AccountName=a;AccountKey=SECRETKEY`, "SECRETKEY"},
		{`token = {"access_token":"SECRETTOKEN"}`, "SECRETTOKEN"},
		{`pass = SECRETPASS`, "SECRETPASS"},
		{`secret_access_key = SECRETACCESS`, "SECRETACCESS"},
		{`session_token = SECRETSESSION`, "SECRETSESSION"},
		{`sse_customer_key_base64 = SECRETSSE`, "SECRETSSE"},
		{`bearer_token = SECRETBEARER`, "SECRETBEARER"},
	}
	for _, r := range rows {
		in := "[remote]\ntype = x\n" + r.line + "\nregion = us-east-1\n"
		out := RedactConfig(in)
		if strings.Contains(out, r.secret) {
			t.Errorf("secret %q survived redaction of %q:\n%s", r.secret, r.line, out)
		}
		if !strings.Contains(out, "region = us-east-1") || !strings.Contains(out, "type = x") {
			t.Errorf("non-secret lines must be preserved, got:\n%s", out)
		}
	}
}
