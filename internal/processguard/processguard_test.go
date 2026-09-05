// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package processguard

import "testing"

func TestIsSeaVaultProcessMatchesNameAndArgs(t *testing.T) {
	tests := []struct {
		name string
		proc processInfo
		want bool
	}{
		{name: "exact unix name", proc: processInfo{PID: 10, Name: "seavault"}, want: true},
		{name: "windows exe name", proc: processInfo{PID: 11, Name: "SeaVault.exe"}, want: true},
		{name: "path in args", proc: processInfo{PID: 12, Name: "launcher", Args: "/opt/seavault/seavault gui"}, want: true},
		{name: "quoted path in args", proc: processInfo{PID: 13, Name: "launcher", Args: "\"C:\\Program Files\\SeaVault\\seavault.exe\" gui"}, want: true},
		{name: "non match", proc: processInfo{PID: 14, Name: "rclone", Args: "rclone serve"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSeaVaultProcess(tt.proc, "seavault"); got != tt.want {
				t.Fatalf("isSeaVaultProcess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFirstCommandToken(t *testing.T) {
	tests := map[string]string{
		"/usr/local/bin/seavault gui":                       "/usr/local/bin/seavault",
		"  seavault gui --no-open":                          "seavault",
		"\"C:\\Program Files\\SeaVault\\seavault.exe\" gui": "C:\\Program Files\\SeaVault\\seavault.exe",
		"": "",
	}
	for input, want := range tests {
		if got := firstCommandToken(input); got != want {
			t.Fatalf("firstCommandToken(%q) = %q, want %q", input, got, want)
		}
	}
}
