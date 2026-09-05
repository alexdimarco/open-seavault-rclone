// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !linux && !darwin && !windows

package keychain

import "fmt"

func Get(account string) (string, error) {
	return "", fmt.Errorf("OS keychain is unsupported on this platform")
}
func Set(account, secret string) error {
	return fmt.Errorf("OS keychain is unsupported on this platform")
}
func Delete(account string) error { return fmt.Errorf("OS keychain is unsupported on this platform") }
