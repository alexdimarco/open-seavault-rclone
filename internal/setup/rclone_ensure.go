// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"context"
	"errors"
	"fmt"

	"github.com/alexdimarco/open-seavault-rclone/internal/rclonebin"
)

// ErrDownloadRefused is returned by RcloneEnsure when a runtime is not present
// and consent for the network download was refused (design §3.5, C11). Its
// message names the offline alternatives so the caller can surface them inline.
var ErrDownloadRefused = errors.New("rclone runtime download was declined; install it offline with `seavault rclone install --offline-archive <zip>` or `--from-binary <path>`")

// rcloneStatus and rcloneInstall are the package seams over the runtime's
// present-check and its network install. They are variables ONLY so the tests
// can prove RcloneEnsure never fetches when a runtime is present or when consent
// is refused, and can inject a fake-fetch success — the network fetch is exactly
// the privilege boundary the discipline permits mocking. Production code uses
// the real rclonebin implementations.
var (
	rcloneStatus = func() rclonebin.Status {
		return rclonebin.StatusNow(context.Background())
	}
	rcloneInstall = func(ctx context.Context) error {
		inst := rclonebin.NewInstaller()
		_, err := inst.Install(ctx, rclonebin.InstallOptions{
			Channel:       "stable",
			SignatureMode: rclonebin.LoadPolicy().SignatureMode,
		})
		return err
	}
)

// RcloneEnsure makes a verified rclone runtime available, asking consent before
// any network access (design §3.5, C11). It returns nil immediately when a
// verified runtime is already present — NO fetch, and consent is never asked.
// Otherwise it calls consent BEFORE touching the network; if consent is nil or
// returns false it returns ErrDownloadRefused (naming the offline options) and
// does NOT fetch. Only on granted consent does it download and install, then
// return the install error (or nil on success).
func RcloneEnsure(consent func() bool) error {
	st := rcloneStatus()
	if st.Installed && st.RuntimeOK {
		return nil
	}
	if consent == nil || !consent() {
		return ErrDownloadRefused
	}
	if err := rcloneInstall(context.Background()); err != nil {
		return fmt.Errorf("install rclone runtime: %w", err)
	}
	return nil
}
