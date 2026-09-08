// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexdimarco/open-seavault-rclone/internal/profile"
)

// resolveLocationConflicts implements the CLI-5 typed-error affordances. After the
// vault location is chosen (step 1) and BEFORE the password and the rest of the
// ceremony, it runs the side-effect-free Plan.Validate and, on a typed conflict,
// offers the design's remedy IN PLACE — rather than spending every later prompt
// and then failing at Execute with a bare "error:" (design §6, the promise the
// friction review found unkept).
//
//   - ErrVaultDirNotEmpty  -> "open it now" (launch the app / print the command)
//     or choose a different location.
//   - ErrVaultDirLeftovers -> remove the interrupted-setup leftovers and retry, or
//     choose a different location.
//   - ErrProfileNameInUse  -> register this vault under a suffixed profile name.
//     Execute then builds and registers the vault under that name; Execute is NOT
//     re-run (there is nothing built yet to re-register), so the C3 "suffixed-name
//     retry registers rather than re-creates" property holds — the name is fixed
//     before a single byte is written.
//
// It loops until the location validates cleanly, the user opens an existing vault
// (done=true — already handled here), or the user declines the remedy (the typed
// error is returned). It returns the possibly-changed vault dir, cloud pre-answer,
// and profile-name override to thread into the Plan. openApp may be nil (tests /
// no launcher wired), in which case the open affordance prints the command.
func resolveLocationConflicts(pr Prompter, vaultDir string, cloud CloudChoice, profileName, home, goos string, openApp func(string) error) (outDir string, outCloud CloudChoice, outProfile string, done bool, err error) {
	for {
		probe := Plan{VaultDir: vaultDir, ProfileName: profileName, Cloud: cloud}
		switch verr := probe.Validate(); {
		case verr == nil:
			return vaultDir, cloud, profileName, false, nil

		case errors.Is(verr, ErrVaultDirNotEmpty):
			openIt, cerr := pr.Confirm(fmt.Sprintf("A vault already exists at %s. Open it now instead of creating a new one?", vaultDir), true)
			if cerr != nil {
				return "", nil, "", false, cerr
			}
			if openIt {
				target := existingVaultOpenTarget(vaultDir)
				if openApp != nil {
					if oerr := openApp(target); oerr != nil {
						return "", nil, "", false, oerr
					}
				} else {
					pr.Show(fmt.Sprintf("Open it any time with: seavault gui %s", shellQuote(target)))
				}
				return vaultDir, cloud, profileName, true, nil
			}
			if vaultDir, cloud, cerr = stepVaultLocation(pr, home, goos); cerr != nil {
				return "", nil, "", false, cerr
			}

		case errors.Is(verr, ErrVaultDirLeftovers):
			removeIt, cerr := pr.Confirm(fmt.Sprintf("The folder %s has leftover files from an interrupted setup (no vault inside). Remove them and set up here?", vaultDir), false)
			if cerr != nil {
				return "", nil, "", false, cerr
			}
			if removeIt {
				if rerr := os.RemoveAll(vaultDir); rerr != nil {
					pr.Show(fmt.Sprintf("could not remove %s: %v — choose a different location.", vaultDir, rerr))
					if vaultDir, cloud, cerr = stepVaultLocation(pr, home, goos); cerr != nil {
						return "", nil, "", false, cerr
					}
				}
				// Otherwise loop: re-validate the now-removed (absent) directory.
			} else if vaultDir, cloud, cerr = stepVaultLocation(pr, home, goos); cerr != nil {
				return "", nil, "", false, cerr
			}

		case errors.Is(verr, ErrProfileNameInUse):
			resolved := probe.ResolvedProfileName()
			suggestion := suffixedProfileName(resolved)
			useIt, cerr := pr.Confirm(fmt.Sprintf("A profile named %q already points at a different vault. Register this vault as %q instead?", resolved, suggestion), true)
			if cerr != nil {
				return "", nil, "", false, cerr
			}
			if !useIt {
				return "", nil, "", false, verr
			}
			profileName = suggestion

		default:
			// A KDF-floor breach, an invalid remote name, or an I/O error: not a
			// location affordance. Surface it (Execute would return the same).
			return "", nil, "", false, verr
		}
	}
}

// suffixedProfileName returns the first "base-N" (N from 2) that no profile
// currently claims, so the ErrProfileNameInUse affordance offers a name that will
// actually register. It reads the profile store through the same side-effect-free
// profileLookup seam Plan.Validate uses.
func suffixedProfileName(base string) string {
	for i := 2; i < 1000; i++ {
		cand := fmt.Sprintf("%s-%d", base, i)
		if _, found, err := profileLookup(cand); err == nil && !found {
			return cand
		}
	}
	return base + "-new"
}

// existingVaultOpenTarget returns the friendliest `seavault gui` argument for the
// vault already at vaultDir: the profile name that points at it when one exists
// (so the offer reads "seavault gui MyVault"), otherwise the directory path, which
// the gui command also accepts.
func existingVaultOpenTarget(vaultDir string) string {
	if entries, err := profile.Entries(); err == nil {
		for _, e := range entries {
			if filepath.Clean(e.VaultPath) == filepath.Clean(vaultDir) {
				return e.Name
			}
		}
	}
	return vaultDir
}
