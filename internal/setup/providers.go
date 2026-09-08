// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

// Package setup is the UI-agnostic core of the first-run wizard (design
// docs/design-setup-wizard.md, Phase U1): detect (sync-folder detection), plan
// (Plan + Validate) and execute (Deps seam + Execute). The CLI `seavault setup`
// and the GUI first-run stepper both drive this package; neither the detection
// nor the execution logic knows which UI is calling.
package setup

// Provider is a well-known consumer sync client whose local folder the wizard
// can place a vault inside (design §3.1). U1 ships exactly the six providers
// that have a verified, authored caveat; Box, pCloud and MEGA were dropped from
// the enum until they earn one (C7).
type Provider string

const (
	ProviderDropbox     Provider = "dropbox"
	ProviderOneDrive    Provider = "onedrive"
	ProviderICloud      Provider = "icloud"
	ProviderGoogleDrive Provider = "googledrive"
	ProviderNextcloud   Provider = "nextcloud"
	ProviderSyncthing   Provider = "syncthing"
)

// AllProviders is the U1 provider set in a stable order. It is the domain of the
// caveat catalog and the providers the detector knows about.
var AllProviders = []Provider{
	ProviderDropbox,
	ProviderOneDrive,
	ProviderICloud,
	ProviderGoogleDrive,
	ProviderNextcloud,
	ProviderSyncthing,
}

// caveats is the ONE source of truth for provider caveats (C7). The text lives
// here in code, not in docs/cloud-provider-notes.md (which carries no caveat
// text); that doc points at this catalog. Each string is the placement warning
// the wizard shows inline when a provider folder is chosen, and the Note the
// detector attaches to every hit. The common thread across providers is
// on-demand / online-only file eviction: a vault is only openable when every
// encrypted chunk is actually present on local disk, so each caveat tells the
// user how to keep the vault folder materialised.
var caveats = map[Provider]string{
	ProviderDropbox: "Dropbox can keep files online-only (Smart Sync / Selective Sync). " +
		"Right-click the vault folder and choose \"Make available offline\" so every encrypted chunk stays on disk; otherwise the vault may fail to open when you are offline.",
	ProviderOneDrive: "OneDrive's Files On-Demand can make the vault's chunks online-only placeholders. " +
		"Right-click the vault folder and choose \"Always keep on this device\" so the encrypted data is present locally.",
	ProviderICloud: "iCloud Drive can offload local copies of files you have not opened recently to free space " +
		"(macOS \"Optimize Mac Storage\"; on Windows the iCloud client streams files on demand). " +
		"Keep the vault folder downloaded — turn Optimize Storage off or open the folder to re-download it on macOS, and \"Always Keep on This Device\" / Keep Downloaded on Windows — so its encrypted chunks are not evicted.",
	ProviderGoogleDrive: "Google Drive for desktop streams files by default instead of mirroring them. " +
		"Set the vault folder to \"Available offline\" (or use Mirror mode) so the encrypted data stays on local disk.",
	ProviderNextcloud: "Nextcloud's virtual-files (on-demand) mode can leave the vault's chunks online-only. " +
		"Mark the vault folder \"Make always available locally\", and enable hidden-file sync if you are opening an older .seavault vault.",
	ProviderSyncthing: "Syncthing skips anything matched by a .stignore rule and keeps no server-side version history by default. " +
		"Keep the vault folder outside every ignore pattern so all chunks propagate to your other devices.",
}

// Caveat returns the placement caveat for a provider, or "" for an unknown
// provider. It is the only accessor callers use; the underlying map is not
// exported so the catalog stays the single source of truth.
func Caveat(p Provider) string { return caveats[p] }

// DisplayName returns a human-facing label for a provider, used by the CLI and
// GUI when listing "inside your <name> folder" choices.
func DisplayName(p Provider) string {
	switch p {
	case ProviderDropbox:
		return "Dropbox"
	case ProviderOneDrive:
		return "OneDrive"
	case ProviderICloud:
		return "iCloud Drive"
	case ProviderGoogleDrive:
		return "Google Drive"
	case ProviderNextcloud:
		return "Nextcloud"
	case ProviderSyncthing:
		return "Syncthing"
	default:
		return string(p)
	}
}
