// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

const (
	MetadataDirName = ".seavault"
	ConfigFileName  = "vault.json"
	IndexFileName   = "index.dat" // legacy single-index file, still readable.
)

// SupportedFormat is the highest format-v3 reader level this build implements
// (design D1.2, P1-20). It is the forward-compatibility ceiling: a vault whose
// VaultConfig.MinReader exceeds it is refused before any unwrap with
// ErrFormatTooNew. It is distinct from VaultConfig.Version (the on-the-wire
// integer the shipped 0.16 client fences on): during the A2 grace release the
// format grows while Version stays 2 (Condition 3), so this ceiling — not
// Version — is what fences a too-new vault for A2-and-later clients.
const SupportedFormat = 3

// ErrFormatTooNew is returned by Open when vault.json declares a MinReader
// greater than SupportedFormat: this build is too old to read the vault
// (design D1.3, P1-20). Its message is deliberately HEDGED because MinReader is
// validated BEFORE the config MAC is verified (it must fence before doing any
// unwrap work), so at this point a forged high MinReader is indistinguishable
// from a genuine forward version — the operator is told the value may be
// tampering, not just a stale client. After unwrap the same field is MAC-covered
// and a forgery is additionally caught as config tampering (backlog B-4, §2).
var ErrFormatTooNew = errors.New("this vault requires a newer version of SeaVault; if you did not expect a version change, vault.json may have been modified — restore it from a backup or another device")

// ErrConfigInconsistent is returned by Open/loadIndexFromDisk when vault.json
// describes a legacy single-index (or version 1) vault but encrypted manifests
// exist on disk — the signature of a vault.json that was downgraded or replaced
// under an intact manifest store (design D2.1, P0-3). Opening such a vault as a
// legacy single-index vault would ignore every manifest, so it is refused.
var ErrConfigInconsistent = errors.New("vault.json describes a legacy single-index vault but encrypted manifests exist; refusing to open — vault.json may have been replaced; restore it from a backup or another device")

// ErrConfigRolledBack is returned by Open when a NON-INTERACTIVE unlock
// (keychain, SEAVAULT_PASSWORD, or a serve/sync auto-supplied password) meets a
// config whose FormatEpoch is lower than this device's freshness high-water — a
// replayed pre-rotation config (design D5.3, T-A2-2, Condition 9). An unattended
// process cannot read a warning, so the rollback is a hard refusal; the operator
// re-runs with --accept-rollback (and a re-supplied credential) to accept it.
var ErrConfigRolledBack = errors.New("vault.json looks older than this device last saw, so SeaVault will not open it. If you deliberately restored this vault from an older backup, re-run with --accept-rollback to open it and re-establish freshness. If you did NOT expect this, the sync server may be replaying a retired configuration: do not enter a retired password, and restore vault.json from a good backup or another device")

// ErrConfigDiverged is returned by Open when the on-disk FormatEpoch TIES this
// device's recorded high-water but the ConfigTag differs (design D3.6, Condition
// 13): two devices mutated the vault configuration concurrently and the sync
// client kept a copy this device did not write. Rather than silently accept it,
// Open refuses so the operator resolves the divergence on the originating device.
var ErrConfigDiverged = errors.New("another device changed the vault configuration at the same time; open on the device that made the change, let it sync, then retry")

// OpenOptions carry the freshness-rollback disposition into Open (design D5.3,
// Condition 9). The zero value hard-refuses a replayed config; --accept-rollback
// sets AcceptRollback to open a deliberate restore and re-establish freshness.
type OpenOptions struct {
	// AcceptRollback is the operator's explicit acknowledgement that a config
	// older than this device's high-water is expected (a restore from backup): it
	// turns the ErrConfigRolledBack refusal into an open and CLEARS the device
	// anchor so the restored config re-TOFUs (Condition 8). Without it, a rollback
	// refuses regardless of whether the unlock was interactive (strict gate).
	AcceptRollback bool
}

type VaultConfig struct {
	Version int `json:"version"`
	// MinReader is the forward-compatibility fence (design D1.2, P1-20): a client
	// whose SupportedFormat is below MinReader refuses the vault with
	// ErrFormatTooNew. Additive and omitempty so an absent field (every pre-A2
	// vault, and every A2 vault during the grace release) reads as 0 and fences
	// nothing. Raised to 3 only by seal-format (slice 6), never during grace.
	MinReader int `json:"minReader,omitempty"`
	// FormatEpoch is a monotonic counter bumped by every config rewrite (design
	// D3.5/D5.1): the device-local freshness anchor compares it to detect a
	// rolled-back config. Additive/omitempty; absent reads as 0.
	FormatEpoch int64        `json:"formatEpoch,omitempty"`
	VaultID     string       `json:"vaultId,omitempty"`
	CreatedAt   string       `json:"createdAt"`
	KDF         KDFConfig    `json:"kdf"`
	Crypto      CryptoConfig `json:"crypto"`
	Chunk       ChunkParams  `json:"chunk"`
	WrappedKeys string       `json:"wrappedKeys"`
	WrapNonce   string       `json:"wrapNonce"`
	// WrapEntries is the format-v3 wrap-entry array (design D3.1, P1-7): password
	// and recovery entries, each with its own KDF salt/cost, nonce and wrapped
	// master||index bundle. Additive/omitempty: when empty, the legacy top-level
	// WrappedKeys/WrapNonce are read as an implicit password entry (I1), so every
	// pre-A2 vault opens unchanged. Populated by password change / recovery
	// (slice 4); read by Open (slice 2). The legacy fields are kept current
	// throughout the grace release (Condition 4).
	WrapEntries []WrapEntry `json:"wrapEntries,omitempty"`
	// ConfigTag is base64 HMAC-SHA256 over the canonical config bytes (this whole
	// struct with ConfigTag zeroed, in declaration order) under a master-derived
	// key (design D2.2, P0-3). Additive/omitempty: absent on legacy/grace vaults
	// (TOFU); written and verified starting slice 3. Declared LAST so the MAC
	// covers every other field in declaration order and the tag is trivially
	// zeroed for the canonical form.
	ConfigTag string `json:"configTag,omitempty"`
}

// WrapEntry is one entry in VaultConfig.WrapEntries (design D3.1, P1-7): a
// password or recovery credential that unwraps the same master||index bundle
// under its own KDF salt/cost and AES-256-GCM nonce. ID is a stable random
// 8-byte hex handle. AAD selects the wrap AAD: "" means the legacy bare AAD
// (migrated wraps, protected by the config MAC covering Version); a non-empty
// value binds the vault Version into the unwrap so a version downgrade also
// breaks the unwrap independent of the MAC (design D2.5), used for newly created
// vaults. The read/write paths land in slices 2 and 4.
type WrapEntry struct {
	ID    string    `json:"id"`                       // random 8-byte hex, stable per entry
	Type  string    `json:"type"`                     // "password" | "recovery"
	KDF   KDFConfig `json:"kdf"`                      // own salt + cost
	Nonce string    `json:"wrapNonce"`                // AES-256-GCM nonce
	CT    string    `json:"wrappedKeys"`              // AES-256-GCM(wrapKey, master||index)
	AAD   string    `json:"wrapAADVersion,omitempty"` // "" = legacy bare AAD; else versioned
}

// Wrap-entry type discriminators (design D3.1, P1-7). A password unlock filters
// WrapEntries by WrapTypePassword; recovery redeem (slice 4) by WrapTypeRecovery.
const (
	WrapTypePassword = "password"
	WrapTypeRecovery = "recovery"
)

type KDFConfig struct {
	Algorithm   string `json:"algorithm"`
	Iterations  int    `json:"iterations,omitempty"`
	Salt        string `json:"salt"`
	ScryptN     int    `json:"scryptN,omitempty"`
	ScryptR     int    `json:"scryptR,omitempty"`
	ScryptP     int    `json:"scryptP,omitempty"`
	MemoryKiB   int    `json:"memoryKiB,omitempty"`
	Time        int    `json:"time,omitempty"`
	Parallelism int    `json:"parallelism,omitempty"`
}

type CryptoConfig struct {
	KeyWrap        string `json:"keyWrap"`
	ChunkAEAD      string `json:"chunkAEAD"`
	IndexAEAD      string `json:"indexAEAD"`
	ObjectID       string `json:"objectID"`
	Chunker        string `json:"chunker"`
	StorageMode    string `json:"storageMode"`
	ManifestMode   string `json:"manifestMode,omitempty"`
	ManifestShards int    `json:"manifestShards,omitempty"`
	// DirIDEpoch is the A3 directory-ID re-key generation (design D1.4): it is 0
	// on every A2 vault and is bumped by A3's directory-ID indirection re-key when
	// that phase lands. It is the marker seal-format's reversal (unseal-format)
	// guards on: once a dir-ID re-key has run (DirIDEpoch > 0), the manifests are
	// re-keyed beyond what a Version-2 reader can decode, so unseal-format refuses
	// to re-admit v2 readers (there is no such re-key in A2, so unseal is always
	// allowed now). Additive/omitempty: absent on every 0.16 and A2 vault, and
	// MAC-covered (it lives in CryptoConfig, inside the ConfigTag), so a forged
	// marker is caught as config tampering.
	DirIDEpoch int `json:"dirIdEpoch,omitempty"`
}

type CreateOptions struct {
	Chunk ChunkParams
	KDF   KDFConfig
}

type Vault struct {
	Root      string
	MetaRoot  string
	Config    VaultConfig
	keys      Keys
	chunkAEAD cipher.AEAD
	indexAEAD cipher.AEAD

	// mu guards the in-memory index cache and the generation high-water mark.
	// The encrypted sharded manifests on disk remain the source of truth; cached
	// is a decrypted snapshot that lets a long-lived process (GUI/WebDAV server,
	// future mount) avoid re-walking and re-decrypting every manifest on each
	// operation. See cache.go.
	mu     sync.Mutex
	cached *Index
	// maxGen is the highest record generation observed across ALL manifests
	// (live, conflict variants, and tombstones) at load time, bumped on every
	// local write. New generations are derived as max(wall-clock, maxGen+1) so a
	// local edit/delete always supersedes everything this device has synced,
	// regardless of cross-device clock skew. See nextGeneration in cache.go.
	maxGen int64
	// lastFP/fpKnown track a cheap stat-based fingerprint of the on-disk
	// manifests so ReloadIfChanged can detect when another process (e.g. the
	// Nextcloud sync client) changed .seavault underneath a long-lived vault.
	lastFP  uint64
	fpKnown bool
	// openNote holds the D1.3 preflight note surfaced when a legacy .seavault
	// vault under a sync-client folder is opened. Set once by Open; read-only after.
	openNote string
	// anchorNote holds the one-time D5.4 note surfaced when the device-local
	// freshness anchor could not be resolved or written (an unwritable appdir):
	// rollback protection is unavailable for this open, but Open is never blocked.
	// Set by checkConfigIntegrity / the ratchet; read-only after.
	anchorNote string
	// deviceID is this installation's stable writer key for the per-record vector
	// clock (design D4.1, P1-8): a random 16-byte hex loaded from appdir.DataDir
	// at Open (finishOpen), NOT from appconfig.json, so a config reset keeps it
	// (Condition 11). It is empty only when the data dir was unresolvable/unwritable
	// at Open — a degraded mode in which local writes are clockless and reconcile
	// by the Generation fallback, exactly like a 0.16 peer.
	deviceID string
}

type PutResult struct {
	Path          string
	Size          int64
	ChunkCount    int
	NewChunkCount int
}

type Stats struct {
	Files        int
	Referenced   int
	Objects      int
	ReferencedMB float64
}

func Create(root string, password string, params ChunkParams) error {
	return CreateWithOptions(root, password, CreateOptions{Chunk: params, KDF: DefaultKDFConfig()})
}

func CreateWithOptions(root string, password string, opts CreateOptions) error {
	var err error
	root, err = userpath.Abs(root)
	if err != nil {
		return err
	}
	if err := userpath.ValidateCreatableVaultPath(root); err != nil {
		return err
	}
	if password == "" {
		return errors.New("password must not be empty")
	}
	params := opts.Chunk
	if params == (ChunkParams{}) {
		params = DefaultChunkParams()
	}
	if err := params.Validate(); err != nil {
		return err
	}
	kdfCfg, err := NormalizeKDFConfig(opts.KDF, true)
	if err != nil {
		return err
	}
	// Resolve the metadata directory FIRST (design D1.1, P0-4). If EITHER name
	// already holds a vault.json — one name, or both (the ambiguous layout) — this
	// is a re-run init or a create racing an incoming .seavault sync: return the
	// existing "vault already exists" error and write nothing. Only a root with no
	// vault under either name proceeds, writing the preferred visible SeaVaultData.
	name, exists, err := ResolveMetaDir(root)
	if errors.Is(err, ErrAmbiguousMetadataDir) {
		return fmt.Errorf("vault already exists at %s", root)
	}
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("vault already exists at %s", filepath.Join(root, name))
	}
	meta := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(meta, "objects", "chunks"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(meta, ManifestDirName), 0o700); err != nil {
		return err
	}
	configPath := filepath.Join(meta, ConfigFileName)
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("vault already exists at %s", meta)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	salt, err := randomBytes(32)
	if err != nil {
		return err
	}
	master, err := randomBytes(32)
	if err != nil {
		return err
	}
	indexKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	vaultID, err := randomHex(16)
	if err != nil {
		return err
	}
	kdfCfg.Salt = base64.StdEncoding.EncodeToString(salt)
	nonce, wrapped, err := wrapKeys(password, kdfCfg, Keys{MasterKey: master, IndexKey: indexKey})
	if err != nil {
		return err
	}
	cfg := VaultConfig{
		Version:   2,
		VaultID:   vaultID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		KDF:       kdfCfg,
		Crypto: CryptoConfig{
			KeyWrap:        "AES-256-GCM",
			ChunkAEAD:      "AES-256-GCM",
			IndexAEAD:      "AES-256-GCM",
			ObjectID:       "HMAC-SHA256(indexKey, plaintextChunk)",
			Chunker:        "gear-hash content-defined chunking",
			StorageMode:    "cloud-folder content-addressed chunks plus encrypted sharded manifests",
			ManifestMode:   "encrypted-sharded-manifests-v2",
			ManifestShards: 256,
		},
		Chunk:       params,
		WrappedKeys: wrapped,
		WrapNonce:   nonce,
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(configPath, cfgJSON, 0o600); err != nil {
		return err
	}
	chunkKey := deriveSubkey(master, "chunk-aead")
	indexAEADKey := deriveSubkey(master, "index-aead")
	chunkAEAD, err := newAESGCM(chunkKey)
	if err != nil {
		return err
	}
	indexAEAD, err := newAESGCM(indexAEADKey)
	if err != nil {
		return err
	}
	v := &Vault{Root: root, MetaRoot: meta, Config: cfg, keys: Keys{MasterKey: master, IndexKey: indexKey}, chunkAEAD: chunkAEAD, indexAEAD: indexAEAD}
	return v.EnsureContentLayout()
}

func ReadConfig(root string) (VaultConfig, error) {
	root, err := userpath.Abs(root)
	if err != nil {
		return VaultConfig{}, err
	}
	// Resolve which metadata directory holds this vault (design D1.1). A root with
	// both names is ambiguous and refused; a root with neither resolves to the
	// preferred name so the read surfaces a normal os.ErrNotExist callers handle.
	name, _, err := ResolveMetaDir(root)
	if err != nil {
		return VaultConfig{}, err
	}
	cfgBytes, err := os.ReadFile(filepath.Join(root, name, ConfigFileName))
	if err != nil {
		return VaultConfig{}, err
	}
	var cfg VaultConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return VaultConfig{}, err
	}
	if cfg.VaultID == "" {
		cfg.VaultID = legacyVaultID(root, cfg)
	}
	return cfg, nil
}

// unlockWith is the format-v3 read leg (design D3.2, P1-7). It unwraps the
// master||index bundle from the first WrapEntries entry of type wantType that
// the secret opens; when WrapEntries is empty it falls back to reading the
// legacy top-level WrappedKeys/WrapNonce as the implicit {Type:"password",
// legacy AAD} entry (design D3.1), so every pre-A2 vault opens unchanged (I1).
//
// A wrong secret matches nothing and returns the single generic errWrongSecret:
// per-entry failures are swallowed and the next entry tried, so the caller
// cannot learn which entry (or how many) exist — no per-entry oracle (D3.2). A
// password unlock derives exactly one wrap key per candidate entry, and rotation
// never appends a second password entry, so a legitimate password touches one.
func (cfg VaultConfig) unlockWith(secret, wantType string) (Keys, error) {
	if len(cfg.WrapEntries) == 0 {
		// Un-migrated / grace-release vault: the top-level wrap IS the implicit
		// legacy-AAD password entry. Read it directly and propagate its error
		// verbatim (a decode error stays a decode error; a wrong password stays
		// the exact pre-A2 generic message) so I1 interop is byte-for-byte
		// unchanged. A recovery redeem on such a vault finds no recovery entry.
		if wantType != WrapTypePassword {
			return Keys{}, errWrongSecret
		}
		return unwrapKeys(secret, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys)
	}
	for _, e := range cfg.WrapEntries {
		if e.Type != wantType {
			continue
		}
		if keys, err := unwrapEntry(secret, cfg.Version, e); err == nil {
			return keys, nil
		}
	}
	// Legacy top-level wrap as a fallback when WrapEntries is populated but has no
	// matching PASSWORD entry (design D3.2 "then the legacy fields"): a legacy
	// vault that gained a recovery entry (via `recovery generate`) carries a
	// recovery-only WrapEntries array yet must still open with its original
	// password, which lives only in the legacy fields. Kept current by every
	// rotation (Condition 4). Errors here are swallowed into the generic result —
	// no per-entry oracle — unlike the empty-WrapEntries branch above, which must
	// preserve the exact pre-A2 messages for I1.
	if wantType == WrapTypePassword && cfg.WrappedKeys != "" {
		if keys, err := unwrapKeys(secret, cfg.KDF, cfg.WrapNonce, cfg.WrappedKeys); err == nil {
			return keys, nil
		}
	}
	return Keys{}, errWrongSecret
}

// recoveryEntryFor unwraps the master||index bundle from the first recovery
// WrapEntry the secret opens and returns that entry's ID (design D3.3): the
// redeem transaction needs the ID to remove exactly the entry that was used. A
// secret matching no recovery entry returns the generic errWrongSecret with no
// per-entry oracle. Recovery secrets are never in the legacy fields, so there is
// no legacy fallback here.
func (cfg VaultConfig) recoveryEntryFor(secret string) (Keys, string, error) {
	for _, e := range cfg.WrapEntries {
		if e.Type != WrapTypeRecovery {
			continue
		}
		if keys, err := unwrapEntry(secret, cfg.Version, e); err == nil {
			return keys, e.ID, nil
		}
	}
	return Keys{}, "", errWrongSecret
}

// Open unlocks a vault with a password. It is the historical entry point and is
// treated as an INTERACTIVE unlock (design D5.3): a detected rotation rollback
// warns and opens rather than hard-refusing, matching every existing caller
// (the GUI login form, a CLI prompt) that has a human present. The strict
// non-interactive disposition is opt-in through OpenWithOptions.
func Open(root string, password string) (*Vault, error) {
	return OpenWithOptions(root, password, OpenOptions{})
}

// OpenWithOptions unlocks a vault with a password under an explicit freshness
// disposition (design D5.3, Condition 9): a non-interactive unlock (the zero
// OpenOptions) hard-refuses a rolled-back config, an interactive one warns and
// opens, and AcceptRollback accepts a restore and re-TOFUs.
func OpenWithOptions(root string, password string, opts OpenOptions) (*Vault, error) {
	root, cfg, metaName, metaExists, err := prepareOpen(root, password)
	if err != nil {
		return nil, err
	}
	// Read leg (design D3.2, P1-7): unlock with the password, trying each
	// WrapEntries "password" entry and falling back to the legacy top-level wrap.
	// A recovery secret is redeemed through OpenWithRecovery, not here; a wrong
	// password matches nothing and returns the generic errWrongSecret with no
	// per-entry oracle.
	keys, err := cfg.unlockWith(password, WrapTypePassword)
	if err != nil {
		return nil, err
	}
	return finishOpen(root, metaName, metaExists, cfg, keys, opts)
}

// OpenWithRecovery unlocks a vault with a recovery phrase (design D3.3, P1-7): it
// canonicalises the phrase, opens the first recovery WrapEntry it matches, and
// returns the opened vault plus that entry's ID so a redeem transaction can
// remove exactly the entry that was used (Condition 1). It runs the same
// post-unlock integrity/freshness gate as Open.
func OpenWithRecovery(root string, phrase string, opts OpenOptions) (*Vault, string, error) {
	root, cfg, metaName, metaExists, err := prepareOpen(root, phrase)
	if err != nil {
		return nil, "", err
	}
	keys, entryID, err := cfg.recoveryEntryFor(canonicalRecovery(phrase))
	if err != nil {
		return nil, "", err
	}
	v, err := finishOpen(root, metaName, metaExists, cfg, keys, opts)
	if err != nil {
		return nil, "", err
	}
	return v, entryID, nil
}

// prepareOpen performs the pre-unlock work shared by every open path: resolve the
// root, reject an empty secret, read and version-check the config, apply the
// pre-MAC MinReader forward fence (design D1.2/D1.3), and resolve the metadata
// directory name. It never unwraps, so the MinReader fence trips before any work
// and before any wrong-secret error.
func prepareOpen(root, secret string) (string, VaultConfig, string, bool, error) {
	abs, err := userpath.Abs(root)
	if err != nil {
		return "", VaultConfig{}, "", false, err
	}
	if secret == "" {
		return "", VaultConfig{}, "", false, errors.New("password must not be empty")
	}
	cfg, err := ReadConfig(abs)
	if err != nil {
		return "", VaultConfig{}, "", false, err
	}
	if cfg.Version != 1 && cfg.Version != 2 && cfg.Version != 3 {
		return "", VaultConfig{}, "", false, fmt.Errorf("unsupported vault version %d", cfg.Version)
	}
	// Forward-compatibility fence (design D1.2/D1.3, P1-20): a vault whose
	// MinReader exceeds what this build implements is refused BEFORE any unwrap.
	// MinReader is pre-MAC here, so the wrapped ErrFormatTooNew message is hedged
	// about tampering (D1.3); after unwrap the same field is MAC-covered, so a
	// forged value is additionally caught as config tampering. Absent MinReader
	// reads as 0 and never fences.
	if err := formatTooNew(cfg.MinReader, SupportedFormat); err != nil {
		return "", VaultConfig{}, "", false, err
	}
	// Resolve the metadata directory name so MetaRoot points at the actual layout
	// (SeaVaultData for new vaults, .seavault for legacy ones); ReadConfig already
	// refused an ambiguous root, so this cannot report ambiguity here (design D1.1).
	metaName, metaExists, err := ResolveMetaDir(abs)
	if err != nil {
		return "", VaultConfig{}, "", false, err
	}
	return abs, cfg, metaName, metaExists, nil
}

// finishOpen builds the *Vault from an unwrapped key bundle and runs the
// post-unlock gates (design §2, §5): derive the chunk/index AEADs, verify the
// ConfigMAC and freshness anchor (a wrong secret already failed above, so there
// is no MAC oracle), surface the D1.3 preflight note for a legacy .seavault vault
// under a sync folder, and ensure the content layout. Shared by OpenWithOptions
// and OpenWithRecovery so both unlock paths run an identical gate.
func finishOpen(root, metaName string, metaExists bool, cfg VaultConfig, keys Keys, opts OpenOptions) (*Vault, error) {
	chunkKey := deriveSubkey(keys.MasterKey, "chunk-aead")
	indexKey := deriveSubkey(keys.MasterKey, "index-aead")
	chunkAEAD, err := newAESGCM(chunkKey)
	if err != nil {
		return nil, err
	}
	indexAEAD, err := newAESGCM(indexKey)
	if err != nil {
		return nil, err
	}
	v := &Vault{Root: root, MetaRoot: filepath.Join(root, metaName), Config: cfg, keys: keys, chunkAEAD: chunkAEAD, indexAEAD: indexAEAD}
	v.deviceID = resolveDeviceID()
	if err := v.checkConfigIntegrity(opts); err != nil {
		return nil, err
	}
	// Record this device's reader signal (design D1.4, Condition 14): a
	// device-local, never-synced note that this DeviceID opened the vault at this
	// SupportedFormat. seal-format prints this inventory before retiring older
	// readers. Best-effort — a missing device id or unwritable appdir simply
	// leaves the inventory thinner, and never blocks Open.
	v.recordReaderSignal()
	if metaExists && metaName == MetadataDirName {
		v.openNote = LegacyOpenPreflightNote(root)
	}
	if err := v.EnsureContentLayout(); err != nil {
		return nil, err
	}
	return v, nil
}

// PreflightNote returns the informational note produced when this vault was
// opened (design D1.3), or "" when there is none. It is set only for a legacy
// .seavault vault under a sync-client folder and never causes a write.
func (v *Vault) PreflightNote() string { return v.openNote }

// FreshnessAnchorNote returns the one-time note produced when the device-local
// freshness anchor could not be resolved or written during Open (design D5.4),
// or "" when the anchor was available. It signals that rollback protection is
// not in effect for this open; Open itself is never blocked by an unwritable
// appdir.
func (v *Vault) FreshnessAnchorNote() string { return v.anchorNote }

func (v *Vault) ID() string {
	if v.Config.VaultID != "" {
		return v.Config.VaultID
	}
	return legacyVaultID(v.Root, v.Config)
}

// DeviceID exposes this installation's stable vector-clock writer key (design
// D4.1, P1-8), loaded from appdir.DataDir at Open. It is "" only in the degraded
// mode where the data dir was unavailable at Open, in which case local writes are
// clockless. Chiefly a test and diagnostics seam; the write path reads v.deviceID
// directly.
func (v *Vault) DeviceID() string { return v.deviceID }

// resolveDeviceID loads this installation's stable device id from appdir.DataDir
// (design D4.1, Condition 11). It is best-effort like the freshness anchor: if
// the data dir is unresolvable or unwritable, it returns "" and Open proceeds
// with clockless local writes (Generation fallback) rather than blocking — the
// vector clock is an additive improvement, never a gate on opening a vault.
func resolveDeviceID() string {
	id, err := appdir.DeviceID()
	if err != nil {
		return ""
	}
	return id
}

func legacyVaultID(root string, cfg VaultConfig) string {
	b, _ := json.Marshal(struct {
		Root string
		Salt string
	}{Root: root, Salt: cfg.KDF.Salt})
	return hmacHex([]byte("seavault-legacy-vault-id"), b)[:32]
}

func (v *Vault) usesManifestStore() bool {
	return v.Config.Version >= 2 || v.Config.Crypto.ManifestMode != ""
}

// LoadIndex returns an owned (deep-copied) snapshot of the vault index. The
// first call decrypts and reconciles the manifests from disk; subsequent calls
// return a copy of the in-memory cache, so repeated operations on a long-lived
// *Vault no longer re-walk and re-decrypt every manifest (the cause of O(N) per
// operation / O(N^2) bulk ingest). Callers may freely mutate the returned copy.
func (v *Vault) LoadIndex() (Index, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	idx, err := v.cachedIndexLocked()
	if err != nil {
		return Index{}, err
	}
	return cloneIndex(*idx), nil
}

// loadIndexFromDisk rebuilds the index from the encrypted manifests (or the
// legacy single-index file). It performs the on-disk conflict reconciliation
// and is intentionally only invoked once per cache lifetime.
func (v *Vault) loadIndexFromDisk() (Index, error) {
	// Downgrade detection (design D2.1, P0-3): a vault.json that claims a legacy
	// single-index (or version 1) layout while encrypted manifests exist on disk
	// has been downgraded or replaced. Opening it as a legacy vault would ignore
	// every manifest, so refuse instead. Presence is checked without decryption so
	// the common load path pays only a directory stat.
	if !v.usesManifestStore() || v.Config.Version == 1 {
		present, err := v.manifestFilesPresent()
		if err != nil {
			return Index{}, err
		}
		if present {
			return Index{}, ErrConfigInconsistent
		}
	}
	if v.usesManifestStore() {
		idx, plan, err := v.loadManifestIndex()
		if err != nil {
			return Index{}, err
		}
		if plan.sawManifest {
			return idx, nil
		}
	}
	idx, err := v.loadLegacyIndex()
	if errors.Is(err, os.ErrNotExist) {
		return NewIndex(), nil
	}
	return idx, err
}

func (v *Vault) loadLegacyIndex() (Index, error) {
	data, err := os.ReadFile(filepath.Join(v.MetaRoot, IndexFileName))
	if err != nil {
		return Index{}, err
	}
	nonce, ct, err := decodeEncrypted(indexMagic, v.indexAEAD.NonceSize(), data)
	if err != nil {
		return Index{}, err
	}
	pt, err := v.indexAEAD.Open(nil, nonce, ct, []byte(indexAAD))
	if err != nil {
		return Index{}, errors.New("index decrypt failed: wrong password or damaged index")
	}
	var idx Index
	if err := json.Unmarshal(pt, &idx); err != nil {
		return Index{}, err
	}
	if idx.Files == nil {
		idx.Files = map[string]FileRecord{}
	}
	return idx, nil
}

func (v *Vault) SaveIndex(idx Index) error {
	idx.Version = 2
	idx.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if v.usesManifestStore() {
		if err := v.saveIndexAsManifests(idx); err != nil {
			return err
		}
		v.cacheReplace(idx)
		return nil
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	nonce, err := randomBytes(v.indexAEAD.NonceSize())
	if err != nil {
		return err
	}
	ct := v.indexAEAD.Seal(nil, nonce, data, []byte(indexAAD))
	if err := atomicWriteFile(filepath.Join(v.MetaRoot, IndexFileName), encodeEncrypted(indexMagic, nonce, ct), 0o600); err != nil {
		return err
	}
	v.cacheReplace(idx)
	return nil
}

// PutReport is the outcome of a PutPathReport call: the per-file results plus any
// advisory warnings raised during the walk (design D1.2). A warning never fails
// the put; it records something the operator should know, such as a source
// directory named like a SeaVault metadata dir that was imported as plain
// content rather than skipped.
type PutReport struct {
	Results  []PutResult
	Warnings []string
}

func (v *Vault) PutPath(sourcePath string, virtualPath string) ([]PutResult, error) {
	rep, err := v.PutPathReport(sourcePath, virtualPath)
	return rep.Results, err
}

// PutPathReport stores sourcePath under virtualPath and returns a PutReport. When
// the source is a directory, its walk excludes exactly THIS vault's own metadata
// directory — the directory whose absolute path equals v.MetaRoot — so a put
// whose source is the vault root (or an ancestor) never re-imports the encrypted
// metadata. A source directory that merely shares a metadata NAME but is not this
// vault's own (a second vault's SeaVaultData, a legacy .seavault in a backup
// tree) is imported like ordinary content and recorded as a warning, never
// silently skipped (design D1.2, P0-4).
func (v *Vault) PutPathReport(sourcePath string, virtualPath string) (PutReport, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return PutReport{}, err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return PutReport{}, err
	}
	var results []PutResult
	var written []string
	var warnings []string
	if !info.IsDir() {
		vp := virtualPath
		if strings.TrimSpace(vp) == "" {
			vp = filepath.Base(sourcePath)
		}
		cleaned, err := normalizeContentFilePath(vp)
		if err != nil {
			return PutReport{}, err
		}
		// A single-file put names its virtual path directly, so the D1.2 create
		// gate applies (unlike the directory-tree branch below, where a foreign
		// metadata-named subdir is imported as content with a warning). Overwriting
		// an existing reserved-segment path still works (design D7.1, peer/F3).
		if _, exists := idx.Files[cleaned]; !exists {
			if err := reservedNewPathError(cleaned); err != nil {
				return PutReport{}, err
			}
		}
		res, err := v.putFile(sourcePath, cleaned, &idx)
		if err != nil {
			return PutReport{}, err
		}
		results = append(results, res)
		written = append(written, cleaned)
	} else {
		baseVirtual := virtualPath
		if strings.TrimSpace(baseVirtual) == "" {
			baseVirtual = filepath.Base(sourcePath)
		}
		baseVirtual, err = normalizeContentDirPath(baseVirtual)
		if err != nil {
			return PutReport{}, err
		}
		metaRootAbs, _ := filepath.Abs(v.MetaRoot)
		err := filepath.WalkDir(sourcePath, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" {
					return filepath.SkipDir
				}
				if abs, aerr := filepath.Abs(p); aerr == nil && abs == metaRootAbs {
					// This vault's own metadata: skip it, never import it.
					return filepath.SkipDir
				}
				if isMetadataDirName(name) {
					// A foreign directory that merely shares a metadata name: import
					// its contents as plain content and warn, do not skip.
					warnings = append(warnings, fmt.Sprintf("source contains a directory named like a SeaVault metadata dir (%s); it was imported as plain content", p))
				}
				return nil
			}
			rel, err := filepath.Rel(sourcePath, p)
			if err != nil {
				return err
			}
			vp, err := virtualJoin(baseVirtual, rel)
			if err != nil {
				return err
			}
			res, err := v.putFile(p, vp, &idx)
			if err != nil {
				return err
			}
			results = append(results, res)
			written = append(written, vp)
			return nil
		})
		if err != nil {
			return PutReport{}, err
		}
	}
	if v.usesManifestStore() {
		for _, p := range written {
			if err := v.commitFileManifest(p, idx.Files[p]); err != nil {
				return PutReport{}, err
			}
		}
		return PutReport{Results: results, Warnings: warnings}, nil
	}
	return PutReport{Results: results, Warnings: warnings}, v.SaveIndex(idx)
}

func (v *Vault) putFile(sourcePath string, virtualPath string, idx *Index) (PutResult, error) {
	// Portable-name gate for a NEW path only (design D7.1, B6): importing a file
	// under an illegal leaf that no Windows peer could recreate is refused, but
	// overwriting an existing (peer/legacy) illegal name keeps working.
	if _, exists := idx.Files[virtualPath]; !exists {
		if err := ValidatePortableName(path.Base(virtualPath)); err != nil {
			return PutResult{}, err
		}
	}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return PutResult{}, err
	}
	f, err := os.Open(sourcePath)
	if err != nil {
		return PutResult{}, err
	}
	defer f.Close()
	return v.putReader(f, virtualPath, info.Size(), uint32(info.Mode().Perm()), info.ModTime(), idx)
}

func (v *Vault) PutReader(r io.Reader, virtualPath string, size int64, mode uint32, modTime time.Time) (PutResult, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return PutResult{}, err
	}
	vp, err := normalizeContentFilePath(virtualPath)
	if err != nil {
		return PutResult{}, err
	}
	// Create-time gates for a NEW upload target only (design D7.1/D1.2, B6):
	// neither metadata dir name may be CREATED as a virtual path segment, and the
	// leaf must be portable. Overwriting an EXISTING path — reserved-segment or
	// illegal leaf, peer/legacy-created — still works (finding peer/F3).
	if _, exists := idx.Files[vp]; !exists {
		if err := reservedNewPathError(vp); err != nil {
			return PutResult{}, err
		}
		if err := ValidatePortableName(path.Base(vp)); err != nil {
			return PutResult{}, err
		}
	}
	res, err := v.putReader(r, vp, size, mode, modTime, &idx)
	if err != nil {
		return PutResult{}, err
	}
	if v.usesManifestStore() {
		return res, v.commitFileManifest(vp, idx.Files[vp])
	}
	return res, v.SaveIndex(idx)
}

func (v *Vault) putReader(r io.Reader, virtualPath string, size int64, mode uint32, modTime time.Time, idx *Index) (PutResult, error) {
	var refs []ChunkRef
	newCount := 0
	var total int64
	err := ForEachChunk(r, v.Config.Chunk, func(chunk []byte) error {
		total += int64(len(chunk))
		ref, created, err := v.storeChunk(chunk)
		if err != nil {
			return err
		}
		refs = append(refs, ref)
		if created {
			newCount++
		}
		return nil
	})
	if err != nil {
		return PutResult{}, err
	}
	if modTime.IsZero() {
		modTime = time.Now().UTC()
	}
	if mode == 0 {
		mode = 0o600
	}
	if size < 0 {
		size = total
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	wallNano := unixNanoOrNow(now)
	generation := v.nextGeneration(wallNano)
	// Advance the per-record vector clock (design D4.1): carry forward the clock of
	// the record this write supersedes and bump this device's own entry, so a local
	// write causally supersedes everything the device has merged and reconciles
	// cleanly (no spurious conflict) against its own earlier versions.
	clock, clockAge := v.nextRecordClock(idx, virtualPath, wallNano)
	idx.Files[virtualPath] = FileRecord{Size: size, Mode: mode, ModTime: modTime.UTC().Format(time.RFC3339Nano), UpdatedAt: now, Generation: generation, Chunks: refs, Clock: clock, ClockAge: clockAge}
	return PutResult{Path: virtualPath, Size: size, ChunkCount: len(refs), NewChunkCount: newCount}, nil
}

func (v *Vault) storeChunk(plaintext []byte) (ChunkRef, bool, error) {
	id := hmacHex(v.keys.IndexKey, plaintext)
	ref := ChunkRef{ID: id, Size: len(plaintext)}
	objectPath := v.chunkPath(id)
	if _, err := os.Stat(objectPath); err == nil {
		return ref, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ChunkRef{}, false, err
	}
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		return ChunkRef{}, false, err
	}
	nonce, err := randomBytes(v.chunkAEAD.NonceSize())
	if err != nil {
		return ChunkRef{}, false, err
	}
	aad := []byte(chunkAADPrefix + id)
	ct := v.chunkAEAD.Seal(nil, nonce, plaintext, aad)
	if err := atomicWriteFile(objectPath, encodeEncrypted(chunkMagic, nonce, ct), 0o600); err != nil {
		return ChunkRef{}, false, err
	}
	return ref, true, nil
}

// ensureDestinationOutsideVault rejects a decrypted-output path that resolves
// to within the vault's encrypted metadata directory (.seavault). Writing
// plaintext there would place it in the very directory that syncs to the
// server, silently breaking the zero-knowledge guarantee. Calling this at every
// export/restore entry point makes that guarantee enforced, not advisory.
func (v *Vault) ensureDestinationOutsideVault(dest string) error {
	abs, err := userpath.Abs(dest)
	if err != nil {
		return err
	}
	meta, err := filepath.Abs(v.MetaRoot)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(meta, abs)
	if err != nil {
		return err
	}
	inside := rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	if inside {
		return fmt.Errorf("refusing to write decrypted output inside the encrypted vault directory %q: choose a destination outside the vault so plaintext is never synced to the server", v.MetaRoot)
	}
	return nil
}

func (v *Vault) GetPath(virtualPath string, destPath string) error {
	if err := v.ensureDestinationOutsideVault(destPath); err != nil {
		return err
	}
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	vp, err := normalizeContentDirPath(virtualPath)
	if err != nil {
		return err
	}
	if rec, ok := idx.Files[vp]; ok {
		return v.restoreFile(rec, destPath)
	}
	prefix := vp
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var matches []string
	for p := range idx.Files {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	sort.Strings(matches)
	for _, p := range matches {
		rel := p
		if prefix != "" {
			rel = strings.TrimPrefix(p, prefix)
		}
		target := filepath.Join(destPath, filepath.FromSlash(rel))
		if err := v.restoreFile(idx.Files[p], target); err != nil {
			return fmt.Errorf("restore %s: %w", p, err)
		}
	}
	return nil
}

func (v *Vault) restoreFile(rec FileRecord, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".seavault-restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	var writeErr error
	defer func() {
		tmp.Close()
		if writeErr != nil {
			os.Remove(tmpName)
		}
	}()
	for _, ref := range rec.Chunks {
		chunk, err := v.loadChunk(ref)
		if err != nil {
			writeErr = err
			return err
		}
		if _, err := tmp.Write(chunk); err != nil {
			writeErr = err
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	mode := os.FileMode(rec.Mode)
	if mode == 0 {
		mode = 0o600
	}
	_ = os.Chmod(tmpName, mode)
	if rec.ModTime != "" {
		if t, err := time.Parse(time.RFC3339Nano, rec.ModTime); err == nil {
			_ = os.Chtimes(tmpName, t, t)
		}
	}
	if err := renameWithRetry(tmpName, destPath); err != nil {
		return err
	}
	// The restored file is durably in place after the rename; a failed
	// best-effort directory fsync must not report the restore as failed
	// (design D5.2, integrity/F5).
	_ = fsyncDir(filepath.Dir(destPath))
	return nil
}

func (v *Vault) WriteFileTo(virtualPath string, w io.Writer) error {
	idx, err := v.LoadIndex()
	if err != nil {
		return err
	}
	vp, err := normalizeContentFilePath(virtualPath)
	if err != nil {
		return err
	}
	rec, ok := idx.Files[vp]
	if !ok {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	for _, ref := range rec.Chunks {
		chunk, err := v.loadChunk(ref)
		if err != nil {
			return err
		}
		if _, err := w.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) loadChunk(ref ChunkRef) ([]byte, error) {
	data, err := os.ReadFile(v.chunkPath(ref.ID))
	if err == nil {
		pt, dErr := v.decodeChunk(data, ref)
		if dErr == nil {
			return pt, nil
		}
		// The canonical object exists but is unreadable (corruption or a partial
		// write). A sync client may have left an intact renamed copy; try those
		// before surfacing the failure.
		if pt, ok := v.tryConflictChunks(ref); ok {
			return pt, nil
		}
		return nil, dErr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// The canonical object is absent. A Nextcloud-style sync conflict can rename
	// <id>.chunk to <id>.sync-conflict-*.chunk; recover from such a copy.
	if pt, ok := v.tryConflictChunks(ref); ok {
		return pt, nil
	}
	// Genuinely not present: a permanently missing object, OR a file whose chunk
	// has not finished syncing yet. Wrap os.ErrNotExist so callers (e.g. verify
	// classification) still detect it while the message stays clear.
	return nil, fmt.Errorf("chunk %s not present (missing object, or not yet synced): %w", ref.ID, os.ErrNotExist)
}

func (v *Vault) decodeChunk(data []byte, ref ChunkRef) ([]byte, error) {
	nonce, ct, err := decodeEncrypted(chunkMagic, v.chunkAEAD.NonceSize(), data)
	if err != nil {
		return nil, err
	}
	pt, err := v.chunkAEAD.Open(nil, nonce, ct, []byte(chunkAADPrefix+ref.ID))
	if err != nil {
		return nil, fmt.Errorf("chunk %s decrypt/authenticate failed", ref.ID)
	}
	if len(pt) != ref.Size {
		return nil, fmt.Errorf("chunk %s size mismatch", ref.ID)
	}
	actual := hmacHex(v.keys.IndexKey, pt)
	if !constantTimeStringEqual(actual, ref.ID) {
		return nil, fmt.Errorf("chunk %s object ID mismatch", ref.ID)
	}
	return pt, nil
}

// tryConflictChunks looks for a sync-client-renamed copy of a chunk object in
// its shard directory (e.g. "<id>.sync-conflict-….chunk" or
// "<id> (conflicted copy).chunk") and returns the first that decrypts and
// authenticates to the expected object id. This recovers a chunk when the
// canonical "<id>.chunk" was renamed or replaced by a cloud sync conflict.
func (v *Vault) tryConflictChunks(ref ChunkRef) ([]byte, bool) {
	canonical := v.chunkPath(ref.ID)
	dir := filepath.Dir(canonical)
	canonicalName := filepath.Base(canonical)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == canonicalName || !strings.HasPrefix(name, ref.ID) || !strings.HasSuffix(strings.ToLower(name), ".chunk") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if pt, dErr := v.decodeChunk(data, ref); dErr == nil {
			return pt, true
		}
	}
	return nil, false
}

func (v *Vault) List() ([]string, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		if IsInternalVirtualPath(p) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (v *Vault) FileInfo(virtualPath string) (FileRecord, bool, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return FileRecord{}, false, err
	}
	vp, err := normalizeContentFilePath(virtualPath)
	if err != nil {
		return FileRecord{}, false, err
	}
	rec, ok := idx.Files[vp]
	return rec, ok, nil
}

func (v *Vault) Files() (map[string]FileRecord, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	out := make(map[string]FileRecord, len(idx.Files))
	for k, rec := range idx.Files {
		if IsInternalVirtualPath(k) {
			continue
		}
		rec.Chunks = append([]ChunkRef(nil), rec.Chunks...)
		out[k] = rec
	}
	return out, nil
}

func (v *Vault) AllEntries() (map[string]FileRecord, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return nil, err
	}
	out := make(map[string]FileRecord, len(idx.Files))
	for k, rec := range idx.Files {
		rec.Chunks = append([]ChunkRef(nil), rec.Chunks...)
		out[k] = rec
	}
	return out, nil
}

func (v *Vault) Remove(virtualPath string) error {
	removed, err := v.RemovePath(virtualPath)
	if err != nil {
		return err
	}
	if removed == 0 {
		return fmt.Errorf("virtual path %q not found", virtualPath)
	}
	return nil
}

func (v *Vault) RemovePath(virtualPath string) (int, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return 0, err
	}
	vp, err := normalizeContentDirPath(virtualPath)
	if err != nil {
		return 0, err
	}
	if vp == ContentRootName {
		return 0, fmt.Errorf("%s/ is the protected vault workspace and cannot be deleted", ContentRootName)
	}
	var targets []string
	if _, ok := idx.Files[vp]; ok {
		targets = append(targets, vp)
	} else {
		prefix := vp
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		for p := range idx.Files {
			if prefix == "" || strings.HasPrefix(p, prefix) {
				targets = append(targets, p)
			}
		}
	}
	if len(targets) == 0 {
		return 0, fmt.Errorf("virtual path %q not found", virtualPath)
	}
	generations := make(map[string]int64, len(targets))
	superseded := make(map[string]int64, len(targets))
	clocks := make(map[string]map[string]int64, len(targets))
	for _, p := range targets {
		// Each call returns a strictly increasing generation above everything
		// observed, so a delete always supersedes any older synced edit and the
		// per-target tombstones remain distinctly ordered.
		generations[p] = v.nextGeneration(time.Now().UTC().UnixNano())
		// Record the generation of the live record being deleted so the tombstone
		// carries a deletedGeneration (design D4.2): a stale synced copy at or
		// below it stays suppressed, a newer concurrent edit above it surfaces as
		// a conflict instead of being lost.
		superseded[p] = idx.Files[p].Generation
		// Advance the tombstone's vector clock over the record being deleted
		// (design D4.3): the delete must DOMINATE the edit it saw (a clean delete),
		// while a concurrent edit from a device it never saw stays concurrent and
		// survives as a conflict (R10). advanceClock joins the deleted record's
		// full clock and bumps this device — with NO aging, so the tombstone always
		// strictly dominates the record (and any stale copy of it); aging an entry
		// out here could leave the tombstone merely concurrent and resurrect the
		// deleted file as a spurious conflict.
		clocks[p] = v.advanceClock(idx.Files[p].Clock, time.Now().UTC().UnixNano())
	}
	for _, p := range targets {
		delete(idx.Files, p)
	}
	if v.usesManifestStore() {
		for _, p := range targets {
			if err := v.commitTombstone(p, generations[p], superseded[p], clocks[p]); err != nil {
				return 0, err
			}
		}
		return len(targets), nil
	}
	return len(targets), v.SaveIndex(idx)
}

type VerifyIssue struct {
	Path      string `json:"path,omitempty"`
	ChunkID   string `json:"chunkId,omitempty"`
	ChunkPath string `json:"chunkPath,omitempty"`
	Kind      string `json:"kind"`
	Error     string `json:"error"`
}

type VerifyReport struct {
	OK            bool          `json:"ok"`
	FilesChecked  int           `json:"filesChecked"`
	ChunksChecked int           `json:"chunksChecked"`
	BytesChecked  int64         `json:"bytesChecked"`
	MissingChunks int           `json:"missingChunks"`
	CorruptChunks int           `json:"corruptChunks"`
	OtherErrors   int           `json:"otherErrors"`
	Issues        []VerifyIssue `json:"issues,omitempty"`
	// PendingIntents lists deletion intents in flight so an operator sees a GC
	// delete queued but not yet fenced-out (design D3.6). Reads write nothing.
	PendingIntents []PendingIntent `json:"pendingIntents,omitempty"`
}

type VerifyError struct {
	Report VerifyReport
}

func (e *VerifyError) Error() string {
	if e == nil {
		return "vault verification failed"
	}
	return fmt.Sprintf("vault verification failed: %d issue(s), %d missing chunk(s), %d corrupt chunk(s), %d other error(s)", len(e.Report.Issues), e.Report.MissingChunks, e.Report.CorruptChunks, e.Report.OtherErrors)
}

func (v *Vault) Verify() error {
	report, err := v.VerifyReport()
	if err != nil {
		return err
	}
	if !report.OK {
		return &VerifyError{Report: report}
	}
	return nil
}

func (v *Vault) VerifyReport() (VerifyReport, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return VerifyReport{}, fmt.Errorf("load vault index: %w", err)
	}
	report := VerifyReport{OK: true}
	paths := make([]string, 0, len(idx.Files))
	for p := range idx.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	report.FilesChecked = len(paths)
	for _, p := range paths {
		for _, ref := range idx.Files[p].Chunks {
			report.ChunksChecked++
			report.BytesChecked += int64(ref.Size)
			if _, err := v.loadChunk(ref); err != nil {
				report.OK = false
				issue := VerifyIssue{
					Path:      p,
					ChunkID:   ref.ID,
					ChunkPath: v.chunkPath(ref.ID),
					Kind:      classifyVerifyIssue(err),
					Error:     err.Error(),
				}
				switch issue.Kind {
				case "missing_chunk":
					report.MissingChunks++
				case "corrupt_chunk":
					report.CorruptChunks++
				default:
					report.OtherErrors++
				}
				report.Issues = append(report.Issues, issue)
			}
		}
	}
	// List any deletion intents in flight (design D3.6). This is a pure read of
	// the gc-intents directory; it writes nothing (invariant I2).
	if intents, ierr := v.walkIntents(); ierr == nil {
		report.PendingIntents = pendingList(intents, time.Now())
	}
	return report, nil
}

func classifyVerifyIssue(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "missing_chunk"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "decrypt") || strings.Contains(msg, "authenticate") || strings.Contains(msg, "size mismatch") || strings.Contains(msg, "object id mismatch") || strings.Contains(msg, "decode") {
		return "corrupt_chunk"
	}
	return "read_error"
}

// chunkIDFromFileName returns the 64-hex object id that a chunk filename belongs
// to, tolerating sync-client conflict suffixes after the id. It returns "" for
// names that do not begin with a 64-hex object id. The id is lower-cased so an
// upper- or mixed-case chunk name (produced by a case-insensitive or
// case-folding filesystem, or a peer) maps to the same live id as its canonical
// lower-case object and GC keeps it (design D6.1, P3 hex-case-mismatch-gc).
func chunkIDFromFileName(name string) string {
	if len(name) >= 64 && isHex(name[:64]) {
		return strings.ToLower(name[:64])
	}
	return ""
}

func (v *Vault) Stats() (Stats, error) {
	idx, err := v.LoadIndex()
	if err != nil {
		return Stats{}, err
	}
	live := map[string]int{}
	var referencedBytes int64
	visibleFiles := 0
	for p, rec := range idx.Files {
		if IsInternalVirtualPath(p) {
			continue
		}
		visibleFiles++
		for _, ref := range rec.Chunks {
			live[ref.ID] = ref.Size
			referencedBytes += int64(ref.Size)
		}
	}
	objects := 0
	_ = filepath.WalkDir(filepath.Join(v.MetaRoot, "objects", "chunks"), func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".chunk") {
			objects++
		}
		return nil
	})
	return Stats{Files: visibleFiles, Referenced: len(live), Objects: objects, ReferencedMB: float64(referencedBytes) / 1024.0 / 1024.0}, nil
}

func (v *Vault) chunkPath(id string) string {
	prefix := id
	if len(prefix) > 2 {
		prefix = id[:2]
	}
	return filepath.Join(v.MetaRoot, "objects", "chunks", prefix, id+".chunk")
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameWithRetry(tmpName, path); err != nil {
		return err
	}
	ok = true
	// The rename above has already durably published the file at `path`. The
	// directory fsync is a best-effort crash-ordering nicety (design D5.2): on
	// filesystems that do not support directory fsync (some FUSE/network mounts)
	// it returns EINVAL/ENOTSUP. Do not turn an already-durable write into a
	// reported failure over it (integrity/F5) — every caller (chunk, manifest,
	// index, intent, seen store) would otherwise see spurious errors while the
	// data is on disk.
	_ = fsyncDir(filepath.Dir(path))
	return nil
}

func Copy(dst io.Writer, src io.Reader) (int64, error) { return io.Copy(dst, src) }
