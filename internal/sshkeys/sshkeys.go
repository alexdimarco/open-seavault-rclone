// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package sshkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexdimarco/open-seavault-rclone/internal/appdir"
	"github.com/alexdimarco/open-seavault-rclone/internal/userpath"
)

type Entry struct {
	Name        string `json:"name"`
	PrivatePath string `json:"privatePath"`
	PublicPath  string `json:"publicPath"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"createdAt"`
	Managed     bool   `json:"managed"`
}

func KeyDir() (string, error) { return appdir.EnsureConfigDir("ssh") }

func Generate(_ context.Context, name string) (Entry, error) { return GenerateEd25519(name, "") }

func GenerateEd25519(name, comment string) (Entry, error) {
	name = sanitizeName(name)
	if name == "" {
		return Entry{}, errors.New("key name is required")
	}
	if comment == "" {
		comment = "seavault-" + name
	}
	dir, err := KeyDir()
	if err != nil {
		return Entry{}, err
	}
	privPath := filepath.Join(dir, name+"_ed25519")
	pubPath := privPath + ".pub"
	if _, err := os.Stat(privPath); err == nil {
		return Entry{}, fmt.Errorf("key already exists: %s", privPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Entry{}, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Entry{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Entry{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := atomicWriteFile(privPath, pemBytes, 0o600); err != nil {
		return Entry{}, err
	}
	auth := AuthorizedKey(pub, comment)
	if err := atomicWriteFile(pubPath, []byte(auth), 0o644); err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, PrivatePath: privPath, PublicPath: pubPath, Fingerprint: FingerprintAuthorized(auth), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Managed: true}, nil
}

func Import(name, src string) (Entry, error) {
	name = sanitizeName(name)
	if name == "" {
		return Entry{}, errors.New("key name is required")
	}
	abs, err := userpath.Abs(src)
	if err != nil {
		return Entry{}, err
	}
	dir, err := KeyDir()
	if err != nil {
		return Entry{}, err
	}
	dst := filepath.Join(dir, name)
	if err := copyFile(abs, dst, 0o600); err != nil {
		return Entry{}, err
	}
	pubPath := ""
	fingerprint := ""
	if b, err := os.ReadFile(abs + ".pub"); err == nil {
		pubPath = dst + ".pub"
		_ = atomicWriteFile(pubPath, b, 0o644)
		fingerprint = FingerprintAuthorized(string(b))
	} else if pubText, err := publicFromPEMFile(abs, name); err == nil {
		pubPath = dst + ".pub"
		_ = atomicWriteFile(pubPath, []byte(pubText), 0o644)
		fingerprint = FingerprintAuthorized(pubText)
	}
	return Entry{Name: name, PrivatePath: dst, PublicPath: pubPath, Fingerprint: fingerprint, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Managed: true}, nil
}

func Reference(name, path string) (Entry, error) {
	name = sanitizeName(name)
	if name == "" {
		return Entry{}, errors.New("key name is required")
	}
	abs, err := userpath.Abs(path)
	if err != nil {
		return Entry{}, err
	}
	if _, err := os.Stat(abs); err != nil {
		return Entry{}, err
	}
	pub := ""
	fingerprint := ""
	if b, err := os.ReadFile(abs + ".pub"); err == nil {
		pub = abs + ".pub"
		fingerprint = FingerprintAuthorized(string(b))
	}
	return Entry{Name: name, PrivatePath: abs, PublicPath: pub, Fingerprint: fingerprint, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Managed: false}, nil
}

func List() ([]Entry, error) { return ListManaged() }

func ListManaged() ([]Entry, error) {
	dir, err := KeyDir()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") || strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		entry := Entry{Name: e.Name(), PrivatePath: p, Managed: true}
		if info, err := e.Info(); err == nil {
			entry.CreatedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		if b, err := os.ReadFile(p + ".pub"); err == nil {
			entry.PublicPath = p + ".pub"
			entry.Fingerprint = FingerprintAuthorized(string(b))
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func Public(nameOrPath string) (string, error) {
	p := nameOrPath
	if !strings.ContainsAny(nameOrPath, `/\`) {
		dir, err := KeyDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(dir, sanitizeName(nameOrPath)) + ".pub"
	} else if !strings.HasSuffix(p, ".pub") {
		p += ".pub"
	}
	abs, err := userpath.Abs(p)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func AuthorizedKey(pub ed25519.PublicKey, comment string) string {
	var buf bytes.Buffer
	writeString(&buf, []byte("ssh-ed25519"))
	writeString(&buf, pub)
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return strings.TrimSpace("ssh-ed25519 "+encoded+" "+strings.TrimSpace(comment)) + "\n"
}

func FingerprintAuthorized(auth string) string {
	fields := strings.Fields(auth)
	if len(fields) < 2 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ""
	}
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

func publicFromPEMFile(path, comment string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("not a PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("not an Ed25519 private key")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("could not derive Ed25519 public key")
	}
	return AuthorizedKey(pub, comment), nil
}

func writeString(w io.Writer, b []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(b)))
	_, _ = w.Write(b)
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(name)
	return name
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
