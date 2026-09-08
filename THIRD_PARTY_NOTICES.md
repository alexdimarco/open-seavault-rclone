# Third-party notices

This repository vendors selected source files from `golang.org/x/crypto` for Argon2id and BLAKE2b so the prototype remains buildable without downloading external modules.

## Go Authors BSD-style license

Copyright 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of Google LLC nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES, INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT, INCLUDING NEGLIGENCE OR OTHERWISE ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## rclone (optional managed runtime)

This project can download and run [rclone](https://rclone.org) as an external transport runtime. rclone is Copyright (C) the rclone Authors and is licensed under the MIT License. It is not modified by this project; it is executed as a separate program. Its source and license are at <https://github.com/rclone/rclone>.

MIT License (rclone):

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

## rsync (optional managed runtime)

This project can download and run [rsync](https://rsync.samba.org) as an external ingest runtime. rsync is Copyright (C) Wayne Davison and others and is licensed under the GNU General Public License, version 3 or later — the same license as this project (see [LICENSE](LICENSE)). It is not modified by this project; it is executed as a separate program. Its complete corresponding source is available from <https://rsync.samba.org> and <https://github.com/WayneD/rsync>.

## BIP-39 English wordlist (recovery phrases)

`internal/vault/recovery_words.go` vendors the canonical **BIP-39 English wordlist**
(2048 words) verbatim as the alphabet for word-based recovery phrases. The bytes are
byte-identical to `bip-0039/english.txt` in the Bitcoin BIPs repository
(<https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>); the same list
ships in the reference implementation at <https://github.com/trezor/python-mnemonic>.
Provenance is pinned in `recovery_words_test.go` by a SHA-256 of the reconstructed
list:

    2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda

plus a published BIP-39 golden test vector, so a silent re-vendor that would make
already-printed recovery cards unredeemable turns the test suite red.

BIP-39 ("Mnemonic code for generating deterministic keys", Marek Palatinus, Pavol
Rusnak, Aaron Voisine, Sean Bowe) is licensed under the 2-clause BSD license:

> Redistribution and use in source and binary forms, with or without modification,
> are permitted provided that the following conditions are met: (1) Redistributions
> of source code must retain the above copyright notice, this list of conditions and
> the following disclaimer. (2) Redistributions in binary form must reproduce the
> above copyright notice, this list of conditions and the following disclaimer in the
> documentation and/or other materials provided with the distribution. THIS SOFTWARE
> IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.

The wordlist is data, not modified, and is used only to encode/decode a recovery
secret this project already generates; no BIP-39 key-derivation (PBKDF2 seed) is used.
