// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package vault

import (
	"bufio"
	"fmt"
	"io"
)

type ChunkParams struct {
	MinSize int `json:"minSize"`
	AvgSize int `json:"avgSize"`
	MaxSize int `json:"maxSize"`
}

func DefaultChunkParams() ChunkParams {
	return ChunkParams{
		MinSize: 2 * 1024 * 1024,
		AvgSize: 8 * 1024 * 1024,
		MaxSize: 16 * 1024 * 1024,
	}
}

func (p ChunkParams) Validate() error {
	if p.MinSize <= 0 || p.AvgSize <= 0 || p.MaxSize <= 0 {
		return fmt.Errorf("chunk sizes must be positive")
	}
	if p.MinSize > p.AvgSize || p.AvgSize > p.MaxSize {
		return fmt.Errorf("chunk sizes must satisfy min <= avg <= max")
	}
	if p.MaxSize > 128*1024*1024 {
		return fmt.Errorf("max chunk size is capped at 128 MiB")
	}
	return nil
}

func ForEachChunk(r io.Reader, params ChunkParams, fn func(chunk []byte) error) error {
	if err := params.Validate(); err != nil {
		return err
	}
	table := gearTable()
	mask := uint64(nextPowerOfTwo(params.AvgSize) - 1)
	br := bufio.NewReaderSize(r, 1024*1024)
	chunk := make([]byte, 0, params.MaxSize)
	var h uint64

	tmp := make([]byte, 256*1024)
	for {
		n, readErr := br.Read(tmp)
		if n > 0 {
			for _, b := range tmp[:n] {
				h = (h << 1) + table[b]
				chunk = append(chunk, b)
				if len(chunk) >= params.MinSize && ((h&mask) == 0 || len(chunk) >= params.MaxSize) {
					if err := fn(append([]byte(nil), chunk...)); err != nil {
						return err
					}
					chunk = chunk[:0]
					h = 0
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if len(chunk) > 0 {
		return fn(append([]byte(nil), chunk...))
	}
	return nil
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func gearTable() [256]uint64 {
	var table [256]uint64
	var x uint64 = 0x9e3779b97f4a7c15
	for i := range table {
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		table[i] = z ^ (z >> 31)
	}
	return table
}
