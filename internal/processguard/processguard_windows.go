// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build windows

package processguard

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func listProcesses() ([]processInfo, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, fmt.Errorf("list processes with tasklist: %w", err)
	}
	return parseTasklistCSV(out)
}

func terminateProcess(pid int) error {
	return exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
}

func parseTasklistCSV(out []byte) ([]processInfo, error) {
	r := csv.NewReader(bytes.NewReader(out))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse tasklist output: %w", err)
	}
	var procs []processInfo
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid := atoiPID(strings.TrimSpace(row[1]))
		if pid <= 0 {
			continue
		}
		procs = append(procs, processInfo{PID: pid, Name: row[0]})
	}
	return procs, nil
}
