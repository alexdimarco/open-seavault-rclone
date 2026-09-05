// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !windows

package processguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func listProcesses() ([]processInfo, error) {
	out, err := exec.Command("ps", "-axo", "pid=,comm=,args=").Output()
	if err != nil {
		return nil, fmt.Errorf("list processes with ps: %w", err)
	}
	return parsePSOutput(out), nil
}

func terminateProcess(pid int) error {
	return exec.Command("kill", strconv.Itoa(pid)).Run()
}

func parsePSOutput(out []byte) []processInfo {
	var procs []processInfo
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		text := strings.TrimSpace(string(line))
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 {
			continue
		}
		pid := atoiPID(fields[0])
		if pid <= 0 {
			continue
		}
		name := fields[1]
		args := ""
		if len(fields) > 2 {
			args = strings.Join(fields[2:], " ")
		}
		procs = append(procs, processInfo{PID: pid, Name: name, Args: args})
	}
	return procs
}
