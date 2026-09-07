// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package processguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TerminateExistingSeaVaultProcesses stops already-running open-seavault-rclone GUI/process
// instances before a new GUI instance starts. It never terminates the current
// process.
func TerminateExistingSeaVaultProcesses() error {
	selfPID := os.Getpid()
	selfExe := executableName()

	procs, err := listProcesses()
	if err != nil {
		return err
	}

	var failures []string
	for _, p := range procs {
		if p.PID <= 0 || p.PID == selfPID {
			continue
		}
		if !isSeaVaultProcess(p, selfExe) {
			continue
		}
		if err := terminateProcess(p.PID); err != nil {
			failures = append(failures, fmt.Sprintf("pid %d: %v", p.PID, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("failed to terminate existing open-seavault-rclone process(es): %s", strings.Join(failures, "; "))
	}
	return nil
}

type processInfo struct {
	PID  int
	Name string
	Args string
}

func executableName() string {
	exe, err := os.Executable()
	if err != nil {
		return "seavault"
	}
	name := filepath.Base(exe)
	return strings.ToLower(strings.TrimSuffix(name, ".exe"))
}

func isSeaVaultProcess(p processInfo, selfExe string) bool {
	name := normalizeProcessName(p.Name)
	if name == "seavault" || name == selfExe {
		return true
	}
	firstArg := firstCommandToken(p.Args)
	if firstArg == "" {
		return false
	}
	base := normalizeProcessName(firstArg)
	return base == "seavault" || base == selfExe
}

func normalizeProcessName(name string) string {
	name = strings.TrimSpace(strings.Trim(name, `"'`))
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.TrimSuffix(strings.ToLower(name), ".exe")
	return name
}

func firstCommandToken(args string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	if args[0] == '"' {
		if end := strings.Index(args[1:], "\""); end >= 0 {
			return args[1 : end+1]
		}
	}
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func atoiPID(s string) int {
	pid, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return pid
}
