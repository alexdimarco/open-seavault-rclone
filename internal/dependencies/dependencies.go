// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package dependencies

import (
	"os/exec"
	"runtime"
	"strings"

	"github.com/alexdimarco/open-seavault-rclone/internal/keychain"
)

type Status struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Summary   string `json:"summary"`
	Detail    string `json:"detail,omitempty"`
}

type Report struct {
	Keychain keychain.Status `json:"keychain"`
	Items    []Status        `json:"items"`
}

func Check() Report {
	items := []Status{}
	kc := keychain.Check()
	items = append(items, Status{Name: "OS keychain", Available: kc.Available, Summary: kc.Summary, Detail: kc.Detail})
	if runtime.GOOS == "windows" {
		items = append(items, checkWSL())
	} else {
		items = append(items, checkCommand("rsync", "System rsync", "Optional; native Go import is used when rsync is absent."))
	}
	items = append(items, checkCommand("rclone", "System rclone", "Optional; open-seavault-rclone can use the managed rclone runtime."))
	return Report{Keychain: kc, Items: items}
}

func checkCommand(name, label, missingDetail string) Status {
	p, err := exec.LookPath(name)
	if err != nil {
		return Status{Name: label, Available: false, Summary: "unavailable", Detail: missingDetail}
	}
	return Status{Name: label, Available: true, Summary: "available", Detail: p}
}

func checkWSL() Status {
	p, err := exec.LookPath("wsl.exe")
	if err != nil {
		return Status{Name: "Windows Subsystem for Linux", Available: false, Summary: "unavailable", Detail: "wsl.exe was not found. Install WSL before using rsync-backed local ingest on Windows."}
	}
	out, err := exec.Command(p, "--status").CombinedOutput()
	if err != nil {
		return Status{Name: "Windows Subsystem for Linux", Available: true, Summary: "installed, status check failed", Detail: strings.TrimSpace(string(out))}
	}
	return Status{Name: "Windows Subsystem for Linux", Available: true, Summary: "available", Detail: strings.TrimSpace(string(out))}
}
