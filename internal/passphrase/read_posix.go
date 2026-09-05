// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum
//go:build !windows

package passphrase

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func Read(prompt string) (string, error) {
	in, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	out := os.Stderr
	if err != nil {
		in = os.Stdin
	} else {
		defer in.Close()
		out = in
	}
	fmt.Fprint(out, prompt)
	noEcho := exec.Command("stty", "-echo")
	noEcho.Stdin = in
	_ = noEcho.Run()
	defer func() {
		echo := exec.Command("stty", "echo")
		echo.Stdin = in
		_ = echo.Run()
		fmt.Fprintln(out)
	}()
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return password, nil
}
