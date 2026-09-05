// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Crescendum

package transport

import "context"

type Operation string

const (
	OperationTest  Operation = "test"
	OperationPush  Operation = "push"
	OperationPull  Operation = "pull"
	OperationSync  Operation = "sync"
	OperationCheck Operation = "check"
)

type Command struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
	Output  string   `json:"output,omitempty"`
}

type Result struct {
	Operation  Operation `json:"operation"`
	OK         bool      `json:"ok"`
	DryRun     bool      `json:"dryRun"`
	Commands   []Command `json:"commands,omitempty"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  string    `json:"startedAt"`
	FinishedAt string    `json:"finishedAt"`
}

type Status struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type Options struct {
	DryRun bool
}

type Transport interface {
	Validate(ctx context.Context) error
	Status(ctx context.Context) (Status, error)
	Test(ctx context.Context) (Result, error)
	DryRunPush(ctx context.Context) (Result, error)
	Push(ctx context.Context, opts Options) (Result, error)
	Pull(ctx context.Context, opts Options) (Result, error)
	Check(ctx context.Context) (Result, error)
}
