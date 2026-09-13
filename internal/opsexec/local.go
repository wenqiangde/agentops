package opsexec

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

const CommandProgramPattern = `^[^\x00-\x1F\x7F]+$`
const CommandArgumentPattern = `^[^\x00-\x1F\x7F]*$`

type LocalExecutor struct {
	factory CommandFactory
	limit   int
}

func NewLocalExecutor() *LocalExecutor {
	return NewLocalExecutorWithLimit(defaultCaptureLimit)
}

func NewLocalExecutorWithLimit(limit int) *LocalExecutor {
	if limit < 0 {
		limit = 0
	}
	return &LocalExecutor{factory: exec.CommandContext, limit: limit}
}

func (e *LocalExecutor) Run(ctx context.Context, request Request) Result {
	if request.Program == "" {
		return failure(fmt.Errorf("program must not be empty"), request.Redact)
	}
	if err := ValidateCommandArgv(request.Program, request.Args); err != nil {
		return failure(err, request.Redact)
	}
	if request.Directory != "" && (!filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory) {
		return failure(fmt.Errorf("working directory must be a clean absolute path"), request.Redact)
	}
	return execute(ctx, e.factory, request.Program, request.Args, request.Directory, request.Timeout, e.limit, request.Redact)
}

func (e *LocalExecutor) Copy(ctx context.Context, request CopyRequest) Result {
	if request.Direction != CopyToRemote && request.Direction != CopyFromRemote {
		return failure(fmt.Errorf("copy direction must be specified"), request.Redact)
	}
	if err := validateLocalCopyPath("source", request.Source); err != nil {
		return failure(err, request.Redact)
	}
	if err := validateLocalCopyPath("destination", request.Destination); err != nil {
		return failure(err, request.Redact)
	}
	return execute(ctx, e.factory, "cp", []string{"--", request.Source, request.Destination}, "", request.Timeout, e.limit, request.Redact)
}

func ValidateCommandArgv(program string, args []string) error {
	if program == "" {
		return fmt.Errorf("program must not be empty")
	}
	if err := rejectControlCharacters("program", program); err != nil {
		return err
	}
	for _, arg := range args {
		if err := rejectControlCharacters("argument", arg); err != nil {
			return err
		}
	}
	return nil
}

func validateLocalCopyPath(name, value string) error {
	if value == "" {
		return fmt.Errorf("local copy %s must not be empty", name)
	}
	if strings.HasPrefix(value, "-") || strings.Contains(value, ":") {
		return fmt.Errorf("local copy %s is ambiguous", name)
	}
	if err := rejectControlCharacters("local copy "+name, value); err != nil {
		return err
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return fmt.Errorf("local copy %s must be a clean absolute path", name)
	}
	return nil
}
