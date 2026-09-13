package opsexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (e *LocalExecutor) Pipeline(ctx context.Context, request PipelineRequest) Result {
	started := time.Now()
	fail := func(err error) Result {
		result := failure(err, request.Redact)
		result.Duration = time.Since(started)
		return result
	}
	if ctx == nil {
		return fail(errors.New("pipeline context must not be nil"))
	}
	if len(request.Stages) < 2 {
		return fail(errors.New("pipeline requires at least two stages"))
	}
	if request.Directory != "" && (!filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory) {
		return fail(errors.New("working directory must be a clean absolute path"))
	}
	for _, value := range []struct{ name, path string }{{"input", request.InputPath}, {"output", request.OutputPath}} {
		if value.path != "" {
			if err := validateLocalCopyPath(value.name, value.path); err != nil {
				return fail(err)
			}
		}
	}
	for _, stage := range request.Stages {
		if err := ValidateCommandArgv(stage.Program, stage.Args); err != nil {
			return fail(err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if request.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		runCtx, timeoutCancel = context.WithTimeout(runCtx, request.Timeout)
		defer timeoutCancel()
	}

	var input *os.File
	var output *os.File
	var err error
	if request.InputPath != "" {
		input, err = os.Open(request.InputPath)
		if err != nil {
			return fail(fmt.Errorf("open pipeline input: %w", err))
		}
		defer input.Close()
	}
	if request.OutputPath != "" {
		output, err = os.OpenFile(request.OutputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail(fmt.Errorf("create pipeline output: %w", err))
		}
		defer output.Close()
	}

	commands := make([]*exec.Cmd, len(request.Stages))
	stderr := make([]*boundedBuffer, len(request.Stages))
	pipes := make([][2]*os.File, len(request.Stages)-1)
	for index, stage := range request.Stages {
		cmd := e.factory(runCtx, stage.Program, stage.Args...)
		if cmd == nil {
			return fail(errors.New("command factory returned nil"))
		}
		cmd.Dir = request.Directory
		stderr[index] = &boundedBuffer{limit: e.limit}
		cmd.Stderr = stderr[index]
		commands[index] = cmd
		if index == 0 && input != nil {
			cmd.Stdin = input
		}
		if index > 0 {
			cmd.Stdin = pipes[index-1][0]
		}
		if index < len(request.Stages)-1 {
			reader, writer, pipeErr := os.Pipe()
			if pipeErr != nil {
				return fail(pipeErr)
			}
			pipes[index] = [2]*os.File{reader, writer}
			cmd.Stdout = writer
		} else if output != nil {
			cmd.Stdout = output
		}
	}
	cleanupOutput := true
	defer func() {
		for _, pair := range pipes {
			for _, file := range pair {
				if file != nil {
					_ = file.Close()
				}
			}
		}
		if cleanupOutput && request.OutputPath != "" {
			_ = os.Remove(request.OutputPath)
		}
	}()
	startedCommands := 0
	for _, cmd := range commands {
		if err := cmd.Start(); err != nil {
			cancel()
			for _, pair := range pipes {
				_ = pair[0].Close()
				_ = pair[1].Close()
			}
			for index := startedCommands - 1; index >= 0; index-- {
				_ = commands[index].Wait()
			}
			return fail(err)
		}
		startedCommands++
	}
	for _, pair := range pipes {
		_ = pair[0].Close()
		_ = pair[1].Close()
	}
	var waitErrors []error
	for index := len(commands) - 1; index >= 0; index-- {
		if err := commands[index].Wait(); err != nil {
			waitErrors = append(waitErrors, fmt.Errorf("pipeline stage %d failed: %w", index+1, err))
		}
	}
	combinedStderr := make([]string, 0, len(stderr))
	for _, buffer := range stderr {
		if value := buffer.String(); value != "" {
			combinedStderr = append(combinedStderr, value)
		}
	}
	result := Result{ExitCode: 0, Stderr: strings.Join(combinedStderr, "\n"), Duration: time.Since(started), TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded)}
	if len(waitErrors) != 0 || result.TimedOut {
		result.ExitCode = 1
		result.Err = errors.Join(waitErrors...)
		if result.Err == nil {
			result.Err = runCtx.Err()
		}
		return redactResult(result, request.Redact)
	}
	if output != nil {
		if err := output.Sync(); err != nil {
			return fail(err)
		}
	}
	cleanupOutput = false
	return redactResult(result, request.Redact)
}
