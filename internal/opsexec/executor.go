package opsexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	defaultCaptureLimit = 256 * 1024
	redactedValue       = "[redacted]"
)

type Executor interface {
	Run(context.Context, Request) Result
	Copy(context.Context, CopyRequest) Result
}

type PipelineExecutor interface {
	Pipeline(context.Context, PipelineRequest) Result
}

type PipelineStage struct {
	Program string
	Args    []string
}

type PipelineRequest struct {
	HostAlias  string
	Stages     []PipelineStage
	InputPath  string
	OutputPath string
	Directory  string
	Timeout    time.Duration
	Redact     []string
}

type Request struct {
	HostAlias string
	Program   string
	Args      []string
	Directory string
	Timeout   time.Duration
	Redact    []string
}

type CopyDirection uint8

const (
	CopyDirectionUnknown CopyDirection = iota
	CopyToRemote
	CopyFromRemote
)

type CopyRequest struct {
	HostAlias   string
	Source      string
	Destination string
	Direction   CopyDirection
	Timeout     time.Duration
	Redact      []string
}

type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
	Err      error
}

type CommandFactory func(context.Context, string, ...string) *exec.Cmd

var ansiSequence = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)?)`)

type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	originalLength := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return originalLength, nil
}

func (b *boundedBuffer) String() string { return b.buf.String() }

func execute(ctx context.Context, factory CommandFactory, program string, args []string, directory string, timeout time.Duration, limit int, redact []string) Result {
	started := time.Now()
	result := Result{ExitCode: -1}
	if ctx == nil {
		result.Err = errors.New("command context must not be nil")
		result.Duration = time.Since(started)
		return redactResult(result, redact)
	}
	if factory == nil {
		result.Err = errors.New("command factory must not be nil")
		result.Duration = time.Since(started)
		return redactResult(result, redact)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: limit}
	cmd := factory(ctx, program, args...)
	if cmd == nil {
		result.Err = errors.New("command factory returned nil")
		result.Duration = time.Since(started)
		return redactResult(result, redact)
	}
	cmd.Dir = directory
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()

	result.Duration = time.Since(started)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Err = err
	result.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	return redactResult(result, redact)
}

func failure(err error, redact []string) Result {
	return redactResult(Result{ExitCode: -1, Err: err}, redact)
}

func redactResult(result Result, values []string) Result {
	values = normalizedRedactions(values)
	result.Stdout = redactText(sanitizeOutput(result.Stdout), values)
	result.Stderr = redactText(sanitizeOutput(result.Stderr), values)
	if result.Err != nil {
		result.Err = errors.New(redactText(sanitizeOutput(result.Err.Error()), values))
	}
	return result
}

func rejectControlCharacters(name, value string) error {
	for _, r := range value {
		if r <= 0x1f || r == 0x7f {
			return fmt.Errorf("%s contains unsupported control characters", name)
		}
	}
	return nil
}

func sanitizeOutput(value string) string {
	value = ansiSequence.ReplaceAllString(value, "")
	return strings.Map(func(r rune) rune {
		if (r <= 0x1f && r != '\n' && r != '\r' && r != '\t') || r == 0x7f {
			return -1
		}
		return r
	}, value)
}

func normalizedRedactions(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = sanitizeOutput(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		clean = append(clean, value)
	}
	sort.Slice(clean, func(i, j int) bool { return len(clean[i]) > len(clean[j]) })
	return clean
}

func redactText(text string, values []string) string {
	for _, value := range values {
		text = strings.ReplaceAll(text, value, redactedValue)
	}
	return text
}
