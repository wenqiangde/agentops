package opsexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalRunCapturesExitCodeAndRedactsEveryResultField(t *testing.T) {
	secret := "top-secret"
	executor := NewLocalExecutor()
	result := executor.Run(context.Background(), Request{
		Program: testHelperProgram(t),
		Args:    testHelperArgs("output", secret),
		Timeout: time.Second,
		Redact:  []string{secret},
	})

	if result.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7 (result: %+v)", result.ExitCode, result)
	}
	assertResultDoesNotContain(t, result, secret)
	if !strings.Contains(result.Stdout, redactedValue) || !strings.Contains(result.Stderr, redactedValue) {
		t.Fatalf("expected redacted output, got stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestLocalRunTimesOutAndBoundsCapturedOutput(t *testing.T) {
	executor := NewLocalExecutorWithLimit(64)
	result := executor.Run(context.Background(), Request{
		Program: testHelperProgram(t),
		Args:    testHelperArgs("spam-and-sleep"),
		Timeout: 50 * time.Millisecond,
	})

	if !result.TimedOut {
		t.Fatalf("TimedOut = false, want true (result: %+v)", result)
	}
	if len(result.Stdout) != 64 || len(result.Stderr) != 64 {
		t.Fatalf("capture boundary mismatch: stdout=%d stderr=%d want=64", len(result.Stdout), len(result.Stderr))
	}
	if result.Duration <= 0 {
		t.Fatalf("Duration = %v, want positive", result.Duration)
	}
}

func TestLocalRunTimeoutKillsDescendantProcessGroup(t *testing.T) {
	started := time.Now()
	result := NewLocalExecutor().Run(context.Background(), Request{
		Program: os.Args[0],
		Args:    testHelperArgs("spawn-child"),
		Timeout: 150 * time.Millisecond,
	})
	if !result.TimedOut || time.Since(started) > 2*time.Second {
		t.Fatalf("timeout did not terminate promptly: elapsed=%v result=%+v", time.Since(started), result)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(result.Stdout))
	if err != nil {
		t.Fatalf("child PID output = %q: %v", result.Stdout, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processExists(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processExists(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("descendant process %d survived timeout", pid)
	}
}

func TestExecuteRejectsNilContextAndFactoryWithoutPanic(t *testing.T) {
	secret := "nil-secret"
	result := execute(nil, nil, secret, nil, "", 0, 16, []string{secret})
	if result.Err == nil || result.ExitCode != -1 {
		t.Fatalf("result = %+v, want structured validation error", result)
	}
	assertResultDoesNotContain(t, result, secret)

	result = NewSSHExecutorWithCommand(nil).Run(context.Background(), Request{HostAlias: "prod-a", Program: "true"})
	if result.Err == nil {
		t.Fatalf("nil constructor factory result = %+v, want error", result)
	}
}

func TestCapturedOutputRemovesANSIControlSequences(t *testing.T) {
	result := NewLocalExecutor().Run(context.Background(), Request{
		Program: os.Args[0],
		Args:    testHelperArgs("ansi-output"),
		Timeout: time.Second,
	})
	if strings.Contains(result.Stdout, "\x1b") || result.Stdout != "red\n" {
		t.Fatalf("stdout = %q, want sanitized text", result.Stdout)
	}
}

func TestSanitizationCannotReassembleAnUnredactedSecret(t *testing.T) {
	secret := "secret"
	result := redactResult(Result{Stdout: "sec\x1b[31mret"}, []string{secret})
	if result.Stdout != redactedValue {
		t.Fatalf("stdout = %q, want %q", result.Stdout, redactedValue)
	}
}

func TestRedactionSanitizesSecretsBeforeMatchingEveryResultField(t *testing.T) {
	secrets := []string{"sec\x1b[31mret", "to\x01ken"}
	result := redactResult(Result{
		Stdout: "stdout sec\x1b[31mret and to\x01ken",
		Stderr: "stderr to\x01ken and sec\x1b[31mret",
		Err:    errors.New("error sec\x1b[31mret and to\x01ken"),
	}, secrets)

	for _, leaked := range []string{"secret", "token"} {
		assertResultDoesNotContain(t, result, leaked)
	}
	if strings.Count(result.Stdout, redactedValue) != 2 ||
		strings.Count(result.Stderr, redactedValue) != 2 ||
		result.Err == nil || strings.Count(result.Err.Error(), redactedValue) != 2 {
		t.Fatalf("sanitized secrets were not redacted from every field: %+v", result)
	}
}

func TestNormalizedRedactionsIgnoresValuesEmptyAfterSanitization(t *testing.T) {
	values := normalizedRedactions([]string{"\x1b[31m", "\x01\x7f", "visible"})
	if !reflect.DeepEqual(values, []string{"visible"}) {
		t.Fatalf("normalized redactions = %#v, want only visible value", values)
	}
}

func TestLocalRunMissingExecutableReturnsRedactedError(t *testing.T) {
	secret := "missing-secret"
	result := NewLocalExecutor().Run(context.Background(), Request{
		Program: "definitely-not-an-executable-" + secret,
		Redact:  []string{secret},
	})

	if result.ExitCode != -1 || result.Err == nil {
		t.Fatalf("result = %+v, want start error and exit code -1", result)
	}
	assertResultDoesNotContain(t, result, secret)
}

func TestLocalRunUsesExplicitWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	result := NewLocalExecutor().Run(context.Background(), Request{
		Program:   testHelperProgram(t),
		Args:      testHelperArgs("working-directory"),
		Directory: dir,
		Timeout:   time.Second,
	})
	if result.Err != nil || result.ExitCode != 0 || !strings.HasPrefix(result.Stdout, dir+"\n") {
		t.Fatalf("result = %+v, want working directory %q", result, dir)
	}
}

func TestSSHRunBuildsBatchModeArgumentsAndQuotesRemoteArgv(t *testing.T) {
	var program string
	var args []string
	executor := NewSSHExecutorWithCommand(func(ctx context.Context, name string, argv ...string) *exec.Cmd {
		program = name
		args = append([]string(nil), argv...)
		return helperCommand(ctx, "success")
	})

	result := executor.Run(context.Background(), Request{
		HostAlias: "prod-a",
		Program:   "printf",
		Args:      []string{"hello world", "it's-safe", ""},
		Timeout:   time.Second,
	})

	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("result = %+v, want success", result)
	}
	if program != "ssh" {
		t.Fatalf("program = %q, want ssh", program)
	}
	want := []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "--", "prod-a", "'printf' 'hello world' 'it'\"'\"'s-safe' ''"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for _, arg := range args {
		if strings.Contains(arg, "StrictHostKeyChecking") {
			t.Fatalf("unsafe host-key option present in %#v", args)
		}
	}
}

func TestSSHRunRejectsControlCharactersWithoutStartingProcess(t *testing.T) {
	for _, request := range []Request{
		{HostAlias: "prod-a", Program: "bad\tprogram"},
		{HostAlias: "prod-a", Program: "printf", Args: []string{"bad\x7farg"}},
	} {
		called := false
		executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
			called = true
			return nil
		})
		result := executor.Run(context.Background(), request)
		if called || result.Err == nil {
			t.Fatalf("called=%v result=%+v, want input rejection", called, result)
		}
	}
}

func TestSSHRejectsUnsafeAliasWithoutStartingProcess(t *testing.T) {
	aliases := []string{"-prod", "prod;rm", "prod host", "prod\nother", "prod/other"}
	for _, alias := range aliases {
		t.Run(strings.ReplaceAll(alias, "\n", "newline"), func(t *testing.T) {
			called := false
			executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
				called = true
				return nil
			})
			result := executor.Run(context.Background(), Request{HostAlias: alias, Program: "true"})
			if called || result.Err == nil {
				t.Fatalf("called=%v result=%+v, want validation failure", called, result)
			}
		})
	}
}

func TestSSHCopyUsesSafeSCPArgumentsWithoutNetwork(t *testing.T) {
	var program string
	var args []string
	executor := NewSSHExecutorWithCommand(func(ctx context.Context, name string, argv ...string) *exec.Cmd {
		program = name
		args = append([]string(nil), argv...)
		return helperCommand(ctx, "success")
	})

	result := executor.Copy(context.Background(), CopyRequest{
		HostAlias:   "prod-a",
		Source:      "/tmp/release.tar.gz",
		Destination: "/opt/apps/demo/incoming/release.tar.gz",
		Direction:   CopyToRemote,
		Timeout:     time.Second,
	})

	if result.Err != nil || result.ExitCode != 0 {
		t.Fatalf("result = %+v, want success", result)
	}
	if program != "scp" {
		t.Fatalf("program = %q, want scp", program)
	}
	want := []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "/tmp/release.tar.gz", "prod-a:/opt/apps/demo/incoming/release.tar.gz"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
}

func TestSSHCopyRequiresExplicitDirection(t *testing.T) {
	called := false
	executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
		called = true
		return nil
	})
	result := executor.Copy(context.Background(), CopyRequest{
		HostAlias: "prod-a", Source: "/tmp/source", Destination: "/opt/apps/dest",
	})
	if called || result.Err == nil {
		t.Fatalf("called=%v result=%+v, want missing direction failure", called, result)
	}
}

func TestSSHCopyBuildsSafeArgumentsInBothDirections(t *testing.T) {
	tests := []struct {
		name    string
		request CopyRequest
		want    []string
	}{
		{"upload", CopyRequest{HostAlias: "prod-a", Source: "/tmp/source", Destination: "/opt/apps/demo/source", Direction: CopyToRemote}, []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "/tmp/source", "prod-a:/opt/apps/demo/source"}},
		{"download", CopyRequest{HostAlias: "prod-a", Source: "/opt/apps/demo/source", Destination: "/tmp/source", Direction: CopyFromRemote}, []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "prod-a:/opt/apps/demo/source", "/tmp/source"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got []string
			executor := NewSSHExecutorWithCommand(func(ctx context.Context, _ string, args ...string) *exec.Cmd {
				got = append([]string(nil), args...)
				return helperCommand(ctx, "success")
			})
			result := executor.Copy(context.Background(), test.request)
			if result.Err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("args=%#v want=%#v result=%+v", got, test.want, result)
			}
		})
	}
}

func TestSSHCopyRejectsUnsafeLocalAndRemotePaths(t *testing.T) {
	tests := []CopyRequest{
		{HostAlias: "prod-a", Source: "relative", Destination: "/opt/apps/dest", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/../source", Destination: "/opt/apps/dest", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/host:path", Destination: "/opt/apps/dest", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/source", Destination: "relative", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/source", Destination: "/opt/apps/host:path", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/source", Destination: "/opt/apps/has space", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/tmp/source", Destination: "/opt/apps/*.tgz", Direction: CopyToRemote},
		{HostAlias: "prod-a", Source: "/opt/apps/source", Destination: "/tmp/host:path", Direction: CopyFromRemote},
		{HostAlias: "prod-a", Source: "/opt/apps/source:evil", Destination: "/tmp/dest", Direction: CopyFromRemote},
		{HostAlias: "prod-a", Source: "/opt/apps/source", Destination: "/tmp/de\x7fst", Direction: CopyFromRemote},
	}
	for i, request := range tests {
		called := false
		executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
			called = true
			return nil
		})
		result := executor.Copy(context.Background(), request)
		if called || result.Err == nil {
			t.Fatalf("case %d called=%v result=%+v, want validation failure", i, called, result)
		}
	}
}

func TestSSHCommandConstructionDoesNotLeakSecretsInErrors(t *testing.T) {
	secret := "credential-value"
	executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
		return nil
	})
	result := executor.Run(context.Background(), Request{
		HostAlias: "prod-a",
		Program:   "printf",
		Args:      []string{secret},
		Redact:    []string{secret},
	})
	assertResultDoesNotContain(t, result, secret)
}

func TestHelperProcess(t *testing.T) {
	if len(testHelperMode()) == 0 {
		return
	}
	switch testHelperMode() {
	case "success":
		return
	case "output":
		secret := testHelperPayload()
		_, _ = fmt.Fprintln(os.Stdout, "stdout "+secret)
		_, _ = fmt.Fprintln(os.Stderr, "stderr "+secret)
		os.Exit(7)
	case "spam-and-sleep":
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("o", 4096))
		_, _ = fmt.Fprintln(os.Stderr, strings.Repeat("e", 4096))
		time.Sleep(5 * time.Second)
	case "spawn-child":
		child := exec.Command(os.Args[0], testHelperArgs("child-sleep")...)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, child.Process.Pid)
		_ = child.Wait()
	case "child-sleep":
		time.Sleep(5 * time.Second)
	case "ansi-output":
		_, _ = fmt.Fprint(os.Stdout, "\x1b[31mred\x1b[0m\n")
		os.Exit(0)
	case "working-directory":
		dir, err := os.Getwd()
		if err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, dir)
	}
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func testHelperProgram(t *testing.T) string {
	t.Helper()
	return os.Args[0]
}

func testHelperArgs(mode string, payload ...string) []string {
	args := []string{"-test.run=TestHelperProcess", "--", mode}
	return append(args, payload...)
}

func helperCommand(ctx context.Context, mode string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], testHelperArgs(mode)...)
}

func testHelperMode() string {
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func testHelperPayload() string {
	args := os.Args
	for i, arg := range args {
		if arg == "--" && i+2 < len(args) {
			return args[i+2]
		}
	}
	return ""
}

func assertResultDoesNotContain(t *testing.T, result Result, secret string) {
	t.Helper()
	combined := result.Stdout + result.Stderr
	if result.Err != nil {
		combined += result.Err.Error()
	}
	if strings.Contains(combined, secret) {
		t.Fatalf("result leaked secret %q: %+v", secret, result)
	}
}
