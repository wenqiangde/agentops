package opshealth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type Result struct {
	Healthy    bool
	Type       string
	Detail     string
	StatusCode int
	TimedOut   bool
	Err        error
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type tcpDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func Probe(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, health opsconfig.Health, timeout time.Duration) Result {
	if ctx == nil {
		return probeFailure(health.Type, errors.New("health context is required"), false)
	}
	if timeout <= 0 {
		return probeFailure(health.Type, errors.New("health timeout must be positive"), false)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch health.Type {
	case "http":
		return probeHTTP(ctx, executor, env, health, timeout, &http.Client{Timeout: timeout})
	case "tcp":
		return probeTCP(ctx, executor, env, health, timeout, &net.Dialer{Timeout: timeout})
	case "command":
		return probeCommand(ctx, executor, env, health, timeout)
	case "process":
		return probeProcess(ctx, executor, env, timeout)
	default:
		return probeFailure(health.Type, fmt.Errorf("unsupported health type %q", health.Type), false)
	}
}

func probeHTTP(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, health opsconfig.Health, timeout time.Duration, client httpDoer) Result {
	status := 0
	if env.Kind == opsconfig.EnvironmentKindSSH {
		if executor == nil {
			return probeFailure("http", errors.New("executor is required for remote health"), false)
		}
		if err := opsconfig.ValidateHealthHTTPURL(health.URL); err != nil {
			return probeFailure("http", err, false)
		}
		seconds := strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64)
		r := executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: "curl", Args: []string{"--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", seconds, "--", health.URL}, Timeout: timeout})
		if r.Err != nil || r.ExitCode != 0 {
			return fromExec("http", r)
		}
		var parseErr error
		status, parseErr = strconv.Atoi(strings.TrimSpace(r.Stdout))
		if parseErr != nil {
			return probeFailure("http", fmt.Errorf("parse HTTP status: %w", parseErr), false)
		}
	} else {
		if err := opsconfig.ValidateHealthHTTPURL(health.URL); err != nil {
			return probeFailure("http", err, false)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, health.URL, nil)
		if err != nil {
			return probeFailure("http", err, false)
		}
		response, err := client.Do(req)
		if err != nil {
			return probeFailure("http", err, errors.Is(ctx.Err(), context.DeadlineExceeded))
		}
		status = response.StatusCode
		_ = response.Body.Close()
	}
	healthy := containsStatus(health.SuccessStatuses, status)
	return Result{Healthy: healthy, Type: "http", StatusCode: status, Detail: fmt.Sprintf("status=%d", status)}
}

func probeTCP(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, health opsconfig.Health, timeout time.Duration, dialer tcpDialer) Result {
	host, port, targetErr := opsconfig.ParseHealthTCPAddress(health.Address)
	if targetErr != nil {
		return probeFailure("tcp", targetErr, false)
	}
	if env.Kind == opsconfig.EnvironmentKindSSH {
		if executor == nil {
			return probeFailure("tcp", errors.New("executor is required for remote health"), false)
		}
		seconds := strconv.FormatInt(int64(math.Ceil(timeout.Seconds())), 10)
		r := executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: "nc", Args: []string{"-z", "-w", seconds, host, port}, Timeout: timeout})
		return fromExec("tcp", r)
	}
	conn, err := dialer.DialContext(ctx, "tcp", health.Address)
	if err != nil {
		return probeFailure("tcp", err, errors.Is(ctx.Err(), context.DeadlineExceeded))
	}
	err = conn.Close()
	if err != nil {
		return probeFailure("tcp", err, false)
	}
	return Result{Healthy: true, Type: "tcp", Detail: "tcp probe succeeded"}
}

func probeCommand(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, health opsconfig.Health, timeout time.Duration) Result {
	if executor == nil {
		return probeFailure("command", errors.New("executor is required for command health"), false)
	}
	if health.Command == nil {
		return probeFailure("command", errors.New("command health requires explicit argv"), false)
	}
	r := executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: health.Command.Program, Args: append([]string(nil), health.Command.Args...), Timeout: timeout})
	result := Result{Healthy: r.Err == nil && r.ExitCode == 0, Type: "command", TimedOut: r.TimedOut, Err: r.Err}
	if result.Healthy {
		result.Detail = "command succeeded (exit=0)"
	} else {
		result.Detail = fmt.Sprintf("command failed (exit=%d)", r.ExitCode)
	}
	return result
}

func probeProcess(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, timeout time.Duration) Result {
	if executor == nil {
		return probeFailure("process", errors.New("executor is required for process health"), false)
	}
	read := executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: "cat", Args: []string{"--", env.PIDFile}, Timeout: timeout})
	if read.Err != nil || read.ExitCode != 0 {
		return fromExec("process", read)
	}
	pid := strings.TrimSpace(read.Stdout)
	value, err := strconv.ParseInt(pid, 10, 64)
	if err != nil || value <= 0 {
		return probeFailure("process", errors.New("invalid pidfile content"), false)
	}
	return fromExec("process", executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: "kill", Args: []string{"-0", pid}, Timeout: timeout}))
}

func fromExec(kind string, r opsexec.Result) Result {
	healthy := r.Err == nil && r.ExitCode == 0
	detail := fmt.Sprintf("%s probe failed (exit=%d)", kind, r.ExitCode)
	if healthy {
		detail = kind + " probe succeeded"
	}
	return Result{Healthy: healthy, Type: kind, Detail: detail, TimedOut: r.TimedOut, Err: r.Err}
}

func probeFailure(kind string, err error, timedOut bool) Result {
	return Result{Type: kind, Detail: kind + " probe failed", TimedOut: timedOut, Err: err}
}
func containsStatus(values []int, want int) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
