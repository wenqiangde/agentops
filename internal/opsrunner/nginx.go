package opsrunner

import (
	"context"
	"errors"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type OperationStep struct {
	Kind     string
	State    string
	ExitCode int
	TimedOut bool
}

func ReloadNginx(ctx context.Context, executor opsexec.Executor, host string) ([]OperationStep, error) {
	if ctx == nil || executor == nil || !runnerIdentity.MatchString(host) {
		return nil, errors.New("nginx reload inputs are invalid")
	}
	validation := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "nginx", Args: []string{"-t"}})
	steps := []OperationStep{{Kind: "validate-nginx", State: operationState(validation), ExitCode: validation.ExitCode, TimedOut: validation.TimedOut}}
	if validation.Err != nil || validation.ExitCode != 0 || validation.TimedOut {
		return steps, errors.New("nginx validation failed")
	}
	reload := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "systemctl", Args: []string{"reload", "nginx"}})
	steps = append(steps, OperationStep{Kind: "reload-nginx", State: operationState(reload), ExitCode: reload.ExitCode, TimedOut: reload.TimedOut})
	if reload.Err != nil || reload.ExitCode != 0 || reload.TimedOut {
		return steps, errors.New("nginx reload failed")
	}
	return steps, nil
}

func operationState(result opsexec.Result) string {
	if result.Err == nil && result.ExitCode == 0 && !result.TimedOut {
		return "succeeded"
	}
	return "failed"
}
