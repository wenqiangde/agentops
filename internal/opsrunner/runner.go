package opsrunner

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

const (
	StateRunning = "running"
	StateStopped = "stopped"
	StateUnknown = "unknown"
	StateManual  = "manual"
)

var ErrUnsupportedWrite = errors.New("runner does not support automatic writes")
var runnerIdentity = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._@+-]{0,127}$`)
var configOwnerIdentity = regexp.MustCompile(opsconfig.ConfigOwnerPattern)
var processCommandIdentity = regexp.MustCompile(opsconfig.ProcessCommandPattern)

type Check struct {
	State  string
	Detail string
	Result opsexec.Result
	Err    error
}

type DeploymentCommand struct {
	Kind    string
	Program string
	Args    []string
}

type Contract struct {
	Activation    []DeploymentCommand
	ProcessHealth []DeploymentCommand
}

func DeploymentContract(service opsconfig.Service, env opsconfig.Environment) (Contract, error) {
	if env.Runner != opsconfig.RunnerSystemd && env.Runner != opsconfig.RunnerPHPFPM {
		return Contract{}, ErrUnsupportedWrite
	}
	if err := validateLifecycleContract(env.Runner, service, env); err != nil {
		return Contract{}, err
	}
	command := func(kind, program string, args ...string) DeploymentCommand {
		return DeploymentCommand{Kind: kind, Program: program, Args: append([]string(nil), args...)}
	}
	switch env.Runner {
	case opsconfig.RunnerSystemd:
		return Contract{
			Activation:    []DeploymentCommand{command("activate-runner", "systemctl", "restart", env.Unit)},
			ProcessHealth: []DeploymentCommand{command("process-health-metadata", "systemctl", "show", env.Unit, "--property=ActiveState,SubState,MainPID", "--no-pager")},
		}, nil
	case opsconfig.RunnerPHPFPM:
		metadataArgs := []string{"show", env.Service, "--property=ActiveState,SubState,MainPID,FragmentPath", "--no-pager"}
		ownerArgs := []string{"-c", "%F %U", "--", env.ConfigPath}
		return Contract{
			Activation: []DeploymentCommand{
				command("verify-runner-metadata", "systemctl", metadataArgs...),
				command("verify-runner-config-owner", "stat", ownerArgs...),
				command("activate-runner", "systemctl", "reload", env.Service),
			},
			ProcessHealth: []DeploymentCommand{
				command("process-health-metadata", "systemctl", metadataArgs...),
				command("process-health-config-owner", "stat", ownerArgs...),
			},
		}, nil
	}
	return Contract{}, ErrUnsupportedWrite
}

type Runner interface {
	Inspect(context.Context, opsconfig.Service, opsconfig.Environment) Check
	Start(context.Context, opsconfig.Service, opsconfig.Environment) Check
	Stop(context.Context, opsconfig.Service, opsconfig.Environment) Check
	Restart(context.Context, opsconfig.Service, opsconfig.Environment) Check
	Logs(context.Context, opsconfig.Service, opsconfig.Environment, time.Duration) Check
}

type commandRunner struct {
	executor opsexec.Executor
	kind     string
}

func New(kind string, executor opsexec.Executor) Runner {
	return &commandRunner{executor: executor, kind: kind}
}

func (r *commandRunner) run(ctx context.Context, env opsconfig.Environment, program string, args ...string) Check {
	if r.executor == nil {
		return Check{State: StateUnknown, Err: errors.New("executor is required")}
	}
	result := r.executor.Run(ctx, opsexec.Request{HostAlias: env.Host, Program: program, Args: args})
	check := Check{State: StateUnknown, Result: result, Err: result.Err}
	if result.Err == nil && result.ExitCode != 0 {
		check.Err = fmt.Errorf("%s exited with status %d", program, result.ExitCode)
		return check
	}
	if result.Err == nil && result.ExitCode == 0 {
		check.State = StateRunning
	}
	return check
}

func unsupported() Check { return Check{State: StateManual, Err: ErrUnsupportedWrite} }

func (r *commandRunner) Start(ctx context.Context, service opsconfig.Service, env opsconfig.Environment) Check {
	if r.kind == opsconfig.RunnerManual {
		return unsupported()
	}
	return r.lifecycle(ctx, service, env, "start", StateRunning)
}
func (r *commandRunner) Stop(ctx context.Context, service opsconfig.Service, env opsconfig.Environment) Check {
	if r.kind == opsconfig.RunnerManual {
		return unsupported()
	}
	return r.lifecycle(ctx, service, env, "stop", StateStopped)
}
func (r *commandRunner) Restart(ctx context.Context, service opsconfig.Service, env opsconfig.Environment) Check {
	if r.kind == opsconfig.RunnerManual {
		return unsupported()
	}
	return r.lifecycle(ctx, service, env, "restart", StateRunning)
}
func (r *commandRunner) Logs(ctx context.Context, _ opsconfig.Service, env opsconfig.Environment, since time.Duration) Check {
	if r.kind == opsconfig.RunnerManual {
		return unsupported()
	}
	if err := validateLogContract(r.kind, env, since); err != nil {
		return Check{State: StateUnknown, Err: err}
	}
	switch r.kind {
	case opsconfig.RunnerSystemd, opsconfig.RunnerPHPFPM:
		check := r.run(ctx, env, "journalctl", "--unit", declaredName(env), "--since", fmt.Sprintf("-%ds", int64(since.Seconds())), "--no-pager")
		check.State = StateUnknown
		return check
	case opsconfig.RunnerPM2:
		check := r.run(ctx, env, "pm2", "logs", env.App, "--nostream")
		check.State = StateUnknown
		return check
	case opsconfig.RunnerProcess:
		check := r.run(ctx, env, "tail", "--", env.Logs)
		check.State = StateUnknown
		return check
	default:
		return Check{State: StateUnknown, Err: fmt.Errorf("unsupported runner %q", r.kind)}
	}
}

func (r *commandRunner) lifecycle(ctx context.Context, service opsconfig.Service, env opsconfig.Environment, action, successState string) Check {
	if err := validateLifecycleContract(r.kind, service, env); err != nil {
		return Check{State: StateUnknown, Err: err}
	}
	var check Check
	switch r.kind {
	case opsconfig.RunnerSystemd:
		check = r.run(ctx, env, "systemctl", action, declaredName(env))
	case opsconfig.RunnerPHPFPM:
		if inspected := r.inspectOwnedPHPFPM(ctx, env); inspected.Err != nil {
			return inspected
		}
		check = r.run(ctx, env, "systemctl", action, env.Service)
	case opsconfig.RunnerPM2:
		if inspected := r.inspectOwnedPM2(ctx, env); inspected.Err != nil {
			return inspected
		}
		check = r.run(ctx, env, "pm2", action, env.App)
	case opsconfig.RunnerProcess:
		return r.processLifecycle(ctx, env, action)
	default:
		return Check{State: StateUnknown, Err: fmt.Errorf("unsupported runner %q", r.kind)}
	}
	if check.Err == nil && check.Result.ExitCode == 0 {
		check.State = successState
	}
	return check
}

func validateLifecycleContract(kind string, service opsconfig.Service, env opsconfig.Environment) error {
	if kind != opsconfig.RunnerSystemd && !runnerIdentity.MatchString(service.ID) {
		return errors.New("service ownership identity is invalid")
	}
	switch kind {
	case opsconfig.RunnerSystemd:
		if !runnerIdentity.MatchString(env.Unit) {
			return errors.New("systemd unit identity is invalid")
		}
	case opsconfig.RunnerPHPFPM:
		if !runnerIdentity.MatchString(env.Service) || !configOwnerIdentity.MatchString(env.ConfigOwner) || !path.IsAbs(env.ConfigPath) || path.Clean(env.ConfigPath) != env.ConfigPath || strings.ContainsAny(env.ConfigPath, "\r\n\x00") {
			return errors.New("PHP-FPM service identity is invalid")
		}
	case opsconfig.RunnerPM2:
		if !runnerIdentity.MatchString(env.App) || !configOwnerIdentity.MatchString(env.ConfigOwner) || !path.IsAbs(env.ConfigPath) || path.Clean(env.ConfigPath) != env.ConfigPath {
			return errors.New("PM2 app identity is invalid")
		}
	case opsconfig.RunnerProcess:
		if !configOwnerIdentity.MatchString(env.User) || !processCommandIdentity.MatchString(env.Command) {
			return errors.New("process command identity is invalid")
		}
		if env.Root == "" && !path.IsAbs(env.Command) {
			return errors.New("local process command must be absolute")
		}
		for _, value := range []string{env.PIDFile, env.Logs} {
			if !path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, "\r\n\x00") {
				return errors.New("process path identity is invalid")
			}
		}
		if !isGracefulSignal(env.ShutdownSignal) {
			return errors.New("process shutdown signal is invalid")
		}
	default:
		return fmt.Errorf("unsupported runner %q", kind)
	}
	return nil
}

func validateLogContract(kind string, env opsconfig.Environment, since time.Duration) error {
	if since <= 0 {
		return errors.New("log time range is invalid")
	}
	switch kind {
	case opsconfig.RunnerSystemd:
		if !runnerIdentity.MatchString(env.Unit) {
			return errors.New("systemd unit identity is invalid")
		}
	case opsconfig.RunnerPHPFPM:
		if !runnerIdentity.MatchString(env.Service) {
			return errors.New("PHP-FPM service identity is invalid")
		}
	case opsconfig.RunnerPM2:
		if !runnerIdentity.MatchString(env.App) {
			return errors.New("PM2 app identity is invalid")
		}
	case opsconfig.RunnerProcess:
		if !path.IsAbs(env.Logs) || path.Clean(env.Logs) != env.Logs {
			return errors.New("process log path is invalid")
		}
	}
	return nil
}

func isGracefulSignal(signal string) bool {
	switch signal {
	case "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT":
		return true
	default:
		return false
	}
}

func declaredName(env opsconfig.Environment) string {
	if env.Unit != "" {
		return env.Unit
	}
	return env.Service
}
