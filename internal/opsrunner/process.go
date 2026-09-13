package opsrunner

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/wenqiangde/agentops/internal/opsconfig"
)

func (r *commandRunner) inspectProcess(ctx context.Context, env opsconfig.Environment) Check {
	if metadata := r.inspectPIDFileOwner(ctx, env); metadata.Err != nil {
		return metadata
	}
	executable := processExecutable(env)
	checked := r.run(ctx, env, "start-stop-daemon", "--stop", "--test", "--quiet", "--pidfile", env.PIDFile, "--exec", executable, "--user", env.User)
	checked.Detail = "declared process identity checked"
	if checked.Result.Err == nil && checked.Result.ExitCode == 1 {
		checked.State = StateStopped
		checked.Err = nil
	}
	return checked
}

func (r *commandRunner) processLifecycle(ctx context.Context, env opsconfig.Environment, action string) Check {
	executable := processExecutable(env)
	if action == "start" {
		return r.startProcess(ctx, env, executable)
	}
	if metadata := r.inspectPIDFileOwner(ctx, env); metadata.Err != nil {
		return metadata
	}
	stopped := r.run(ctx, env, "start-stop-daemon", "--stop", "--retry", env.ShutdownSignal+"/5", "--remove-pidfile", "--pidfile", env.PIDFile, "--exec", executable, "--user", env.User)
	if stopped.Err != nil {
		return stopped
	}
	stopped.State = StateStopped
	if action == "stop" {
		return stopped
	}
	return r.startProcess(ctx, env, executable)
}

func processExecutable(env opsconfig.Environment) string {
	if path.IsAbs(env.Command) || env.Root == "" {
		return env.Command
	}
	return path.Join(env.Root, env.Command)
}

func (r *commandRunner) startProcess(ctx context.Context, env opsconfig.Environment, executable string) Check {
	args := []string{"--start", "--background", "--make-pidfile", "--pidfile", env.PIDFile, "--startas", executable, "--chuid", env.User}
	if env.Root != "" {
		args = append(args, "--chdir", env.Root)
	}
	started := r.run(ctx, env, "start-stop-daemon", args...)
	if started.Err != nil {
		return started
	}
	if metadata := r.inspectPIDFileOwner(ctx, env); metadata.Err != nil {
		return metadata
	}
	verified := r.run(ctx, env, "start-stop-daemon", "--stop", "--test", "--quiet", "--pidfile", env.PIDFile, "--exec", executable, "--user", env.User)
	if verified.Err != nil {
		verified.State = StateUnknown
		verified.Err = fmt.Errorf("started process identity could not be verified")
		return verified
	}
	started.State = StateRunning
	return started
}

func (r *commandRunner) inspectPIDFileOwner(ctx context.Context, env opsconfig.Environment) Check {
	metadata := r.run(ctx, env, "stat", "-c", "%F %U", "--", env.PIDFile)
	if metadata.Err != nil || strings.TrimSpace(metadata.Result.Stdout) != "regular file "+env.User {
		metadata.State = StateUnknown
		metadata.Err = fmt.Errorf("pidfile ownership is invalid")
	}
	return metadata
}
