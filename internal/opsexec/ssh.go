package opsexec

import (
	"context"
	"fmt"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

var safeHostAlias = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var safeRemotePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

var nonInteractiveSSHOptions = []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes"}

type SSHExecutor struct {
	factory CommandFactory
	limit   int
}

func NewSSHExecutor() *SSHExecutor {
	return NewSSHExecutorWithCommand(exec.CommandContext)
}

func NewSSHExecutorWithCommand(factory CommandFactory) *SSHExecutor {
	return &SSHExecutor{factory: factory, limit: defaultCaptureLimit}
}

func (e *SSHExecutor) Run(ctx context.Context, request Request) Result {
	if request.Directory != "" {
		return failure(fmt.Errorf("remote working directory is not supported"), request.Redact)
	}
	if err := validateHostAlias(request.HostAlias); err != nil {
		return failure(err, request.Redact)
	}
	if request.Program == "" {
		return failure(fmt.Errorf("program must not be empty"), request.Redact)
	}
	if err := ValidateCommandArgv(request.Program, request.Args); err != nil {
		return failure(err, request.Redact)
	}
	remoteCommand, err := quotePOSIXArgv(append([]string{request.Program}, request.Args...))
	if err != nil {
		return failure(err, request.Redact)
	}
	args := append(append([]string{}, nonInteractiveSSHOptions...), "--", request.HostAlias, remoteCommand)
	return execute(ctx, e.factory, "ssh", args, "", request.Timeout, e.limit, request.Redact)
}

func (e *SSHExecutor) Pipeline(ctx context.Context, request PipelineRequest) Result {
	if request.Directory != "" || request.InputPath != "" {
		return failure(fmt.Errorf("remote pipeline input and working directory are not supported"), request.Redact)
	}
	if err := validateHostAlias(request.HostAlias); err != nil {
		return failure(err, request.Redact)
	}
	if len(request.Stages) < 2 {
		return failure(fmt.Errorf("pipeline requires at least two stages"), request.Redact)
	}
	if err := validateRemoteCopyPath("output", request.OutputPath); err != nil {
		return failure(err, request.Redact)
	}
	commands := make([]string, 0, len(request.Stages))
	for _, stage := range request.Stages {
		if err := ValidateCommandArgv(stage.Program, stage.Args); err != nil {
			return failure(err, request.Redact)
		}
		command, err := quotePOSIXArgv(append([]string{stage.Program}, stage.Args...))
		if err != nil {
			return failure(err, request.Redact)
		}
		commands = append(commands, command)
	}
	pipeline := "set -o noclobber; umask 077; " + strings.Join(commands, " | ") + " > " + quotePOSIX(request.OutputPath)
	remoteCommand, err := quotePOSIXArgv([]string{"bash", "-o", "pipefail", "-c", pipeline})
	if err != nil {
		return failure(err, request.Redact)
	}
	args := append(append([]string{}, nonInteractiveSSHOptions...), "--", request.HostAlias, remoteCommand)
	return execute(ctx, e.factory, "ssh", args, "", request.Timeout, e.limit, request.Redact)
}

func (e *SSHExecutor) Copy(ctx context.Context, request CopyRequest) Result {
	if err := validateHostAlias(request.HostAlias); err != nil {
		return failure(err, request.Redact)
	}
	var source, destination string
	switch request.Direction {
	case CopyToRemote:
		if err := validateLocalCopyPath("source", request.Source); err != nil {
			return failure(err, request.Redact)
		}
		if err := validateRemoteCopyPath("destination", request.Destination); err != nil {
			return failure(err, request.Redact)
		}
		source = request.Source
		destination = request.HostAlias + ":" + request.Destination
	case CopyFromRemote:
		if err := validateRemoteCopyPath("source", request.Source); err != nil {
			return failure(err, request.Redact)
		}
		if err := validateLocalCopyPath("destination", request.Destination); err != nil {
			return failure(err, request.Redact)
		}
		source = request.HostAlias + ":" + request.Source
		destination = request.Destination
	default:
		return failure(fmt.Errorf("unsupported copy direction %d", request.Direction), request.Redact)
	}

	// OpenSSH scp does not support a portable option terminator on every target
	// platform, so option-like paths are rejected before constructing argv.
	args := append(append([]string{}, nonInteractiveSSHOptions...), source, destination)
	return execute(ctx, e.factory, "scp", args, "", request.Timeout, e.limit, request.Redact)
}

func validateHostAlias(alias string) error {
	if !safeHostAlias.MatchString(alias) {
		return fmt.Errorf("invalid SSH host alias")
	}
	return nil
}

func validateRemoteCopyPath(name, value string) error {
	if value == "" || !safeRemotePath.MatchString(value) || path.Clean(value) != value {
		return fmt.Errorf("remote copy %s must be a clean absolute POSIX path using safe characters", name)
	}
	return nil
}

func quotePOSIXArgv(args []string) (string, error) {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = quotePOSIX(arg)
	}
	return strings.Join(quoted, " "), nil
}

func quotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
