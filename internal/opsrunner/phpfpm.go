package opsrunner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/wenqiangde/agentops/internal/opsconfig"
)

func (r *commandRunner) inspectOwnedPHPFPM(ctx context.Context, env opsconfig.Environment) Check {
	check := r.run(ctx, env, "systemctl", "show", env.Service, "--property=ActiveState,SubState,MainPID,FragmentPath", "--no-pager")
	if check.Err != nil {
		return check
	}
	values := parseProperties(check.Result.Stdout)
	fragment := values["FragmentPath"]
	if fragment == "" || fragment != env.ConfigPath || values["ActiveState"] == "" || values["SubState"] == "" || values["MainPID"] == "" {
		return Check{State: StateUnknown, Err: fmt.Errorf("PHP-FPM unit metadata is incomplete")}
	}
	pid, err := strconv.ParseUint(values["MainPID"], 10, 64)
	if err != nil || strconv.FormatUint(pid, 10) != values["MainPID"] || (values["ActiveState"] == "active" && pid == 0) {
		return Check{State: StateUnknown, Err: fmt.Errorf("PHP-FPM unit metadata is invalid")}
	}
	metadata := r.run(ctx, env, "stat", "-c", "%F %U", "--", env.ConfigPath)
	if metadata.Err != nil || strings.TrimSpace(metadata.Result.Stdout) != "regular file "+env.ConfigOwner {
		metadata.State = StateUnknown
		metadata.Err = fmt.Errorf("PHP-FPM configuration ownership is invalid")
		return metadata
	}
	check.State = StateRunning
	if values["ActiveState"] != "active" {
		check.State = StateStopped
	}
	check.Result.Stdout = ""
	check.Result.Stderr = ""
	return check
}
