package opsrunner

import (
	"context"
	"fmt"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"strconv"
	"strings"
)

func (r *commandRunner) Inspect(ctx context.Context, service opsconfig.Service, env opsconfig.Environment) Check {
	switch r.kind {
	case opsconfig.RunnerSystemd, opsconfig.RunnerPHPFPM:
		check := r.run(ctx, env, "systemctl", "show", declaredName(env), "--property=ActiveState,SubState,MainPID", "--no-pager")
		if check.Err == nil {
			values := parseProperties(check.Result.Stdout)
			for _, field := range []string{"ActiveState", "SubState", "MainPID"} {
				if values[field] == "" {
					check.State = StateUnknown
					check.Err = fmt.Errorf("systemctl show missing %s", field)
					return check
				}
			}
			pid, err := strconv.ParseUint(values["MainPID"], 10, 64)
			if err != nil || strconv.FormatUint(pid, 10) != values["MainPID"] || (values["ActiveState"] == "active" && pid == 0) {
				check.State = StateUnknown
				check.Err = fmt.Errorf("systemctl show has invalid MainPID")
				return check
			}
			check.Detail = "systemd unit is " + values["ActiveState"]
			if values["ActiveState"] != "active" {
				check.State = StateStopped
			}
		}
		return check
	case opsconfig.RunnerPM2:
		return r.inspectPM2(ctx, env)
	case opsconfig.RunnerProcess:
		if err := validateLifecycleContract(r.kind, service, env); err != nil {
			return Check{State: StateUnknown, Err: err}
		}
		return r.inspectProcess(ctx, env)
	case opsconfig.RunnerManual:
		return Check{State: StateManual, Detail: "manual inspection required"}
	default:
		return Check{State: StateUnknown}
	}
}

func parseProperties(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[parts[0]] = parts[1]
		}
	}
	return values
}
