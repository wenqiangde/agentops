package opsrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wenqiangde/agentops/internal/opsconfig"
)

type pm2Row struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	Env  struct {
		Status   string `json:"status"`
		Username string `json:"username"`
	} `json:"pm2_env"`
}

func (r *commandRunner) inspectPM2(ctx context.Context, env opsconfig.Environment) (check Check) {
	check = r.run(ctx, env, "pm2", "jlist")
	defer func() { check.Result.Stdout = ""; check.Result.Stderr = "" }()
	if check.Err != nil {
		return check
	}
	var rows []pm2Row
	if err := json.Unmarshal([]byte(check.Result.Stdout), &rows); err != nil {
		check.State = StateUnknown
		check.Err = err
		return check
	}
	matches := matchingPM2Rows(rows, env.App)
	if len(matches) != 1 {
		check.State = StateUnknown
		check.Err = fmt.Errorf("declared PM2 app must match exactly one process")
		return check
	}
	return r.pm2State(matches[0], check)
}

func (r *commandRunner) inspectOwnedPM2(ctx context.Context, env opsconfig.Environment) (check Check) {
	metadata := r.run(ctx, env, "stat", "-c", "%F %U", "--", env.ConfigPath)
	if metadata.Err != nil || strings.TrimSpace(metadata.Result.Stdout) != "regular file "+env.ConfigOwner {
		metadata.State = StateUnknown
		metadata.Err = fmt.Errorf("PM2 configuration ownership is invalid")
		return metadata
	}
	check = r.run(ctx, env, "pm2", "jlist")
	defer func() { check.Result.Stdout = ""; check.Result.Stderr = "" }()
	if check.Err != nil {
		return check
	}
	var rows []pm2Row
	if err := json.Unmarshal([]byte(check.Result.Stdout), &rows); err != nil {
		check.State = StateUnknown
		check.Err = fmt.Errorf("PM2 state is invalid")
		return check
	}
	matches := matchingPM2Rows(rows, env.App)
	if len(matches) != 1 || strings.TrimSpace(matches[0].Env.Username) != env.ConfigOwner {
		check.State = StateUnknown
		check.Err = fmt.Errorf("PM2 configuration ownership is invalid")
		return check
	}
	return r.pm2State(matches[0], check)
}

func matchingPM2Rows(rows []pm2Row, app string) []pm2Row {
	var matches []pm2Row
	for _, row := range rows {
		if row.Name == app {
			matches = append(matches, row)
		}
	}
	return matches
}

func (r *commandRunner) pm2State(row pm2Row, check Check) Check {
	switch row.Env.Status {
	case "online":
		if row.PID <= 0 {
			check.State = StateUnknown
			check.Err = fmt.Errorf("online PM2 app must have a positive pid")
			return check
		}
		check.State = StateRunning
		check.Detail = "PM2 app is online"
	case "stopped", "errored", "stopping", "launching", "one-launch-status":
		if row.PID < 0 {
			check.State = StateUnknown
			check.Err = fmt.Errorf("declared PM2 app has invalid pid")
			return check
		}
		check.State = StateStopped
		check.Detail = "PM2 app is not running"
	default:
		check.State = StateUnknown
		check.Err = fmt.Errorf("declared PM2 app has unknown status")
	}
	return check
}
