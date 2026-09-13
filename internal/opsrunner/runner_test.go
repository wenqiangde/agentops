package opsrunner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type recordingExecutor struct {
	requests []opsexec.Request
	results  []opsexec.Result
}

func (e *recordingExecutor) Run(_ context.Context, r opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, r)
	if len(e.results) == 0 {
		return opsexec.Result{ExitCode: 0}
	}
	v := e.results[0]
	e.results = e.results[1:]
	return v
}
func (e *recordingExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: 0}
}

func TestRunnerInspectUsesDeclaredMachineReadableCommands(t *testing.T) {
	tests := []struct {
		name, kind  string
		env         opsconfig.Environment
		wantProgram string
		wantArgs    []string
		output      string
		wantState   string
	}{
		{"systemd", opsconfig.RunnerSystemd, opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"}, "systemctl", []string{"show", "demo.service", "--property=ActiveState,SubState,MainPID", "--no-pager"}, "ActiveState=active\nSubState=running\nMainPID=42\n", StateRunning},
		{"php-fpm", opsconfig.RunnerPHPFPM, opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.3-fpm.service"}, "systemctl", []string{"show", "php8.3-fpm.service", "--property=ActiveState,SubState,MainPID", "--no-pager"}, "ActiveState=active\nSubState=running\nMainPID=43\n", StateRunning},
		{"pm2", opsconfig.RunnerPM2, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared-app"}, "pm2", []string{"jlist"}, `[{"name":"declared-app","pid":44,"pm2_env":{"status":"online"}}]`, StateRunning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: tt.output}, {ExitCode: 0}}}
			check := New(tt.kind, ex).Inspect(context.Background(), opsconfig.Service{ID: "demo"}, tt.env)
			if check.State != tt.wantState || len(ex.requests) == 0 || ex.requests[0].Program != tt.wantProgram || !reflect.DeepEqual(ex.requests[0].Args, tt.wantArgs) {
				t.Fatalf("check=%+v requests=%+v", check, ex.requests)
			}
		})
	}
}

func TestRunnerContractsAndManualWrites(t *testing.T) {
	r := New(opsconfig.RunnerManual, &recordingExecutor{})
	env := opsconfig.Environment{Runner: opsconfig.RunnerManual}
	if got := r.Inspect(context.Background(), opsconfig.Service{ID: "demo"}, env); got.State != StateManual {
		t.Fatalf("inspect=%+v", got)
	}
	for name, got := range map[string]Check{
		"start": r.Start(context.Background(), opsconfig.Service{}, env), "stop": r.Stop(context.Background(), opsconfig.Service{}, env),
		"restart": r.Restart(context.Background(), opsconfig.Service{}, env), "logs": r.Logs(context.Background(), opsconfig.Service{}, env, time.Minute),
	} {
		if !errors.Is(got.Err, ErrUnsupportedWrite) {
			t.Fatalf("%s=%+v", name, got)
		}
	}
}

func TestRunnerRejectsMalformedSystemdAndProcessState(t *testing.T) {
	for _, output := range []string{"ActiveState=active\nSubState=running\n", "ActiveState=active\nMainPID=42\n", "SubState=running\nMainPID=42\n"} {
		ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: output}}}
		got := New(opsconfig.RunnerSystemd, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"})
		if got.State != StateUnknown || got.Err == nil {
			t.Fatalf("output=%q check=%+v", output, got)
		}
	}
}

func TestProcessInspectValidatesDeclaredExecutableUserAndPIDFile(t *testing.T) {
	env := opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Command: "/srv/api/bin/api", PIDFile: "/run/api.pid", ShutdownSignal: "SIGTERM", Logs: "/var/log/api.log"}
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 0}}}
	got := New(opsconfig.RunnerProcess, ex).Inspect(context.Background(), opsconfig.Service{ID: "api"}, env)
	want := []string{"--stop", "--test", "--quiet", "--pidfile", "/run/api.pid", "--exec", "/srv/api/bin/api", "--user", "deploy"}
	if got.Err != nil || got.State != StateRunning || len(ex.requests) != 2 || ex.requests[1].Program != "start-stop-daemon" || !reflect.DeepEqual(ex.requests[1].Args, want) {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestProcessInspectReportsNoMatchingDeclaredIdentityAsStopped(t *testing.T) {
	env := opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Command: "/srv/api/bin/api", PIDFile: "/run/api.pid", ShutdownSignal: "SIGTERM", Logs: "/var/log/api.log"}
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 1}}}
	got := New(opsconfig.RunnerProcess, ex).Inspect(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err != nil || got.State != StateStopped || len(ex.requests) != 2 {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestRunnerPM2MalformedNotFoundAndTimeoutAreUnknown(t *testing.T) {
	tests := []opsexec.Result{{ExitCode: 0, Stdout: "{"}, {ExitCode: 0, Stdout: `[{"name":"other","pid":1,"pm2_env":{"status":"online"}}]`}, {ExitCode: -1, TimedOut: true, Err: context.DeadlineExceeded}}
	for _, result := range tests {
		ex := &recordingExecutor{results: []opsexec.Result{result}}
		got := New(opsconfig.RunnerPM2, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared"})
		if got.State != StateUnknown || got.Err == nil {
			t.Fatalf("result=%+v check=%+v", result, got)
		}
	}
}

func TestRunnerPM2StoppedStateAllowsZeroPID(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: `[{"name":"declared","pid":0,"pm2_env":{"status":"stopped"}}]`}}}
	got := New(opsconfig.RunnerPM2, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared"})
	if got.State != StateStopped || got.Err != nil {
		t.Fatalf("check=%+v", got)
	}
}

func TestRunnerPM2UnknownStatusIsParseError(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: `[{"name":"declared","pid":0,"pm2_env":{"status":"mystery"}}]`}}}
	got := New(opsconfig.RunnerPM2, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared"})
	if got.State != StateUnknown || got.Err == nil {
		t.Fatalf("check=%+v", got)
	}
}

func TestRunnerPM2ClearsRawExecutorOutputOnEveryPath(t *testing.T) {
	secret := "DATABASE_PASSWORD=top-secret"
	tests := []struct{ name, output string }{{"online", `[{"name":"declared","pid":42,"pm2_env":{"status":"online","env_secret":"` + secret + `"}}]`}, {"stopped", `[{"name":"declared","pid":0,"pm2_env":{"status":"stopped","env_secret":"` + secret + `"}}]`}, {"not found", `[{"name":"other","pid":1,"pm2_env":{"status":"online","env_secret":"` + secret + `"}}]`}, {"parse error", `{"secret":"` + secret + `"`}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: tt.output, Stderr: secret}}}
			got := New(opsconfig.RunnerPM2, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared"})
			if got.Result.Stdout != "" || got.Result.Stderr != "" {
				t.Fatalf("result leaked output: %+v", got.Result)
			}
		})
	}
}

func TestRunnerLifecycleStatesReflectOperationSemantics(t *testing.T) {
	r := New(opsconfig.RunnerSystemd, &recordingExecutor{})
	env := opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"}
	if got := r.Start(context.Background(), opsconfig.Service{}, env); got.State != StateRunning {
		t.Fatalf("start=%+v", got)
	}
	if got := r.Restart(context.Background(), opsconfig.Service{}, env); got.State != StateRunning {
		t.Fatalf("restart=%+v", got)
	}
	if got := r.Stop(context.Background(), opsconfig.Service{}, env); got.State != StateStopped {
		t.Fatalf("stop=%+v", got)
	}
	if got := r.Logs(context.Background(), opsconfig.Service{}, env, time.Minute); got.State != StateUnknown {
		t.Fatalf("logs=%+v", got)
	}
}

func TestRunnerInspectStopsOnNonZeroExecutorExit(t *testing.T) {
	tests := []struct {
		name, kind, output string
		env                opsconfig.Environment
	}{{"systemd", opsconfig.RunnerSystemd, "ActiveState=active\nSubState=running\nMainPID=42\n", opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"}}, {"pm2", opsconfig.RunnerPM2, `[{"name":"demo","pid":42,"pm2_env":{"status":"online"}}]`, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "demo"}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 3, Stdout: tt.output}}}
			got := New(tt.kind, ex).Inspect(context.Background(), opsconfig.Service{}, tt.env)
			if got.State != StateUnknown || got.Err == nil || len(ex.requests) != 1 {
				t.Fatalf("check=%+v requests=%+v", got, ex.requests)
			}
		})
	}
}

func TestRunnerSystemdRejectsInvalidMainPID(t *testing.T) {
	for _, tt := range []struct{ active, pid string }{{"active", "0"}, {"active", "-1"}, {"active", "01"}, {"active", "abc"}, {"inactive", "-1"}, {"inactive", "01"}} {
		out := "ActiveState=" + tt.active + "\nSubState=running\nMainPID=" + tt.pid + "\n"
		ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: out}}}
		got := New(opsconfig.RunnerSystemd, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"})
		if got.State != StateUnknown || got.Err == nil {
			t.Fatalf("active=%q pid=%q check=%+v", tt.active, tt.pid, got)
		}
	}
}

func TestRunnerDetailsNeverEchoExecutorPayload(t *testing.T) {
	secret := "credential-payload"
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\n" + secret}}}
	got := New(opsconfig.RunnerSystemd, ex).Inspect(context.Background(), opsconfig.Service{}, opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "demo.service"})
	if strings.Contains(got.Detail, secret) {
		t.Fatalf("detail leaked payload: %q", got.Detail)
	}
}

func TestPHPFPMLifecycleUsesOnlyValidatedDeclaredService(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\nFragmentPath=/etc/systemd/system/php8.3-fpm.service\n"},
		{ExitCode: 0, Stdout: "regular file root\n"},
		{ExitCode: 0},
	}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.3-fpm.service", ConfigOwner: "root", ConfigPath: "/etc/systemd/system/php8.3-fpm.service"}
	got := New(opsconfig.RunnerPHPFPM, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err != nil || got.State != StateRunning || len(ex.requests) != 3 || ex.requests[2].Program != "systemctl" || !reflect.DeepEqual(ex.requests[2].Args, []string{"restart", "php8.3-fpm.service"}) {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestPM2LifecycleRequiresDeclaredAppInMachineReadableState(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "regular file deploy\n"},
		{ExitCode: 0, Stdout: `[{"name":"declared","pid":42,"pm2_env":{"status":"online","username":"deploy"}}]`},
		{ExitCode: 0},
	}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared", ConfigOwner: "deploy", ConfigPath: "/srv/api/ecosystem.config.js"}
	got := New(opsconfig.RunnerPM2, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err != nil || got.State != StateRunning || len(ex.requests) != 3 || ex.requests[2].Program != "pm2" || !reflect.DeepEqual(ex.requests[2].Args, []string{"restart", "declared"}) {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}

	missing := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 0, Stdout: `[{"name":"other","pid":1,"pm2_env":{"status":"online"}}]`}}}
	got = New(opsconfig.RunnerPM2, missing).Stop(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err == nil || len(missing.requests) != 2 {
		t.Fatalf("missing app check=%+v requests=%+v", got, missing.requests)
	}
}

func TestProcessStopValidatesPIDFileOwnershipAndUsesDeclaredSignal(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 0}}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Root: "/srv/api", Command: "./bin/api", PIDFile: "/run/api.pid", ShutdownSignal: "SIGTERM", Logs: "/var/log/api.log"}
	got := New(opsconfig.RunnerProcess, ex).Stop(context.Background(), opsconfig.Service{ID: "api"}, env)
	want := []string{"--stop", "--retry", "SIGTERM/5", "--remove-pidfile", "--pidfile", "/run/api.pid", "--exec", "/srv/api/bin/api", "--user", "deploy"}
	if got.Err != nil || got.State != StateStopped || len(ex.requests) != 2 || ex.requests[1].Program != "start-stop-daemon" || !reflect.DeepEqual(ex.requests[1].Args, want) {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}

	wrongOwner := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file root\n"}}}
	got = New(opsconfig.RunnerProcess, wrongOwner).Stop(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err == nil || len(wrongOwner.requests) != 1 {
		t.Fatalf("wrong owner check=%+v requests=%+v", got, wrongOwner.requests)
	}
}

func TestProcessStartUsesAbsoluteRemoteProgramAndVerifiesNewIdentity(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0}, {ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 0}}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Host: "prod", Root: "/srv/api", Command: "./bin/api", PIDFile: "/run/api.pid", ShutdownSignal: "SIGTERM", Logs: "/var/log/api.log"}
	got := New(opsconfig.RunnerProcess, ex).Start(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err != nil || got.State != StateRunning || len(ex.requests) != 3 || ex.requests[0].Program != "start-stop-daemon" || ex.requests[0].Directory != "" || !strings.Contains(strings.Join(ex.requests[0].Args, " "), "--startas /srv/api/bin/api") {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestPM2LifecycleRejectsWrongOwnerAndDuplicateName(t *testing.T) {
	env := opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared", ConfigOwner: "deploy", ConfigPath: "/srv/api/ecosystem.config.js"}
	for _, output := range []string{
		`[{"name":"declared","pid":42,"pm2_env":{"status":"online","username":"root"}}]`,
		`[{"name":"declared","pid":42,"pm2_env":{"status":"online","username":"deploy"}},{"name":"declared","pid":43,"pm2_env":{"status":"online","username":"deploy"}}]`,
	} {
		ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file deploy\n"}, {ExitCode: 0, Stdout: output}}}
		got := New(opsconfig.RunnerPM2, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
		if got.Err == nil || len(ex.requests) != 2 {
			t.Fatalf("output=%s check=%+v requests=%+v", output, got, ex.requests)
		}
	}
}

func TestPM2LifecycleRejectsConfigFileOwnerMismatch(t *testing.T) {
	env := opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "declared", ConfigOwner: "deploy", ConfigPath: "/srv/api/ecosystem.config.js"}
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "regular file root\n"}}}
	got := New(opsconfig.RunnerPM2, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err == nil || len(ex.requests) != 1 || ex.requests[0].Program != "stat" {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestPHPFPMLifecycleRejectsWrongConfigOwner(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=42\nFragmentPath=/etc/systemd/system/php8.3-fpm.service\n"},
		{ExitCode: 0, Stdout: "regular file someone-else\n"},
	}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.3-fpm.service", ConfigOwner: "root", ConfigPath: "/etc/systemd/system/php8.3-fpm.service"}
	got := New(opsconfig.RunnerPHPFPM, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err == nil || len(ex.requests) != 2 {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestPHPFPMLifecycleRejectsInvalidMainPID(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "ActiveState=active\nSubState=running\nMainPID=0\nFragmentPath=/etc/systemd/system/php8.3-fpm.service\n"}}}
	env := opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.3-fpm.service", ConfigOwner: "root", ConfigPath: "/etc/systemd/system/php8.3-fpm.service"}
	got := New(opsconfig.RunnerPHPFPM, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, env)
	if got.Err == nil || len(ex.requests) != 1 {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestDeploymentContractSystemdUsesExactCommands(t *testing.T) {
	contract, err := DeploymentContract(opsconfig.Service{ID: "api"}, opsconfig.Environment{Runner: opsconfig.RunnerSystemd, Unit: "api.service"})
	want := Contract{
		Activation:    []DeploymentCommand{{Kind: "activate-runner", Program: "systemctl", Args: []string{"restart", "api.service"}}},
		ProcessHealth: []DeploymentCommand{{Kind: "process-health-metadata", Program: "systemctl", Args: []string{"show", "api.service", "--property=ActiveState,SubState,MainPID", "--no-pager"}}},
	}
	if err != nil || !reflect.DeepEqual(contract, want) {
		t.Fatalf("contract=%+v err=%v", contract, err)
	}
}

func TestDeploymentContractPHPFPMBindsOwnershipReloadAndHealthCommands(t *testing.T) {
	env := opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.5-fpm.service", ConfigOwner: "root", ConfigPath: "/lib/systemd/system/php8.5-fpm.service"}
	contract, err := DeploymentContract(opsconfig.Service{ID: "resourcehub"}, env)
	metadata := DeploymentCommand{Kind: "verify-runner-metadata", Program: "systemctl", Args: []string{"show", "php8.5-fpm.service", "--property=ActiveState,SubState,MainPID,FragmentPath", "--no-pager"}}
	owner := DeploymentCommand{Kind: "verify-runner-config-owner", Program: "stat", Args: []string{"-c", "%F %U", "--", "/lib/systemd/system/php8.5-fpm.service"}}
	want := Contract{
		Activation:    []DeploymentCommand{metadata, owner, {Kind: "activate-runner", Program: "systemctl", Args: []string{"reload", "php8.5-fpm.service"}}},
		ProcessHealth: []DeploymentCommand{{Kind: "process-health-metadata", Program: metadata.Program, Args: metadata.Args}, {Kind: "process-health-config-owner", Program: owner.Program, Args: owner.Args}},
	}
	if err != nil || !reflect.DeepEqual(contract, want) {
		t.Fatalf("contract=%+v err=%v", contract, err)
	}
}

func TestDeploymentContractRejectsUnsupportedOrInvalidRunnerBeforeExecution(t *testing.T) {
	tests := []struct {
		name string
		env  opsconfig.Environment
	}{
		{"pm2", opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "api", ConfigOwner: "deploy", ConfigPath: "/srv/api/ecosystem.config.js"}},
		{"process", opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Command: "/srv/api/bin/api", PIDFile: "/run/api.pid", ShutdownSignal: "SIGTERM", Logs: "/var/log/api.log"}},
		{"manual", opsconfig.Environment{Runner: opsconfig.RunnerManual}},
		{"php-fpm missing path", opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php8.5-fpm.service", ConfigOwner: "root"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeploymentContract(opsconfig.Service{ID: "api"}, tt.env)
			if !errors.Is(err, ErrUnsupportedWrite) && tt.name != "php-fpm missing path" {
				t.Fatalf("err=%v", err)
			}
			if err == nil {
				t.Fatal("expected deployment contract error")
			}
		})
	}
}

func TestInvalidRunnerIdentitiesFailBeforeExecutorCall(t *testing.T) {
	for _, tt := range []struct {
		kind string
		env  opsconfig.Environment
	}{
		{opsconfig.RunnerPHPFPM, opsconfig.Environment{Runner: opsconfig.RunnerPHPFPM, Service: "php; reboot"}},
		{opsconfig.RunnerPM2, opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "app\nother"}},
		{opsconfig.RunnerProcess, opsconfig.Environment{Runner: opsconfig.RunnerProcess, User: "deploy", Command: "./bin/api --unsafe", PIDFile: "/tmp/api.pid", ShutdownSignal: "SIGKILL", Logs: "/tmp/api.log"}},
	} {
		ex := &recordingExecutor{}
		got := New(tt.kind, ex).Restart(context.Background(), opsconfig.Service{ID: "api"}, tt.env)
		if got.Err == nil || len(ex.requests) != 0 {
			t.Fatalf("kind=%s check=%+v requests=%+v", tt.kind, got, ex.requests)
		}
	}
}

func TestPM2LogsRejectOptionLikeAppBeforeExecutorCall(t *testing.T) {
	ex := &recordingExecutor{}
	env := opsconfig.Environment{Runner: opsconfig.RunnerPM2, App: "--lines"}
	got := New(opsconfig.RunnerPM2, ex).Logs(context.Background(), opsconfig.Service{ID: "api"}, env, time.Minute)
	if got.Err == nil || len(ex.requests) != 0 {
		t.Fatalf("check=%+v requests=%+v", got, ex.requests)
	}
}

func TestNginxNeverReloadsAfterFailedValidation(t *testing.T) {
	secret := "password=private"
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 1, Stdout: secret, Stderr: secret, Err: errors.New(secret)}}}
	steps, err := ReloadNginx(context.Background(), ex, "prod")
	if err == nil || strings.Contains(err.Error(), secret) || len(steps) != 1 || len(ex.requests) != 1 || ex.requests[0].Program != "nginx" {
		t.Fatalf("err=%v steps=%+v requests=%+v", err, steps, ex.requests)
	}
}

func TestNginxReloadsOnlyAfterSuccessfulValidationAndRecordsBothSteps(t *testing.T) {
	ex := &recordingExecutor{results: []opsexec.Result{{ExitCode: 0}, {ExitCode: 0}}}
	steps, err := ReloadNginx(context.Background(), ex, "prod")
	if err != nil || len(steps) != 2 || steps[0].State != "succeeded" || steps[1].State != "succeeded" || len(ex.requests) != 2 || ex.requests[0].Program != "nginx" || !reflect.DeepEqual(ex.requests[0].Args, []string{"-t"}) || ex.requests[1].Program != "systemctl" || !reflect.DeepEqual(ex.requests[1].Args, []string{"reload", "nginx"}) {
		t.Fatalf("err=%v steps=%+v requests=%+v", err, steps, ex.requests)
	}
}
