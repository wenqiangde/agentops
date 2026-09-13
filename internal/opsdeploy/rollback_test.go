package opsdeploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type rollbackExecutor struct {
	calls         []string
	allowWrites   bool
	current       string
	targetDigest  string
	targetMissing bool
	healthCode    string
	healthRuns    int
	markerType    string
}

func (e *rollbackExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	call := request.Program + " " + strings.Join(request.Args, " ")
	e.calls = append(e.calls, call)
	if isRollbackWrite(request) && !e.allowWrites {
		return opsexec.Result{ExitCode: 9, Err: errors.New("write forbidden")}
	}
	switch request.Program {
	case "test":
		if e.targetMissing {
			return opsexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}
		}
		return opsexec.Result{ExitCode: 0}
	case "readlink":
		current := e.current
		if current == "" {
			current = "2.0.0"
		}
		return opsexec.Result{ExitCode: 0, Stdout: "/opt/apps/demo/releases/" + current + "\n"}
	case "sha256sum":
		digest := e.targetDigest
		if digest == "" {
			digest = strings.Repeat("a", 64)
		}
		return opsexec.Result{ExitCode: 0, Stdout: digest + "  " + request.Args[len(request.Args)-1] + "\n"}
	case "stat":
		if len(request.Args) > 0 && request.Args[0] == "-c" {
			if len(request.Args) > 1 && request.Args[1] == "%F %U" {
				return opsexec.Result{ExitCode: 0, Stdout: "regular file root\n"}
			}
			kind := e.markerType
			if kind == "" {
				kind = "regular file"
			}
			return opsexec.Result{ExitCode: 0, Stdout: kind}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "4096 1780000000 640\n"}
	case "uname":
		return opsexec.Result{ExitCode: 0, Stdout: "Linux x86_64\n"}
	case "which":
		return opsexec.Result{ExitCode: 0, Stdout: "/usr/bin/" + request.Args[0] + "\n"}
	case "id":
		return opsexec.Result{ExitCode: 0, Stdout: "deploy\n"}
	case "systemctl":
		if len(request.Args) > 0 && request.Args[0] == "show" {
			output := "ActiveState=active\nSubState=running\nMainPID=42\n"
			if strings.Contains(strings.Join(request.Args, " "), "FragmentPath") {
				output += "FragmentPath=/usr/lib/systemd/system/php8.5-fpm.service\n"
			}
			return opsexec.Result{ExitCode: 0, Stdout: output}
		}
		return opsexec.Result{ExitCode: 0}
	case "curl":
		e.healthRuns++
		code := e.healthCode
		if code == "" || (code == "503" && e.healthRuns > 1) {
			code = "200"
		}
		return opsexec.Result{ExitCode: 0, Stdout: code}
	default:
		return opsexec.Result{ExitCode: 0}
	}
}

func (e *rollbackExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: 9, Err: errors.New("rollback must not copy")}
}

func isRollbackWrite(request opsexec.Request) bool {
	switch request.Program {
	case "ln", "mv":
		return true
	case "systemctl":
		return len(request.Args) > 0 && (request.Args[0] == "restart" || request.Args[0] == "reload")
	default:
		return false
	}
}

func TestCreateRollbackPlanIsCanonicalReadOnlyAndSensitiveToRemoteState(t *testing.T) {
	executor := &rollbackExecutor{}
	plan, err := CreateRollback(context.Background(), executor, rollbackService(false), rollbackHost(), rollbackPolicies(), "1.5.0", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != "rollback" || plan.CurrentVersion != "2.0.0" || plan.TargetVersion != "1.5.0" || plan.TargetArtifactSHA256 != strings.Repeat("a", 64) || plan.Blocked {
		t.Fatalf("plan=%+v", plan)
	}
	if hasRollbackWrite(executor.calls) {
		t.Fatalf("preview wrote remotely: %v", executor.calls)
	}
	if !containsRollbackCall(executor.calls, "sha256sum -- /opt/apps/demo/shared/config/app.env") {
		t.Fatalf("configuration content fingerprint was not collected: %v", executor.calls)
	}
	digest, err := RollbackDigest(plan)
	if err != nil || !IsDigest(digest) {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	preview, err := MarshalRollbackIndented(plan)
	if err != nil || !strings.Contains(string(preview), `"operation": "rollback"`) || strings.Contains(string(preview), "token=") {
		t.Fatalf("preview=%q err=%v", preview, err)
	}

	changed := plan
	changed.ConfigFingerprints = map[string]string{"shared/config/app.env": strings.Repeat("b", 64)}
	changedDigest, err := RollbackDigest(changed)
	if err != nil || changedDigest == digest {
		t.Fatalf("changed digest=%q err=%v", changedDigest, err)
	}
	if err := ConfirmRollback(changed, digest); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale confirmation err=%v", err)
	}
}

func TestCreateRollbackRejectsNonRegularArtifactMarker(t *testing.T) {
	_, err := CreateRollback(context.Background(), &rollbackExecutor{markerType: "symbolic link"}, rollbackService(false), rollbackHost(), rollbackPolicies(), "1.5.0", time.Second)
	if err == nil {
		t.Fatal("symlink artifact marker was accepted")
	}
}

func TestApplyRollbackRechecksTargetMarkerBeforeWriting(t *testing.T) {
	plan := rollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true, targetDigest: strings.Repeat("b", 64)}
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, nil)
	if err == nil || result.Activated || hasRollbackWrite(executor.calls) {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func TestApplyRollbackRechecksTargetMarkerIsRegularBeforeWriting(t *testing.T) {
	plan := rollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true, markerType: "symbolic link"}
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, nil)
	if err == nil || result.Activated || hasRollbackWrite(executor.calls) {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func TestCreateRollbackRejectsMissingTargetAndBlocksMigration(t *testing.T) {
	missing := &rollbackExecutor{targetMissing: true}
	if _, err := CreateRollback(context.Background(), missing, rollbackService(false), rollbackHost(), rollbackPolicies(), "1.5.0", time.Second); err == nil {
		t.Fatal("missing target accepted")
	}

	blocked, err := CreateRollback(context.Background(), &rollbackExecutor{}, rollbackService(true), rollbackHost(), rollbackPolicies(), "1.5.0", time.Second)
	if err != nil || !blocked.Blocked || !strings.Contains(blocked.BlockReason, "migration") {
		t.Fatalf("plan=%+v err=%v", blocked, err)
	}
	if err := ConfirmRollback(blocked, strings.Repeat("a", 64)); err == nil {
		t.Fatal("migration rollback was confirmable")
	}
}

func TestRollbackPreviewShowsSafeTargetsAndRedactedHealthEndpoint(t *testing.T) {
	plan := rollbackPlanFixture()
	plan.Health.URL = "https://api.example.com/health?token=private#secret"
	preview, err := MarshalRollbackIndented(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(preview)
	for _, want := range []string{`"deployment_root": "/opt/apps/demo"`, `"target_release": "/opt/apps/demo/releases/1.5.0"`, `"url": "https://api.example.com/health"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("preview missing %s: %s", want, text)
		}
	}
	for _, secret := range []string{"token=private", "#secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("preview leaked %q: %s", secret, text)
		}
	}
}

func TestApplyRollbackSwitchesLinksRestartsVerifiesAndReports(t *testing.T) {
	plan := rollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true}
	reports := 0
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, func(_ context.Context, result RollbackResult) error {
		reports++
		if !result.Success || result.Recovered {
			t.Fatalf("report result=%+v", result)
		}
		return nil
	})
	if err != nil || !result.Success || !result.Activated || result.Recovered || reports != 1 {
		t.Fatalf("result=%+v reports=%d err=%v", result, reports, err)
	}
	assertRollbackOrder(t, executor.calls, []string{
		"ln -sfn releases/2.0.0 /opt/apps/demo/.previous.rollback.tmp",
		"ln -sfn releases/1.5.0 /opt/apps/demo/.current.rollback.tmp",
		"mv -Tf /opt/apps/demo/.previous.rollback.tmp /opt/apps/demo/previous",
		"mv -Tf /opt/apps/demo/.current.rollback.tmp /opt/apps/demo/current",
		"systemctl restart demo.service",
		"systemctl show demo.service",
		"curl ",
	})
}

func TestApplyRollbackRestoresOriginalCurrentWhenHealthFails(t *testing.T) {
	plan := rollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true, healthCode: "503"}
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, nil)
	if err == nil || result.Success || !result.Activated || !result.Recovered {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	assertRollbackOrder(t, executor.calls, []string{
		"ln -sfn releases/2.0.0 /opt/apps/demo/.current.rollback.recovery.tmp",
		"mv -Tf /opt/apps/demo/.current.rollback.recovery.tmp /opt/apps/demo/current",
		"systemctl restart demo.service",
		"systemctl show demo.service",
		"curl ",
	})
}

func TestCreateRollbackSupportsPHPFPMWithExactCommands(t *testing.T) {
	executor := &rollbackExecutor{}
	plan, err := CreateRollback(context.Background(), executor, phpFPMRollbackService(), phpFPMRollbackHost(), rollbackPolicies(), "1.5.0", time.Second)
	if err != nil || plan.Blocked {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if err := ConfirmRollback(plan, mustRollbackDigest(t, plan)); err != nil {
		t.Fatalf("confirm rollback: %v", err)
	}
	if plan.Runner.ConfigPath != "/usr/lib/systemd/system/php8.5-fpm.service" || plan.Runner.ConfigOwner != "root" {
		t.Fatalf("runner=%+v", plan.Runner)
	}
	assertRollbackSteps(t, plan.Steps, []string{
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
	})
	if hasRollbackWrite(executor.calls) {
		t.Fatalf("preview wrote remotely: %v", executor.calls)
	}
}

func TestApplyRollbackRunsPHPFPMContractInOrder(t *testing.T) {
	plan := phpFPMRollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true}
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, nil)
	if err != nil || !result.Success || !result.Activated || result.Recovered {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
	assertRollbackOrder(t, executor.calls, []string{
		"mv -Tf /opt/apps/demo/.current.rollback.tmp /opt/apps/demo/current",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"curl ",
	})
}

func TestApplyRollbackPHPFPMRestoresOriginalCurrentWhenHealthFails(t *testing.T) {
	plan := phpFPMRollbackPlanFixture()
	executor := &rollbackExecutor{allowWrites: true, healthCode: "503"}
	result, err := ApplyRollback(context.Background(), executor, confirmedRollback(t, plan), time.Second, nil)
	if err == nil || result.Success || !result.Activated || !result.Recovered {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
	assertRollbackOrder(t, executor.calls, []string{
		"mv -Tf /opt/apps/demo/.current.rollback.recovery.tmp /opt/apps/demo/current",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"curl ",
	})
}

func rollbackService(migration bool) opsconfig.Service {
	service := opsconfig.Service{ID: "demo", Environments: map[string]opsconfig.Environment{
		opsconfig.EnvironmentProduction: {
			Kind: opsconfig.EnvironmentKindSSH, Host: "prod", Root: "/opt/apps/demo", Runner: opsconfig.RunnerSystemd, Unit: "demo.service",
			Config: opsconfig.ConfigContract{Files: []string{"shared/config/app.env"}},
			Health: opsconfig.Health{Type: "http", URL: "http://127.0.0.1:8080/health", SuccessStatuses: []int{200}},
		},
	}}
	if migration {
		service.Data.MySQL = &opsconfig.MySQLData{MigrationCommand: "./migrate", BackupPolicy: "required"}
	}
	return service
}

func rollbackHost() opsconfig.Host {
	return opsconfig.Host{SSHAlias: "prod", Platform: "ubuntu", Architecture: "amd64", Capabilities: []string{"systemd"}}
}

func phpFPMRollbackService() opsconfig.Service {
	return opsconfig.Service{ID: "demo", Environments: map[string]opsconfig.Environment{
		opsconfig.EnvironmentProduction: {
			Kind: opsconfig.EnvironmentKindSSH, Host: "prod", Root: "/opt/apps/demo", Runner: opsconfig.RunnerPHPFPM,
			Service: "php8.5-fpm", ConfigOwner: "root", ConfigPath: "/usr/lib/systemd/system/php8.5-fpm.service",
			Config: opsconfig.ConfigContract{Files: []string{"shared/config/app.env"}},
			Health: opsconfig.Health{Type: "http", URL: "http://127.0.0.1:8080/health", SuccessStatuses: []int{200}},
		},
	}}
}

func phpFPMRollbackHost() opsconfig.Host {
	return opsconfig.Host{SSHAlias: "prod", Platform: "ubuntu", Architecture: "amd64", Capabilities: []string{"php-fpm"}}
}

func rollbackPolicies() opsconfig.Policies {
	return opsconfig.Policies{Execution: opsconfig.ExecutionPolicies{DefaultTimeout: "30s", HealthTimeout: "5s"}, Production: opsconfig.ProductionPolicies{RequirePreviewDigest: true}, Releases: opsconfig.ReleasePolicies{Retain: 3}}
}

func rollbackPlanFixture() RollbackPlan {
	plan := RollbackPlan{
		Operation: "rollback", Service: "demo", Environment: opsconfig.EnvironmentProduction, Host: "prod", DeploymentRoot: "/opt/apps/demo",
		CurrentVersion: "2.0.0", TargetVersion: "1.5.0", TargetArtifactSHA256: strings.Repeat("a", 64), RemoteUser: "deploy",
		ConfigFingerprints: map[string]string{"shared/config/app.env": strings.Repeat("a", 64)},
		Runner:             RunnerEvidence{Kind: opsconfig.RunnerSystemd, Identity: "demo.service", State: "running", Identified: true},
		Health:             opsconfig.Health{Type: "http", URL: "http://127.0.0.1:8080/health", SuccessStatuses: []int{200}},
		Policy:             Policy{DefaultTimeout: "30s", HealthTimeout: "5s", ReleaseRetain: 3, RequirePreviewDigest: true},
		Recovery:           Recovery{Ready: true, Reason: "original current release remains cached"},
	}
	plan.Steps = rollbackSteps(plan)
	plan.Recovery.Steps = rollbackRecoverySteps(plan)
	return plan
}

func phpFPMRollbackPlanFixture() RollbackPlan {
	plan := rollbackPlanFixture()
	plan.Runner = RunnerEvidence{Kind: opsconfig.RunnerPHPFPM, Identity: "php8.5-fpm", State: "running", Identified: true, ConfigOwner: "root", ConfigPath: "/usr/lib/systemd/system/php8.5-fpm.service"}
	plan.HostCapabilities = []string{"php-fpm"}
	plan.Steps = rollbackSteps(plan)
	plan.Recovery.Steps = rollbackRecoverySteps(plan)
	return plan
}

func mustRollbackDigest(t *testing.T, plan RollbackPlan) string {
	t.Helper()
	digest, err := RollbackDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func confirmedRollback(t *testing.T, plan RollbackPlan) ConfirmedRollbackPlan {
	t.Helper()
	digest, err := RollbackDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return ConfirmedRollbackPlan{Plan: plan, Digest: digest}
}

func hasRollbackWrite(calls []string) bool {
	for _, call := range calls {
		if strings.HasPrefix(call, "ln ") || strings.HasPrefix(call, "mv ") || strings.HasPrefix(call, "systemctl restart") || strings.HasPrefix(call, "systemctl reload") {
			return true
		}
	}
	return false
}

func assertRollbackSteps(t *testing.T, steps []Step, commands []string) {
	t.Helper()
	actual := make([]string, 0, len(steps))
	for _, step := range steps {
		actual = append(actual, step.Program+" "+strings.Join(step.Args, " "))
	}
	assertRollbackOrder(t, actual, commands)
}

func containsRollbackCall(calls []string, want string) bool {
	for _, call := range calls {
		if strings.Contains(call, want) {
			return true
		}
	}
	return false
}

func assertRollbackOrder(t *testing.T, calls, prefixes []string) {
	t.Helper()
	index := 0
	for _, call := range calls {
		if index < len(prefixes) && strings.HasPrefix(call, prefixes[index]) {
			index++
		}
	}
	if index != len(prefixes) {
		t.Fatalf("missing %q after calls %v", prefixes[index], calls)
	}
}
