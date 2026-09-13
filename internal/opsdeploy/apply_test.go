package opsdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type applyExecutor struct {
	calls         []string
	fail          string
	healthCode    string
	current       string
	healthRuns    int
	timeoutHealth bool
	mutateSource  bool
	remoteDigest  string
	releaseExists bool
	markerType    string
}

func (e *applyExecutor) Run(ctx context.Context, request opsexec.Request) opsexec.Result {
	call := request.Program + " " + strings.Join(request.Args, " ")
	e.calls = append(e.calls, call)
	if ctx.Err() != nil {
		return opsexec.Result{ExitCode: -1, TimedOut: true, Err: ctx.Err()}
	}
	if e.fail != "" && strings.HasPrefix(call, e.fail) {
		return opsexec.Result{ExitCode: 1, Err: errors.New("private executor detail")}
	}
	switch request.Program {
	case "sha256sum":
		digest := e.remoteDigest
		if digest == "" {
			digest = strings.Repeat("a", 64)
		}
		return opsexec.Result{ExitCode: 0, Stdout: digest + "  " + request.Args[len(request.Args)-1] + "\n"}
	case "test":
		target := request.Args[len(request.Args)-1]
		if strings.HasSuffix(target, "/current") || strings.HasSuffix(target, "/previous") {
			return opsexec.Result{ExitCode: 0}
		}
		if e.releaseExists {
			return opsexec.Result{ExitCode: 0}
		}
		return opsexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}
	case "readlink":
		version := e.current
		if version == "" {
			version = "1.0.0"
		}
		return opsexec.Result{ExitCode: 0, Stdout: "/opt/apps/demo/releases/" + version + "\n"}
	case "stat":
		if len(request.Args) > 1 && request.Args[1] == "%F %U" {
			return opsexec.Result{ExitCode: 0, Stdout: "regular file root\n"}
		}
		kind := e.markerType
		if kind == "" {
			kind = "regular file"
		}
		return opsexec.Result{ExitCode: 0, Stdout: kind}
	case "systemctl":
		if len(request.Args) > 0 && request.Args[0] == "show" {
			output := "ActiveState=active\nSubState=running\nMainPID=42\n"
			if strings.Contains(strings.Join(request.Args, ","), "FragmentPath") {
				output += "FragmentPath=/usr/lib/systemd/system/php8.5-fpm.service\n"
			}
			return opsexec.Result{ExitCode: 0, Stdout: output}
		}
	case "curl":
		e.healthRuns++
		if e.timeoutHealth && e.healthRuns == 1 {
			<-ctx.Done()
			return opsexec.Result{ExitCode: -1, TimedOut: true, Err: ctx.Err()}
		}
		code := e.healthCode
		if code == "503" && e.healthRuns > 1 {
			code = "200"
		}
		if code == "" {
			code = "200"
		}
		return opsexec.Result{ExitCode: 0, Stdout: code}
	case "find":
		return opsexec.Result{ExitCode: 0, Stdout: "300 1.1.0\n200 1.0.0\n100 0.9.0\n"}
	}
	return opsexec.Result{ExitCode: 0}
}

func TestApplyRejectsExistingReleaseWithNonRegularMarker(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{releaseExists: true, markerType: "symbolic link"}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil)
	if err == nil || result.Activated || !containsCall(executor.calls, "stat -c %F --") {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func TestApplyRejectsAlteredSignedCommandAndChangedCurrentBeforeWritingRelease(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	altered := plan
	altered.Steps = append([]Step(nil), plan.Steps...)
	altered.Steps[1].Args = []string{"-p", "/tmp/not-the-signed-target"}
	executor := &applyExecutor{}
	if _, err := Apply(context.Background(), executor, confirmedPlan(t, altered), artifact, time.Second, nil); err == nil || len(executor.calls) != 0 {
		t.Fatalf("altered command was executable: err=%v calls=%v", err, executor.calls)
	}

	executor = &applyExecutor{current: "0.9.0"}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil)
	if err == nil || result.Activated || containsCall(executor.calls, "ln -sfn") {
		t.Fatalf("changed current release was not rejected: result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func TestApplyUsesFreshBoundedContextForRecoveryAndReportAfterHealthTimeout(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{timeoutHealth: true}
	reportContextLive := false
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, 10*time.Millisecond, func(ctx context.Context, value ApplyResult) error {
		reportContextLive = ctx.Err() == nil
		return nil
	})
	if err == nil || !result.Recovered || !reportContextLive {
		t.Fatalf("result=%+v reportContextLive=%v err=%v", result, reportContextLive, err)
	}
}

func (e *applyExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	e.calls = append(e.calls, "copy "+request.Source+" "+request.Destination)
	data, err := os.ReadFile(request.Source)
	if err == nil {
		sum := sha256.Sum256(data)
		e.remoteDigest = hex.EncodeToString(sum[:])
	}
	if e.mutateSource {
		_ = os.WriteFile(request.Source, []byte("changed after copy"), 0o600)
	}
	if e.fail == "copy" {
		return opsexec.Result{ExitCode: 1, Err: errors.New("private copy detail")}
	}
	return opsexec.Result{ExitCode: 0}
}

func TestApplyRunsSystemdTransactionInOrderAndPrunesAfterReport(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{}
	reports := 0
	var terminalStates []bool
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, func(_ context.Context, result ApplyResult) error {
		reports++
		terminalStates = append(terminalStates, result.Terminal)
		if !result.Success || !result.Activated || result.Recovered {
			t.Fatalf("premature report: %+v", result)
		}
		return nil
	})
	if err != nil || !result.Success || reports != 2 || !reflect.DeepEqual(terminalStates, []bool{false, true}) {
		t.Fatalf("result=%+v reports=%d terminal=%v err=%v", result, reports, terminalStates, err)
	}
	wantPrefixes := []string{
		"mkdir -p /opt/apps/demo/.agentsetup/1.1.0",
		"copy " + artifact + " /opt/apps/demo/.agentsetup/1.1.0/artifact.tar.gz",
		"sha256sum -- /opt/apps/demo/.agentsetup/1.1.0/artifact.tar.gz",
		"test -e /opt/apps/demo/releases/1.1.0",
		"mkdir /opt/apps/demo/releases/1.1.0",
		"tar --extract --gzip --file /opt/apps/demo/.agentsetup/1.1.0/artifact.tar.gz --directory /opt/apps/demo/releases/1.1.0 --no-same-owner --no-same-permissions",
		"mv -T /opt/apps/demo/.agentsetup/1.1.0/artifact.tar.gz /opt/apps/demo/releases/1.1.0/.agentsetup-artifact.tar.gz",
		"chmod -R a-w /opt/apps/demo/releases/1.1.0",
		"test -e /opt/apps/demo/current",
		"readlink -f -- /opt/apps/demo/current",
		"ln -sfn releases/1.0.0 /opt/apps/demo/.previous.tmp",
		"ln -sfn releases/1.1.0 /opt/apps/demo/.current.tmp",
		"mv -Tf /opt/apps/demo/.previous.tmp /opt/apps/demo/previous",
		"mv -Tf /opt/apps/demo/.current.tmp /opt/apps/demo/current",
		"systemctl restart demo.service",
		"systemctl show demo.service",
		"curl ",
		"find /opt/apps/demo/releases -mindepth 1 -maxdepth 1 -type d -printf %T@ %f\\n",
	}
	if len(executor.calls) != len(wantPrefixes) {
		t.Fatalf("calls=%v", executor.calls)
	}
	for index, prefix := range wantPrefixes {
		if !strings.HasPrefix(executor.calls[index], prefix) {
			t.Fatalf("call[%d]=%q want prefix %q", index, executor.calls[index], prefix)
		}
	}
}

func TestApplyRunsPHPFPMContractInOrder(t *testing.T) {
	plan, artifact := preparedApply(t, phpFPMApplyPlan())
	executor := &applyExecutor{}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil)
	if err != nil || !result.Success || !result.Activated || result.Recovered {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
	want := []string{
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"curl ",
	}
	assertCallsInOrder(t, executor.calls, want)
}

func TestApplyPHPFPMRestoresPreviousAfterApplicationHealthFailure(t *testing.T) {
	plan, artifact := preparedApply(t, phpFPMApplyPlan())
	executor := &applyExecutor{healthCode: "503"}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil)
	if err == nil || result.Success || !result.Activated || !result.Recovered {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
	want := []string{
		"systemctl reload php8.5-fpm",
		"curl ",
		"ln -sfn releases/1.0.0 /opt/apps/demo/.current.recovery.tmp",
		"mv -Tf /opt/apps/demo/.current.recovery.tmp /opt/apps/demo/current",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"curl ",
	}
	assertCallsInOrder(t, executor.calls, want)
}

func TestApplyRejectsTamperedPHPFPMContractBeforeRemoteWrite(t *testing.T) {
	plan, artifact := preparedApply(t, phpFPMApplyPlan())
	for index := range plan.Steps {
		if plan.Steps[index].Kind == "activate-runner" {
			plan.Steps[index].Args = []string{"restart", "other.service"}
			break
		}
	}
	executor := &applyExecutor{}
	if _, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil); err == nil || len(executor.calls) != 0 {
		t.Fatalf("tampered PHP-FPM contract ran: err=%v calls=%v", err, executor.calls)
	}
}

func TestApplyRejectsArtifactChangedDuringCopy(t *testing.T) {
	artifact, err := os.CreateTemp(t.TempDir(), "artifact-*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := artifact.Close(); err != nil {
		t.Fatal(err)
	}
	plan := applyPlan()
	plan.ArtifactSHA256 = localDigest(t, artifact.Name())
	executor := &applyExecutor{mutateSource: true}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact.Name(), time.Second, nil)
	if err == nil || result.Activated || containsCall(executor.calls, "sha256sum") {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func TestApplyWritesUpdatedFailureReportWhenPruneFails(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{fail: "find "}
	var reports []ApplyResult
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, func(_ context.Context, value ApplyResult) error {
		reports = append(reports, value)
		return nil
	})
	if err == nil || result.Success || len(reports) != 2 || !reports[0].Success || reports[1].Success {
		t.Fatalf("result=%+v reports=%+v err=%v", result, reports, err)
	}
}

func TestApplyFailsClosedWhenFailureReportCannotBeWritten(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{fail: "copy"}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, func(context.Context, ApplyResult) error {
		return errors.New("private report detail")
	})
	if err == nil || result.Activated || !strings.Contains(err.Error(), "report") || strings.Contains(err.Error(), "private") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestApplyRecordsBoundedStepTimes(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	result, err := Apply(context.Background(), &applyExecutor{}, confirmedPlan(t, plan), artifact, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range result.Steps {
		if step.StartedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) {
			t.Fatalf("invalid step timing: %+v", step)
		}
	}
}

func TestApplyStopsBeforeActivationOnUploadOrDigestFailure(t *testing.T) {
	for _, fail := range []string{"copy", "sha256sum"} {
		t.Run(fail, func(t *testing.T) {
			plan, artifact := preparedApply(t, applyPlan())
			executor := &applyExecutor{fail: fail}
			result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, nil)
			if err == nil || result.Activated || result.Recovered || containsCall(executor.calls, "systemctl restart") || containsCall(executor.calls, "find ") {
				t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatalf("leaked executor detail: %v", err)
			}
		})
	}
}

func TestApplyRestoresPreviousAfterApplicationHealthFailure(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{healthCode: "503"}
	reported := ApplyResult{}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, func(_ context.Context, value ApplyResult) error {
		reported = value
		return nil
	})
	if err == nil || result.Success || !result.Activated || !result.Recovered || !reported.Recovered {
		t.Fatalf("result=%+v reported=%+v err=%v", result, reported, err)
	}
	want := []string{"ln -sfn releases/1.0.0 /opt/apps/demo/.current.recovery.tmp", "mv -Tf /opt/apps/demo/.current.recovery.tmp /opt/apps/demo/current", "systemctl restart demo.service"}
	for _, call := range want {
		if !containsCall(executor.calls, call) {
			t.Fatalf("missing recovery call %q in %v", call, executor.calls)
		}
	}
	if containsCall(executor.calls, "find ") {
		t.Fatalf("failure pruned releases: %v", executor.calls)
	}
}

func TestApplyReportsTerminalOutcomeWhenRecoveryFails(t *testing.T) {
	plan, artifact := preparedApply(t, applyPlan())
	executor := &applyExecutor{healthCode: "503", fail: "ln -sfn releases/1.0.0 /opt/apps/demo/.current.recovery.tmp"}
	reports := 0
	result, err := Apply(context.Background(), executor, confirmedPlan(t, plan), artifact, time.Second, func(context.Context, ApplyResult) error {
		reports++
		return nil
	})
	if err == nil || reports != 1 || !result.Activated || result.Recovered {
		t.Fatalf("result=%+v reports=%d err=%v", result, reports, err)
	}
}

func TestApplyRejectsBlockedAndStopsFirstDeploymentWithoutRecovery(t *testing.T) {
	blocked := applyPlan()
	blocked.Blocked = true
	blocked.BlockReason = "migration evidence missing"
	executor := &applyExecutor{}
	if _, err := Apply(context.Background(), executor, confirmedPlan(t, blocked), "/tmp/demo.tar.gz", time.Second, nil); err == nil || len(executor.calls) != 0 {
		t.Fatalf("blocked plan ran: err=%v calls=%v", err, executor.calls)
	}

	first := applyPlan()
	first.CurrentVersion = ""
	first.Recovery = Recovery{Ready: false, Reason: "first deployment"}
	first, artifact := preparedApply(t, first)
	executor = &applyExecutor{healthCode: "503"}
	result, err := Apply(context.Background(), executor, confirmedPlan(t, first), artifact, time.Second, nil)
	if err == nil || !result.Activated || result.Recovered || containsCall(executor.calls, ".current.recovery.tmp") || containsCall(executor.calls, "find ") {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, executor.calls)
	}
}

func applyPlan() Plan {
	plan := Plan{
		Service: "demo", Environment: opsconfig.EnvironmentProduction, Host: "prod", DeploymentRoot: "/opt/apps/demo",
		Version: "1.1.0", ArtifactSHA256: strings.Repeat("a", 64), ArtifactPlatform: "linux", ArtifactArchitecture: "amd64",
		CurrentVersion: "1.0.0", Policy: Policy{ReleaseRetain: 3},
		Health:    opsconfig.Health{Type: "http", URL: "http://127.0.0.1:8080/health", SuccessStatuses: []int{200}},
		Preflight: Preflight{Runner: RunnerEvidence{Kind: opsconfig.RunnerSystemd, Identity: "demo.service", State: "running", Identified: true}},
		Recovery:  Recovery{Ready: true, Reason: "compatible"},
	}
	return plan
}

func phpFPMApplyPlan() Plan {
	plan := applyPlan()
	plan.Preflight.Runner = RunnerEvidence{
		Kind:        opsconfig.RunnerPHPFPM,
		Identity:    "php8.5-fpm",
		ConfigOwner: "root",
		ConfigPath:  "/usr/lib/systemd/system/php8.5-fpm.service",
		State:       "running",
		Identified:  true,
	}
	return plan
}

func localDigest(t *testing.T, filename string) string {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func preparedApply(t *testing.T, plan Plan) (Plan, string) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "artifact.tar.gz")
	if err := os.WriteFile(filename, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan.ArtifactSHA256 = localDigest(t, filename)
	plan.Steps = applyStepContract(plan, filename)
	plan.Recovery.Steps = recoverySteps(opsconfig.Environment{
		Root:        plan.DeploymentRoot,
		Runner:      plan.Preflight.Runner.Kind,
		Unit:        plan.Preflight.Runner.Identity,
		Service:     plan.Preflight.Runner.Identity,
		ConfigOwner: plan.Preflight.Runner.ConfigOwner,
		ConfigPath:  plan.Preflight.Runner.ConfigPath,
	}, plan.CurrentVersion).Steps
	return plan, filename
}

func assertCallsInOrder(t *testing.T, calls, want []string) {
	t.Helper()
	position := 0
	for _, call := range calls {
		if position < len(want) && strings.HasPrefix(call, want[position]) {
			position++
		}
	}
	if position != len(want) {
		t.Fatalf("matched %d/%d calls; calls=%v want=%v", position, len(want), calls, want)
	}
}

func containsCall(calls []string, prefix string) bool {
	for _, call := range calls {
		if strings.Contains(call, prefix) {
			return true
		}
	}
	return false
}

func confirmedPlan(t *testing.T, plan Plan) ConfirmedPlan {
	t.Helper()
	digest, err := Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return ConfirmedPlan{Plan: plan, Digest: digest}
}

func TestApplyStepKindsRemainStructured(t *testing.T) {
	result := ApplyResult{Steps: []ApplyStepResult{{Kind: "upload", State: "succeeded"}}}
	if !reflect.DeepEqual(result.Steps, []ApplyStepResult{{Kind: "upload", State: "succeeded"}}) {
		t.Fatal(result)
	}
}
