package opscli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

func TestCloudflareRollbackFailureReportPersistsTypedUnknownStateIdentity(t *testing.T) {
	root := t.TempDir()
	plan := opscloudflare.CloudflareRollbackPlan{
		Service: "example-relay", Environment: "production", Worker: "example-worker",
		DeploymentInputSHA256: strings.Repeat("b", 64), TargetVersionID: "11111111-1111-4111-8111-111111111111",
		CurrentDeploymentID: "33333333-3333-4333-8333-333333333333",
	}
	result := opscloudflare.RollbackResult{
		ProductionWriteSucceeded: true,
		DeploymentID:             "22222222-2222-4222-8222-222222222222",
		VersionID:                plan.TargetVersionID,
	}
	var output bytes.Buffer
	started := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	if err := writeCloudflareRollbackFailureReport(root, strings.Repeat("a", 64), plan, result, started, started.Add(time.Second), &output); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("reports=%v err=%v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(root, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var report opsreport.Report
	if json.Unmarshal(data, &report) != nil || report.Cloudflare == nil || report.Cloudflare.Outcome != opsreport.CloudflareUnknownState || report.Terminal || report.Cloudflare.PreviousDeploymentID != plan.CurrentDeploymentID || report.Cloudflare.DeploymentID != result.DeploymentID || len(report.Cloudflare.VersionIDs) != 1 || report.Cloudflare.VersionIDs[0] != result.VersionID {
		t.Fatalf("typed rollback unknown-state identity missing: %s", data)
	}
}

type cliRollbackExecutor struct {
	runs            []opsexec.Request
	copies          []opsexec.CopyRequest
	trace           []string
	allowWrites     bool
	targetMissing   bool
	badMarker       bool
	failApplyHealth bool
	restarts        int
}

func (e *cliRollbackExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.runs = append(e.runs, request)
	call := request.Program + " " + strings.Join(request.Args, " ")
	e.trace = append(e.trace, call)
	write := request.Program == "ln" || request.Program == "mv" || (request.Program == "systemctl" && len(request.Args) > 0 && (request.Args[0] == "restart" || request.Args[0] == "reload"))
	if write && !e.allowWrites {
		return opsexec.Result{ExitCode: 9, Err: errors.New("rollback preview attempted a write")}
	}
	switch request.Program {
	case "test":
		if len(request.Args) > 1 && strings.Contains(request.Args[1], "/releases/1.5.0/") && e.targetMissing {
			return opsexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}
		}
		return opsexec.Result{ExitCode: 0}
	case "readlink":
		return opsexec.Result{ExitCode: 0, Stdout: "/opt/apps/demo-api/releases/2.0.0\n"}
	case "sha256sum":
		requested := request.Args[len(request.Args)-1]
		outputPath := requested
		if e.badMarker && strings.Contains(requested, "/releases/1.5.0/") {
			outputPath = "/opt/apps/demo-api/releases/other/.agentsetup-artifact.tar.gz"
		}
		return opsexec.Result{ExitCode: 0, Stdout: strings.Repeat("a", 64) + "  " + outputPath + "\n"}
	case "stat":
		if e.targetMissing && len(request.Args) > 0 && strings.Contains(request.Args[len(request.Args)-1], "/releases/1.5.0/") {
			return opsexec.Result{ExitCode: 1, Err: errors.New("exit status 1")}
		}
		if len(request.Args) > 1 && request.Args[1] == "%F %U" {
			return opsexec.Result{ExitCode: 0, Stdout: "regular file root\n"}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "regular file\n"}
	case "id":
		return opsexec.Result{ExitCode: 0, Stdout: "deploy\n"}
	case "uname":
		return opsexec.Result{ExitCode: 0, Stdout: "Linux x86_64\n"}
	case "which":
		return opsexec.Result{ExitCode: 0, Stdout: "/usr/bin/" + request.Args[0] + "\n"}
	case "systemctl":
		if len(request.Args) > 0 && (request.Args[0] == "restart" || request.Args[0] == "reload") {
			e.restarts++
			return opsexec.Result{ExitCode: 0}
		}
		output := "ActiveState=active\nSubState=running\nMainPID=42\n"
		if strings.Contains(strings.Join(request.Args, " "), "FragmentPath") {
			output += "FragmentPath=/usr/lib/systemd/system/php8.5-fpm.service\n"
		}
		return opsexec.Result{ExitCode: 0, Stdout: output}
	case "curl":
		if e.failApplyHealth && e.restarts == 1 {
			return opsexec.Result{ExitCode: 0, Stdout: "503"}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "200"}
	case "find":
		return opsexec.Result{ExitCode: 0}
	case "ln", "mv":
		return opsexec.Result{ExitCode: 0}
	default:
		return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("unexpected rollback command")}
	}
}

func (e *cliRollbackExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	e.copies = append(e.copies, request)
	return opsexec.Result{ExitCode: 9, Err: errors.New("rollback must not copy")}
}

func TestOpsRollbackPreviewStaleAndConfirm(t *testing.T) {
	p := opsTestPaths(t, "valid")
	fake := &cliRollbackExecutor{}
	original := opsRollbackExecutor
	opsRollbackExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsRollbackExecutor = original })

	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0"}, &out, &errOut)
	if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), `"operation": "rollback"`) || !strings.Contains(out.String(), `"target_version": "1.5.0"`) {
		t.Fatalf("preview code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	digest := previewDigest(t, out.String())
	previewRuns := len(fake.runs)
	if previewRuns == 0 || len(fake.copies) != 0 || hasRollbackCLIWrite(fake.runs) {
		t.Fatalf("preview runs=%v copies=%v", fake.runs, fake.copies)
	}

	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0", "--confirm", "--preview-digest", strings.Repeat("0", 64)}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "stale") || len(fake.runs) != previewRuns*2 || hasRollbackCLIWrite(fake.runs) || len(fake.copies) != 0 {
		t.Fatalf("stale code=%d runs=%v copies=%v err=%q", code, fake.runs, fake.copies, errOut.String())
	}

	fake.allowWrites = true
	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0", "--confirm", "--preview-digest", digest}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "rollback: succeeded") || !strings.Contains(out.String(), "report-id: rollback-") || len(fake.copies) != 0 {
		t.Fatalf("confirm code=%d out=%q err=%q copies=%v", code, out.String(), errOut.String(), fake.copies)
	}
	assertTraceSubsequence(t, fake.trace, []string{
		"ln -sfn releases/2.0.0 /opt/apps/demo-api/.previous.rollback.tmp",
		"ln -sfn releases/1.5.0 /opt/apps/demo-api/.current.rollback.tmp",
		"mv -Tf /opt/apps/demo-api/.previous.rollback.tmp /opt/apps/demo-api/previous",
		"mv -Tf /opt/apps/demo-api/.current.rollback.tmp /opt/apps/demo-api/current",
		"systemctl restart demo-api.service",
		"systemctl show demo-api.service",
		"curl ",
	})
	reports, err := os.ReadDir(p.OpsReportRoot)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports=%v err=%v", reports, err)
	}
	data, err := os.ReadFile(filepath.Join(p.OpsReportRoot, reports[0].Name()))
	if err != nil || !strings.Contains(string(data), `"requested_version": "1.5.0"`) || !strings.Contains(string(data), `"previous_version": "2.0.0"`) {
		t.Fatalf("report=%q err=%v", data, err)
	}
}

func TestOpsRollbackRejectsCloudflareProductionWriteWhileSecurityGateIsClosed(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	target := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	args := []string{"ops", "rollback", "example-relay", "--environment", "production", "--version", target}

	previewExecutor := successfulCLICloudflareRollbackExecutor(target)
	original := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return previewExecutor }
	t.Cleanup(func() { opsCloudflareExecutor = original })
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}

	confirmedExecutor := successfulCLICloudflareRollbackExecutor(target)
	opsCloudflareExecutor = func() opsexec.Executor { return confirmedExecutor }
	var stdout, stderr bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirmArgs, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "rollback apply failed") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if hasCloudflareRollback(confirmedExecutor.requests) {
		t.Fatalf("security gate allowed production rollback: %+v", confirmedExecutor.requests)
	}
}

func successfulCLICloudflareRollbackExecutor(target string) *cliCloudflareExecutor {
	return &cliCloudflareExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.107.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: `[{"id":"` + target + `"}]`},
		{ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]}`},
	}}
}

func hasCloudflareRollback(requests []opsexec.Request) bool {
	for _, request := range requests {
		if len(request.Args) > 0 && request.Args[0] == "rollback" {
			return true
		}
	}
	return false
}

func TestOpsRollbackRejectsSnapshotDriftBeforeProductionCommand(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	target := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	args := []string{"ops", "rollback", "example-relay", "--environment", "production", "--version", target}
	previewExecutor := successfulCLICloudflareRollbackExecutor(target)
	stubCLICloudflareExecutor(t, previewExecutor)
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d err=%q", code, previewErr.String())
	}
	confirmedExecutor := successfulCLICloudflareRollbackExecutor(target)
	confirmedExecutor.afterRun = func(request opsexec.Request) {
		if len(request.Args) > 1 && request.Args[0] == "deployments" && request.Args[1] == "status" {
			writeCLIFile(t, filepath.Join(request.Directory, "src", "index.ts"), "snapshot changed\n", 0o644)
			confirmedExecutor.afterRun = nil
		}
	}
	stubCLICloudflareExecutor(t, confirmedExecutor)
	var stdout, stderr bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirmArgs, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "stale") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if hasCloudflareRollback(confirmedExecutor.requests) {
		t.Fatalf("changed snapshot executed rollback: %+v", confirmedExecutor.requests)
	}
}

func TestOpsRollbackHealthFailureRestoresOriginalAndReports(t *testing.T) {
	p := opsTestPaths(t, "valid")
	fake := &cliRollbackExecutor{failApplyHealth: true}
	original := opsRollbackExecutor
	opsRollbackExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsRollbackExecutor = original })
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0"}, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d err=%q", code, previewErr.String())
	}
	fake.allowWrites = true
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0", "--confirm", "--preview-digest", previewDigest(t, preview.String())}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "rollback: failed") || !strings.Contains(out.String(), "recovery: restored-original-release") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	assertTraceSubsequence(t, fake.trace, []string{
		"ln -sfn releases/2.0.0 /opt/apps/demo-api/.current.rollback.recovery.tmp",
		"mv -Tf /opt/apps/demo-api/.current.rollback.recovery.tmp /opt/apps/demo-api/current",
		"systemctl restart demo-api.service",
		"systemctl show demo-api.service",
		"curl ",
	})
	reports, err := os.ReadDir(p.OpsReportRoot)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports=%v err=%v", reports, err)
	}
}

func TestOpsRollbackPHPFPMPreviewStaleConfirmAndRecovery(t *testing.T) {
	p := opsTestPaths(t, "valid")
	setCLIServicePHPFPM(t, p)
	fake := &cliRollbackExecutor{failApplyHealth: true}
	original := opsRollbackExecutor
	opsRollbackExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsRollbackExecutor = original })
	args := []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0"}
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 || previewErr.Len() != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}
	for _, want := range []string{`"kind": "php-fpm"`, `"config_owner": "root"`, `"kind": "activate-runner"`, `"kind": "activate-original-runner"`} {
		if !strings.Contains(preview.String(), want) {
			t.Fatalf("preview missing %s: %s", want, preview.String())
		}
	}
	digest := previewDigest(t, preview.String())
	previewRuns := len(fake.runs)
	var staleOut, staleErr bytes.Buffer
	staleArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", strings.Repeat("0", 64))
	if code, _ := executeRootCommand(p, staleArgs, &staleOut, &staleErr); code != 1 || !strings.Contains(staleErr.String(), "stale") || len(fake.runs) != previewRuns*2 || hasRollbackCLIWrite(fake.runs) {
		t.Fatalf("stale code=%d runs=%v out=%q err=%q", code, fake.runs, staleOut.String(), staleErr.String())
	}
	fake.allowWrites = true
	var out, errOut bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", digest)
	if code, _ := executeRootCommand(p, confirmArgs, &out, &errOut); code != 1 || !strings.Contains(out.String(), "recovery: restored-original-release") {
		t.Fatalf("confirm code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	assertTraceSubsequence(t, fake.trace, []string{
		"mv -Tf /opt/apps/demo-api/.current.rollback.recovery.tmp /opt/apps/demo-api/current",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
	})
}

func TestOpsRollbackRejectsInvalidArgumentsAndRemoteTarget(t *testing.T) {
	p := opsTestPaths(t, "valid")
	for _, args := range [][]string{
		{"ops", "rollback", "demo-api", "--environment", "production"},
		{"ops", "rollback", "demo-api", "--environment", "local", "--version", "1.5.0"},
		{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0", "--confirm"},
		{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0", "--preview-digest", strings.Repeat("a", 64)},
	} {
		var out, errOut bytes.Buffer
		if code, _ := executeRootCommand(p, args, &out, &errOut); code != 1 {
			t.Fatalf("args=%v code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
	for _, tt := range []struct {
		name string
		fake *cliRollbackExecutor
	}{
		{name: "missing target", fake: &cliRollbackExecutor{targetMissing: true}},
		{name: "invalid marker", fake: &cliRollbackExecutor{badMarker: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := opsRollbackExecutor
			opsRollbackExecutor = func() opsexec.Executor { return tt.fake }
			t.Cleanup(func() { opsRollbackExecutor = original })
			var out, errOut bytes.Buffer
			code, _ := executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0"}, &out, &errOut)
			if code != 1 || !strings.Contains(errOut.String(), "preview collection failed") || hasRollbackCLIWrite(tt.fake.runs) || len(tt.fake.copies) != 0 {
				t.Fatalf("code=%d runs=%v copies=%v out=%q err=%q", code, tt.fake.runs, tt.fake.copies, out.String(), errOut.String())
			}
		})
	}
}

func previewDigest(t *testing.T, output string) string {
	t.Helper()
	marker := "preview-digest: "
	index := strings.LastIndex(output, marker)
	if index < 0 {
		t.Fatalf("preview digest missing: %q", output)
	}
	return strings.TrimSpace(output[index+len(marker):])
}

func hasRollbackCLIWrite(requests []opsexec.Request) bool {
	for _, request := range requests {
		if request.Program == "ln" || request.Program == "mv" || (request.Program == "systemctl" && len(request.Args) > 0 && (request.Args[0] == "restart" || request.Args[0] == "reload")) {
			return true
		}
	}
	return false
}
