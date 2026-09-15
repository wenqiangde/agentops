package opscli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

func TestOpsDeployRoutesCloudflareWorkerToReadOnlyPreview(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	fake := &cliCloudflareExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: "private dry-run output"},
	}}
	original := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = original })

	var stdout, stderr bytes.Buffer
	code, handled := executeRootCommand(p, []string{
		"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.14-1",
	}, &stdout, &stderr)
	if !handled || code != 0 || stderr.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, stdout.String(), stderr.String())
	}
	for _, wanted := range []string{`"service": "example-relay"`, `"worker": "example-worker"`, "preview-digest: "} {
		if !strings.Contains(stdout.String(), wanted) {
			t.Fatalf("preview missing %q: %s", wanted, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "0123456789abcdef0123456789abcdef") || !strings.Contains(stdout.String(), "012345...cdef") {
		t.Fatalf("preview did not minimize account identity: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "private dry-run output") {
		t.Fatalf("preview exposed Wrangler output: %s", stdout.String())
	}
	wantArgs := [][]string{
		{"--version"},
		{"whoami", "--account", "0123456789abcdef0123456789abcdef", "--json"},
		{"deploy", "--dry-run", "--config", "wrangler.jsonc"},
	}
	if len(fake.requests) != len(wantArgs) {
		t.Fatalf("requests=%+v", fake.requests)
	}
	snapshotPath := fake.requests[0].Directory
	for index, request := range fake.requests {
		if request.Program != "node_modules/.bin/wrangler" || request.Directory != snapshotPath || request.Directory == sourcePath || request.Timeout != 30*time.Second || strings.Join(request.Args, "\x00") != strings.Join(wantArgs[index], "\x00") {
			t.Fatalf("request[%d]=%+v snapshot=%q", index, request, snapshotPath)
		}
	}
}

func TestOpsDeployDryRunFailureReportsSafeStageDiagnostics(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	fake := &cliCloudflareExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n", Duration: 5 * time.Millisecond},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`, Duration: 7 * time.Millisecond},
		{ExitCode: 1, Stdout: "private source output", Stderr: "token=private-token account=0123456789abcdef0123456789abcdef", Duration: 125 * time.Millisecond},
	}}
	previous := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = previous })

	var stdout, stderr bytes.Buffer
	code, handled := executeRootCommand(p, []string{
		"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.15-1",
	}, &stdout, &stderr)
	if !handled || code != 1 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, stdout.String(), stderr.String())
	}
	diagnostic := stderr.String()
	for _, wanted := range []string{
		"stage=dry-run",
		"code=CF_DRY_RUN_FAILED",
		"elapsed=125ms",
		"timeout=none",
		"correlation-id=",
		"remediation=Inspect the private operation report, correct the dry-run input, and rerun the preview.",
	} {
		if !strings.Contains(diagnostic, wanted) {
			t.Fatalf("diagnostic missing %q: %s", wanted, diagnostic)
		}
	}
	if strings.Contains(diagnostic, "deployment preview failed") {
		t.Fatalf("generic preview error remained: %s", diagnostic)
	}
	for _, private := range []string{"private source output", "private-token", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(stdout.String(), private) || strings.Contains(diagnostic, private) {
			t.Fatalf("private execution output leaked: out=%q err=%q", stdout.String(), diagnostic)
		}
	}
}

func TestOpsDeployPreviewReportsSuccessfulStageTimings(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	fake := successfulCLICloudflareExecutor()
	fake.results[0].Duration = 5 * time.Millisecond
	fake.results[1].Duration = 7 * time.Millisecond
	fake.results[2].Duration = 11 * time.Millisecond
	previous := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = previous })

	var stdout, stderr bytes.Buffer
	code, _ := executeRootCommand(p, []string{
		"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.15-1",
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	for _, stage := range []string{"git-inspect", "snapshot", "wrangler-version", "account-membership", "dry-run"} {
		if !strings.Contains(stdout.String(), `"stage": "`+stage+`"`) {
			t.Fatalf("preview missing successful stage %q: %s", stage, stdout.String())
		}
	}
	for _, elapsed := range []string{`"elapsed": 5000000`, `"elapsed": 7000000`, `"elapsed": 11000000`} {
		if !strings.Contains(stdout.String(), elapsed) {
			t.Fatalf("preview missing elapsed evidence %q: %s", elapsed, stdout.String())
		}
	}
}

func TestOpsDeployPreviewUsesRepositoryScopeSnapshotForSiblingAssets(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLIFile(t, filepath.Join(sourcePath, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","assets":{"directory":"../admin"}}`, 0o644)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	fake := successfulCLICloudflareExecutor()
	siblingVisible := false
	fake.afterRun = func(request opsexec.Request) {
		if len(request.Args) > 1 && request.Args[0] == "deploy" && request.Args[1] == "--dry-run" {
			_, err := os.Stat(filepath.Join(filepath.Dir(request.Directory), "admin", "index.html"))
			siblingVisible = err == nil
		}
	}
	original := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = original })

	var stdout, stderr bytes.Buffer
	code, _ := executeRootCommand(p, []string{
		"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.15-1",
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if len(fake.requests) != 3 {
		t.Fatalf("requests=%+v", fake.requests)
	}
	snapshotSource := fake.requests[0].Directory
	if filepath.Base(snapshotSource) != "relay" {
		t.Fatalf("Wrangler directory=%q", snapshotSource)
	}
	if !siblingVisible {
		t.Fatal("sibling scope was not visible during Wrangler dry-run")
	}
}

func TestOpsDeployStartsWranglerTimeoutAfterSnapshotCreation(t *testing.T) {
	p := opsTestPaths(t, "valid")
	replacePolicyValue(t, p.OperationsRoot, "defaultTimeout: 30s", "defaultTimeout: 500ms")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)

	previousSnapshot := opsCloudflareSnapshot
	opsCloudflareSnapshot = func(root, source string, scopes []string) (opscloudflare.SourceSnapshot, error) {
		snapshot, err := previousSnapshot(root, source, scopes)
		time.Sleep(600 * time.Millisecond)
		return snapshot, err
	}
	t.Cleanup(func() { opsCloudflareSnapshot = previousSnapshot })
	fake := &contextCheckingCloudflareExecutor{cliCloudflareExecutor: successfulCLICloudflareExecutor()}
	previousExecutor := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = previousExecutor })

	var stdout, stderr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{
		"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.15-1",
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func TestOpsDeployRejectsCloudflareProductionWriteWhileSecurityGateIsClosed(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	args := []string{"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.14-1"}

	previewExecutor := successfulCLICloudflareExecutor()
	original := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return previewExecutor }
	t.Cleanup(func() { opsCloudflareExecutor = original })
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}

	confirmedExecutor := successfulCLICloudflareExecutor()
	opsCloudflareExecutor = func() opsexec.Executor { return confirmedExecutor }
	var stdout, stderr bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirmArgs, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "production writes are temporarily disabled") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if hasCloudflareProductionDeploy(confirmedExecutor.requests) {
		t.Fatalf("security gate allowed production deploy: %+v", confirmedExecutor.requests)
	}
}

func TestOpsDeployRejectsCloudflareInputDriftBeforeProductionCommand(t *testing.T) {
	previousWritesEnabled := cloudflareProductionWritesEnabled
	cloudflareProductionWritesEnabled = true
	t.Cleanup(func() { cloudflareProductionWritesEnabled = previousWritesEnabled })

	tests := []struct {
		name          string
		mutate        func(*testing.T, string)
		applyExecutor func() *cliCloudflareExecutor
		wantError     string
	}{
		{
			name: "scoped bytes",
			mutate: func(t *testing.T, root string) {
				writeCLIFile(t, filepath.Join(root, "relay", "src", "index.ts"), "changed\n", 0o644)
			},
			applyExecutor: successfulCLICloudflareExecutor,
			wantError:     "stale",
		},
		{
			name: "untracked scoped file",
			mutate: func(t *testing.T, root string) {
				writeCLIFile(t, filepath.Join(root, "relay", "src", "untracked.ts"), "new\n", 0o644)
			},
			applyExecutor: successfulCLICloudflareExecutor,
			wantError:     "stale",
		},
		{
			name: "Wrangler config",
			mutate: func(t *testing.T, root string) {
				writeCLIFile(t, filepath.Join(root, "relay", "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","compatibility_date":"2026-09-14"}`, 0o644)
			},
			applyExecutor: successfulCLICloudflareExecutor,
			wantError:     "stale",
		},
		{
			name:   "account membership",
			mutate: func(*testing.T, string) {},
			applyExecutor: func() *cliCloudflareExecutor {
				return &cliCloudflareExecutor{results: []opsexec.Result{
					{ExitCode: 0, Stdout: "4.35.0\n"},
					{ExitCode: 0, Stdout: `{"accounts":[{"id":"ffffffffffffffffffffffffffffffff"}]}`},
				}}
			},
			wantError: "stage=account-membership",
		},
		{
			name:   "Wrangler version",
			mutate: func(*testing.T, string) {},
			applyExecutor: func() *cliCloudflareExecutor {
				executor := successfulCLICloudflareExecutor()
				executor.results[0].Stdout = "4.36.0\n"
				return executor
			},
			wantError: "stale",
		},
		{
			name: "ignored deployment input",
			mutate: func(t *testing.T, root string) {
				writeCLIFile(t, filepath.Join(root, "relay", "dist", "worker.js"), "ignored bundle\n", 0o644)
			},
			applyExecutor: successfulCLICloudflareExecutor,
			wantError:     "stale",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := opsTestPaths(t, "valid")
			repositoryRoot, sourcePath := newCLICloudflareRepository(t)
			writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
			previewExecutor := successfulCLICloudflareExecutor()
			original := opsCloudflareExecutor
			opsCloudflareExecutor = func() opsexec.Executor { return previewExecutor }
			t.Cleanup(func() { opsCloudflareExecutor = original })

			args := []string{"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.14-1"}
			var preview, previewErr bytes.Buffer
			if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
				t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
			}
			digest := previewDigest(t, preview.String())
			tt.mutate(t, repositoryRoot)

			applyExecutor := tt.applyExecutor()
			opsCloudflareExecutor = func() opsexec.Executor { return applyExecutor }
			var stdout, stderr bytes.Buffer
			confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", digest)
			if code, _ := executeRootCommand(p, confirmArgs, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), tt.wantError) {
				t.Fatalf("code=%d out=%q err=%q want=%q", code, stdout.String(), stderr.String(), tt.wantError)
			}
			if hasCloudflareProductionDeploy(applyExecutor.requests) {
				t.Fatalf("drift executed production deploy: %+v", applyExecutor.requests)
			}
		})
	}
}

func successfulCLICloudflareExecutor() *cliCloudflareExecutor {
	return &cliCloudflareExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: "dry-run"},
	}}
}

func TestOpsDeployRejectsScopedDriftAfterConfirmationDryRun(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	args := []string{"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.14-1"}
	previewExecutor := successfulCLICloudflareExecutor()
	stubCLICloudflareExecutor(t, previewExecutor)
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}

	confirmedExecutor := successfulCLICloudflareExecutor()
	confirmedExecutor.afterRun = func(request opsexec.Request) {
		if len(request.Args) > 1 && request.Args[0] == "deploy" && request.Args[1] == "--dry-run" {
			writeCLIFile(t, filepath.Join(repositoryRoot, "relay", "src", "index.ts"), "changed after dry-run\n", 0o644)
			confirmedExecutor.afterRun = nil
		}
	}
	stubCLICloudflareExecutor(t, confirmedExecutor)
	var stdout, stderr bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirmArgs, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "stale") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if hasCloudflareProductionDeploy(confirmedExecutor.requests) {
		t.Fatalf("post-dry-run drift executed production deploy: %+v", confirmedExecutor.requests)
	}
}

func TestOpsDeployRejectsSnapshotDriftAfterConfirmationDryRun(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	args := []string{"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.14-1"}
	previewExecutor := successfulCLICloudflareExecutor()
	stubCLICloudflareExecutor(t, previewExecutor)
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d err=%q", code, previewErr.String())
	}
	confirmedExecutor := successfulCLICloudflareExecutor()
	confirmedExecutor.afterRun = func(request opsexec.Request) {
		if len(request.Args) > 1 && request.Args[0] == "deploy" && request.Args[1] == "--dry-run" {
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
	if hasCloudflareProductionDeploy(confirmedExecutor.requests) {
		t.Fatalf("changed snapshot executed production deploy: %+v", confirmedExecutor.requests)
	}
}

func TestCloudflareApplyFailureReportPersistsTypedUnknownStateIdentity(t *testing.T) {
	root := t.TempDir()
	plan := opscloudflare.CloudflareDeployPlan{
		Service: "example-relay", Environment: "production", Worker: "example-worker", RequestedVersion: "2026.09.15-1",
		DeploymentInputSHA256: strings.Repeat("b", 64),
	}
	result := opscloudflare.ApplyResult{
		ProductionWriteSucceeded: true,
		DeploymentID:             "22222222-2222-4222-8222-222222222222",
		VersionIDs:               []string{"11111111-1111-4111-8111-111111111111"},
	}
	var output bytes.Buffer
	started := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	if err := writeCloudflareApplyFailureReport(root, "cloudflare-deploy", strings.Repeat("a", 64), plan, result, started, started.Add(time.Second), &output); err != nil {
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
	if json.Unmarshal(data, &report) != nil || report.Cloudflare == nil || report.Cloudflare.Outcome != opsreport.CloudflareUnknownState || report.Terminal || report.Cloudflare.DeploymentID != result.DeploymentID || len(report.Cloudflare.VersionIDs) != 1 || report.Cloudflare.VersionIDs[0] != result.VersionIDs[0] {
		t.Fatalf("typed unknown-state identity missing: %s", data)
	}
}

func TestCloudflareEmergencyReportIgnoresPreexistingSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	primary := filepath.Join(root, "reports")
	if err := os.WriteFile(primary, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(root, "emergency-reports")); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report := opsreport.Report{
		OperationID: "cloudflare-test", Actor: "actor", Service: "service", Environment: "production", Host: "worker",
		PlanDigest: strings.Repeat("1", 64), RequestedVersion: "version", ArtifactDigest: strings.Repeat("2", 64),
		Steps:     []opsreport.StepResult{{Order: 1, Kind: "test", Status: "failed", StartedAt: now, FinishedAt: now}},
		StartedAt: now, FinishedAt: now, Terminal: true,
	}
	path, err := writeCloudflareReport(primary, report)
	if err != nil || strings.HasPrefix(path, external+string(filepath.Separator)) {
		t.Fatalf("path=%q err=%v", path, err)
	}
	entries, err := os.ReadDir(external)
	if err != nil || len(entries) != 0 {
		t.Fatalf("external entries=%v err=%v", entries, err)
	}
}

func emergencyReportRoot(t *testing.T, parent string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(parent, "emergency-reports-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("emergency report roots=%v err=%v", matches, err)
	}
	return matches[0]
}
func stubCLICloudflareExecutor(t *testing.T, executor opsexec.Executor) {
	t.Helper()
	previous := opsCloudflareExecutor
	previousWritesEnabled := cloudflareProductionWritesEnabled
	opsCloudflareExecutor = func() opsexec.Executor { return executor }
	cloudflareProductionWritesEnabled = true
	t.Cleanup(func() {
		opsCloudflareExecutor = previous
		cloudflareProductionWritesEnabled = previousWritesEnabled
	})
}

func stubCLICloudflareHealth(t *testing.T, result opshealth.Result) {
	t.Helper()
	previous := opsHealthProbe
	opsHealthProbe = func(context.Context, opsexec.Executor, opsconfig.Environment, opsconfig.Health, time.Duration) opshealth.Result {
		return result
	}
	t.Cleanup(func() { opsHealthProbe = previous })
}

func readOnlyCloudflareReport(t *testing.T, root string) opsreport.Report {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("reports=%v err=%v", entries, err)
	}
	path := filepath.Join(root, entries[0].Name())
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report opsreport.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func hasCloudflareProductionDeploy(requests []opsexec.Request) bool {
	for _, request := range requests {
		if len(request.Args) > 0 && request.Args[0] == "deploy" && !containsCLIArgument(request.Args, "--dry-run") {
			return true
		}
	}
	return false
}

func containsCLIArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}

type cliCloudflareExecutor struct {
	requests []opsexec.Request
	results  []opsexec.Result
	afterRun func(opsexec.Request)
}

type contextCheckingCloudflareExecutor struct {
	*cliCloudflareExecutor
}

func (e *contextCheckingCloudflareExecutor) Run(ctx context.Context, request opsexec.Request) opsexec.Result {
	if err := ctx.Err(); err != nil {
		return opsexec.Result{ExitCode: -1, Err: err}
	}
	return e.cliCloudflareExecutor.Run(ctx, request)
}

func (e *cliCloudflareExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, request)
	if len(e.results) == 0 {
		return opsexec.Result{ExitCode: -1}
	}
	result := e.results[0]
	e.results = e.results[1:]
	if e.afterRun != nil {
		e.afterRun(request)
	}
	return result
}

func (e *cliCloudflareExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: -1}
}

func newCLICloudflareRepository(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "relay")
	writeCLIFile(t, filepath.Join(source, "package.json"), `{"devDependencies":{"wrangler":"~4.35.0"}}`, 0o644)
	writeCLIFile(t, filepath.Join(source, "package-lock.json"), `{}`, 0o644)
	writeCLIFile(t, filepath.Join(source, "node_modules", ".bin", "wrangler"), "#!/usr/bin/env node\n", 0o755)
	writeCLIFile(t, filepath.Join(source, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef"}`, 0o644)
	writeCLIFile(t, filepath.Join(source, "src", "index.ts"), "baseline\n", 0o644)
	writeCLIFile(t, filepath.Join(root, "admin", "index.html"), "admin", 0o644)
	writeCLIFile(t, filepath.Join(root, ".gitignore"), "relay/dist/\n", 0o644)
	runCLIGit(t, root, "init", "--quiet")
	runCLIGit(t, root, "config", "user.name", "AgentOps Test")
	runCLIGit(t, root, "config", "user.email", "agentops@example.test")
	runCLIGit(t, root, "add", ".")
	runCLIGit(t, root, "commit", "--quiet", "-m", "baseline")
	return root, source
}

func writeCLICloudflareService(t *testing.T, operationsRoot, repositoryRoot, sourcePath string) {
	t.Helper()
	content := fmt.Sprintf(`version: 1
id: example-relay
language: typescript
source:
  path: %s
  repository: git@example.com:example.git
  repositoryRoot: %s
  deploymentScope: [relay, admin]
deployment:
  requireCommittedScope: false
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: example-worker
    accountId: 0123456789abcdef0123456789abcdef
    wranglerConfig: wrangler.jsonc
    health:
      type: http
      url: https://example.test/health
      successStatuses: [200, 204]
`, sourcePath, repositoryRoot)
	writeCLIFile(t, filepath.Join(operationsRoot, "services", "example-relay.yaml"), content, 0o644)
}

func writeCLIFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func runCLIGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
}
