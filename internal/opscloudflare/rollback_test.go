package opscloudflare_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
)

func TestResolveRollbackTargetRequiresExplicitCloudflareIdentity(t *testing.T) {
	executor := &recordingExecutor{}
	_, err := opscloudflare.ResolveRollbackTarget(context.Background(), executor, opscloudflare.RollbackTargetRequest{
		SourcePath: "/tmp/example-relay", WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "explicit") {
		t.Fatalf("err=%v", err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("missing target executed commands: %+v", executor.requests)
	}
}

func TestResolveRollbackTargetFindsVersionFromMachineReadableVersionList(t *testing.T) {
	const target = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	executor := &recordingExecutor{results: []opsexec.Result{{
		ExitCode: 0,
		Stdout:   `[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","metadata":{"created_on":"2026-09-13T10:00:00Z"}}]`,
	}}}
	resolved, err := opscloudflare.ResolveRollbackTarget(context.Background(), executor, rollbackTargetRequest(target))
	if err != nil || resolved.VersionID != target || resolved.DeploymentID != "" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	want := []opsexec.Request{{
		Program: "node_modules/.bin/wrangler", Args: []string{"versions", "list", "--json", "--config", "wrangler.jsonc"},
		Directory: "/tmp/example-relay", Timeout: 5 * time.Second,
	}}
	if !reflect.DeepEqual(executor.requests, want) {
		t.Fatalf("requests=%+v want=%+v", executor.requests, want)
	}
}

func TestResolveRollbackTargetMapsOnlySingleVersionDeployment(t *testing.T) {
	const deploymentID = "11111111-1111-4111-8111-111111111111"
	const versionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: `[{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}]`},
		{ExitCode: 0, Stdout: `[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]`},
	}}
	resolved, err := opscloudflare.ResolveRollbackTarget(context.Background(), executor, rollbackTargetRequest(deploymentID))
	if err != nil || resolved.VersionID != versionID || resolved.DeploymentID != deploymentID {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}

	splitExecutor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: `[]`},
		{ExitCode: 0, Stdout: `[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":50},{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":50}]}]`},
	}}
	if _, err := opscloudflare.ResolveRollbackTarget(context.Background(), splitExecutor, rollbackTargetRequest(deploymentID)); err == nil || !strings.Contains(err.Error(), "single 100% version") {
		t.Fatalf("split deployment err=%v", err)
	}
}

func TestCreateRollbackPlanUsesOnlyMachineReadableIdentityReads(t *testing.T) {
	root := newCloudflareProject(t)
	target := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: `[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]`},
		{ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]}`},
	}}
	plan, err := opscloudflare.CreateRollbackPlan(context.Background(), executor, sampleRollbackPlanRequest(root, target))
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetVersionID != target || plan.CurrentDeploymentID != "11111111-1111-4111-8111-111111111111" || !reflect.DeepEqual(plan.CurrentVersionIDs, []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}) {
		t.Fatalf("plan=%+v", plan)
	}
	for _, request := range executor.requests {
		if request.Program != "node_modules/.bin/wrangler" || hasRollbackWrite(request) {
			t.Fatalf("preview executed non-read command: %+v", request)
		}
	}
}

func TestConfirmRollbackPlanRejectsTargetSourceAndAccountDrift(t *testing.T) {
	base := opscloudflare.CloudflareRollbackPlan{
		Service: "example-relay", Environment: "production",
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64), WranglerVersion: "4.35.0",
		BaseCommit: strings.Repeat("2", 40), ScopeState: opsgit.StateClean, ScopeContentSHA256: strings.Repeat("3", 64),
		DeploymentInputSHA256: strings.Repeat("4", 64),
		TargetVersionID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		CurrentDeploymentID:   "11111111-1111-4111-8111-111111111111",
		CurrentVersionIDs:     []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		TargetVerified:        true,
	}
	digest, err := opscloudflare.RollbackDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opscloudflare.ConfirmRollbackPlan(base, digest); err != nil {
		t.Fatalf("unchanged plan rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*opscloudflare.CloudflareRollbackPlan)
	}{
		{name: "target", mutate: func(plan *opscloudflare.CloudflareRollbackPlan) {
			plan.TargetVersionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		}},
		{name: "source", mutate: func(plan *opscloudflare.CloudflareRollbackPlan) { plan.ScopeContentSHA256 = strings.Repeat("4", 64) }},
		{name: "account", mutate: func(plan *opscloudflare.CloudflareRollbackPlan) { plan.AccountID = "1123456789abcdef0123456789abcdef" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := base
			changed.CurrentVersionIDs = append([]string(nil), base.CurrentVersionIDs...)
			tt.mutate(&changed)
			if _, err := opscloudflare.ConfirmRollbackPlan(changed, digest); err == nil || !strings.Contains(err.Error(), "stale") {
				t.Fatalf("drift accepted: plan=%+v err=%v", changed, err)
			}
		})
	}
}

func TestResolveRollbackTargetRejectsMissingOrUnprovableIdentity(t *testing.T) {
	tests := []struct {
		name    string
		results []opsexec.Result
		want    string
	}{
		{
			name: "target missing",
			results: []opsexec.Result{
				{ExitCode: 0, Stdout: `[]`},
				{ExitCode: 0, Stdout: `[]`},
			},
			want: "not found",
		},
		{
			name: "version list malformed",
			results: []opsexec.Result{
				{ExitCode: 0, Stdout: `{not-json`},
			},
			want: "version lookup failed",
		},
		{
			name: "deployment identity malformed",
			results: []opsexec.Result{
				{ExitCode: 0, Stdout: `[]`},
				{ExitCode: 0, Stdout: `[{"id":"not-a-uuid","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]`},
			},
			want: "durable deployment identity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &recordingExecutor{results: tt.results}
			_, err := opscloudflare.ResolveRollbackTarget(context.Background(), executor, rollbackTargetRequest("11111111-1111-4111-8111-111111111111"))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want=%q", err, tt.want)
			}
		})
	}
}

func TestCreateRollbackPlanRejectsUnprovableCurrentIdentityAndBlocksAlreadyActiveTarget(t *testing.T) {
	root := newCloudflareProject(t)
	target := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	baseResults := []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: `[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]`},
	}

	malformed := &recordingExecutor{results: append(append([]opsexec.Result(nil), baseResults...), opsexec.Result{ExitCode: 0, Stdout: `{"id":"not-a-uuid","versions":[]}`})}
	if _, err := opscloudflare.CreateRollbackPlan(context.Background(), malformed, sampleRollbackPlanRequest(root, target)); err == nil || !strings.Contains(err.Error(), "active deployment identity") {
		t.Fatalf("unprovable current identity err=%v", err)
	}
	incompleteTraffic := &recordingExecutor{results: append(append([]opsexec.Result(nil), baseResults...), opsexec.Result{
		ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":80}]}`,
	})}
	if _, err := opscloudflare.CreateRollbackPlan(context.Background(), incompleteTraffic, sampleRollbackPlanRequest(root, target)); err == nil || !strings.Contains(err.Error(), "active deployment identity") {
		t.Fatalf("incomplete traffic identity err=%v", err)
	}
	duplicateVersion := &recordingExecutor{results: append(append([]opsexec.Result(nil), baseResults...), opsexec.Result{
		ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":50},{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":50}]}`,
	})}
	if _, err := opscloudflare.CreateRollbackPlan(context.Background(), duplicateVersion, sampleRollbackPlanRequest(root, target)); err == nil || !strings.Contains(err.Error(), "active deployment identity") {
		t.Fatalf("duplicate version identity err=%v", err)
	}

	alreadyActive := &recordingExecutor{results: append(append([]opsexec.Result(nil), baseResults...), opsexec.Result{
		ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}`,
	})}
	plan, err := opscloudflare.CreateRollbackPlan(context.Background(), alreadyActive, sampleRollbackPlanRequest(root, target))
	if err != nil || !plan.Blocked || !strings.Contains(plan.BlockReason, "already active") {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err := opscloudflare.ConfirmRollbackPlan(plan, strings.Repeat("0", 64)); err == nil {
		t.Fatal("already-active target was confirmable")
	}
}

func rollbackTargetRequest(target string) opscloudflare.RollbackTargetRequest {
	return opscloudflare.RollbackTargetRequest{
		SourcePath: "/tmp/example-relay", WranglerConfig: "wrangler.jsonc", TargetID: target, Timeout: 5 * time.Second,
	}
}

func sampleRollbackPlanRequest(root, target string) opscloudflare.RollbackPlanRequest {
	return opscloudflare.RollbackPlanRequest{
		Service: "example-relay", TargetID: target,
		Git: opsgit.Evidence{
			RepositoryRoot: root, BaseCommit: strings.Repeat("2", 40), State: opsgit.StateClean,
			ContentSHA256: strings.Repeat("3", 64),
		},
		Preflight: opscloudflare.Request{
			SourcePath: root, Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
			WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
		},
	}
}

func sampleCloudflareRollbackPlan() opscloudflare.CloudflareRollbackPlan {
	return opscloudflare.CloudflareRollbackPlan{
		Service: "example-relay", Environment: "production",
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64), WranglerVersion: "4.35.0",
		BaseCommit: strings.Repeat("2", 40), ScopeState: opsgit.StateClean, ScopeContentSHA256: strings.Repeat("3", 64),
		DeploymentInputSHA256: strings.Repeat("4", 64),
		TargetVersionID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		CurrentDeploymentID:   "11111111-1111-4111-8111-111111111111",
		CurrentVersionIDs:     []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		TargetVerified:        true, SourcePath: "/tmp/example-relay", Timeout: 5 * time.Second,
	}
}

func hasRollbackWrite(request opsexec.Request) bool {
	return len(request.Args) > 0 && (request.Args[0] == "rollback" || request.Args[0] == "deploy")
}
