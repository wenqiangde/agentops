package opscloudflare_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestApplyRequiresExactConfirmedDigestAndUsesProjectLocalWrangler(t *testing.T) {
	plan := opscloudflare.CloudflareDeployPlan{
		Service: "preveal-relay", Environment: "production", RequestedVersion: "2026.09.14-1",
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64),
		WranglerVersion: "4.35.0", BaseCommit: strings.Repeat("2", 40),
		ScopeState: "clean", ScopeContentSHA256: strings.Repeat("3", 64),
		DryRunVerified: true, SourcePath: "/tmp/example-relay", Timeout: 5 * time.Second,
	}
	digest, err := opscloudflare.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}

	staleExecutor := &recordingExecutor{}
	if _, err := opscloudflare.Apply(context.Background(), staleExecutor, opscloudflare.ConfirmedPlan{Plan: plan, Digest: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("stale digest was accepted")
	}
	if len(staleExecutor.requests) != 0 {
		t.Fatalf("stale digest executed commands: %+v", staleExecutor.requests)
	}

	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: `[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]`},
		{ExitCode: 0, Stdout: "private deploy output"},
		{ExitCode: 0, Stdout: `[{"id":"22222222-2222-4222-8222-222222222222","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]},{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]`},
	}}
	result, err := opscloudflare.Apply(context.Background(), executor, opscloudflare.ConfirmedPlan{Plan: plan, Digest: digest})
	if err != nil || !result.Success || result.DeploymentID != "22222222-2222-4222-8222-222222222222" || len(result.VersionIDs) != 1 || result.VersionIDs[0] != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(executor.requests) != 3 {
		t.Fatalf("requests=%+v", executor.requests)
	}
	for _, index := range []int{0, 2} {
		request := executor.requests[index]
		if request.Program != "node_modules/.bin/wrangler" || request.Directory != plan.SourcePath || request.Timeout != plan.Timeout || strings.Join(request.Args, " ") != "deployments list --json --config wrangler.jsonc" {
			t.Fatalf("identity request=%+v", request)
		}
	}
	request := executor.requests[1]
	if request.Program != "node_modules/.bin/wrangler" || request.Directory != plan.SourcePath || request.Timeout != plan.Timeout || strings.Join(request.Args, " ") != "deploy --config wrangler.jsonc" {
		t.Fatalf("request=%+v", request)
	}
}

func TestApplyRejectsSuccessfulDeployWithoutNewDurableIdentity(t *testing.T) {
	plan := opscloudflare.CloudflareDeployPlan{
		Service: "preveal-relay", Environment: "production", RequestedVersion: "2026.09.14-1",
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64),
		WranglerVersion: "4.35.0", BaseCommit: strings.Repeat("2", 40),
		ScopeState: "clean", ScopeContentSHA256: strings.Repeat("3", 64),
		DryRunVerified: true, SourcePath: "/tmp/example-relay", Timeout: 5 * time.Second,
	}
	digest, err := opscloudflare.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := `[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]`
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: unchanged},
		{ExitCode: 0, Stdout: "deploy exited successfully"},
		{ExitCode: 0, Stdout: unchanged},
	}}
	result, err := opscloudflare.Apply(context.Background(), executor, opscloudflare.ConfirmedPlan{Plan: plan, Digest: digest})
	if err == nil || result.Success || !strings.Contains(err.Error(), "durable deployment identity") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
