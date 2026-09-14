package opscloudflare_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
)

func TestCreatePlanOnlyReadsIdentityAndRunsWranglerDryRun(t *testing.T) {
	sourcePath := newCloudflareProject(t)
	accountID := "0123456789abcdef0123456789abcdef"
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: "dry-run output must not enter the plan"},
	}}

	_, err := opscloudflare.CreatePlan(context.Background(), executor, opscloudflare.PlanRequest{
		Service:          "preveal-relay",
		RequestedVersion: "2026.09.14-1",
		Git: opsgit.Evidence{
			RepositoryRoot: sourcePath,
			BaseCommit:     "0123456789abcdef0123456789abcdef01234567",
			State:          opsgit.StateClean,
			ContentSHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Preflight: opscloudflare.Request{
			SourcePath: sourcePath, Worker: "example-worker", AccountID: accountID,
			WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []opsexec.Request{
		{
			Program: "node_modules/.bin/wrangler", Args: []string{"--version"},
			Directory: sourcePath, Timeout: 5 * time.Second,
		},
		{
			Program:   "node_modules/.bin/wrangler",
			Args:      []string{"whoami", "--account", accountID, "--json"},
			Directory: sourcePath, Timeout: 5 * time.Second,
		},
		{
			Program:   "node_modules/.bin/wrangler",
			Args:      []string{"deploy", "--dry-run", "--config", "wrangler.jsonc"},
			Directory: sourcePath, Timeout: 5 * time.Second,
		},
	}
	if !reflect.DeepEqual(executor.requests, want) {
		t.Fatalf("requests=%+v want=%+v", executor.requests, want)
	}
	for _, request := range executor.requests {
		if len(request.Args) > 0 && request.Args[0] == "deploy" && !containsArgument(request.Args, "--dry-run") {
			t.Fatalf("preview attempted a real deployment: %+v", request)
		}
	}
}

func TestCloudflareDeployPlanDigestTracksTypedInputs(t *testing.T) {
	root := newCloudflareProject(t)
	writeFile(t, filepath.Join(root, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef"}`, 0o644)
	base := samplePlanRequest(root)
	baseline := createPlanDigest(t, base, "4.35.0", "first dry-run output")
	if repeated := createPlanDigest(t, base, "4.35.0", "different raw dry-run output"); repeated != baseline {
		t.Fatalf("identical typed input produced unstable digest: first=%s repeated=%s", baseline, repeated)
	}

	tests := []struct {
		name       string
		mutate     func(*opscloudflare.PlanRequest)
		version    string
		editConfig func(string)
	}{
		{
			name: "scoped content",
			mutate: func(request *opscloudflare.PlanRequest) {
				request.Git.ContentSHA256 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			},
		},
		{
			name: "Wrangler config content",
			editConfig: func(root string) {
				writeFile(t, filepath.Join(root, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","compatibility_date":"2026-09-14"}`, 0o644)
			},
		},
		{
			name: "account",
			mutate: func(request *opscloudflare.PlanRequest) {
				request.Preflight.AccountID = "1123456789abcdef0123456789abcdef"
				writeFile(t, filepath.Join(root, "wrangler.jsonc"), `{"name":"example-worker","account_id":"1123456789abcdef0123456789abcdef"}`, 0o644)
			},
		},
		{
			name: "Worker",
			mutate: func(request *opscloudflare.PlanRequest) {
				request.Preflight.Worker = "other-worker"
				writeFile(t, filepath.Join(root, "wrangler.jsonc"), `{"name":"other-worker","account_id":"0123456789abcdef0123456789abcdef"}`, 0o644)
			},
		},
		{name: "Wrangler version", version: "4.36.0"},
		{
			name: "base commit",
			mutate: func(request *opscloudflare.PlanRequest) {
				request.Git.BaseCommit = "1123456789abcdef0123456789abcdef01234567"
			},
		},
		{
			name: "requested version",
			mutate: func(request *opscloudflare.PlanRequest) {
				request.RequestedVersion = "2026.09.14-2"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeFile(t, filepath.Join(root, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef"}`, 0o644)
			request := samplePlanRequest(root)
			if tt.editConfig != nil {
				tt.editConfig(root)
			}
			if tt.mutate != nil {
				tt.mutate(&request)
			}
			version := tt.version
			if version == "" {
				version = "4.35.0"
			}
			if changed := createPlanDigest(t, request, version, "dry-run output"); changed == baseline {
				t.Fatalf("%s did not change digest", tt.name)
			}
		})
	}
}

func samplePlanRequest(sourcePath string) opscloudflare.PlanRequest {
	return opscloudflare.PlanRequest{
		Service:          "preveal-relay",
		RequestedVersion: "2026.09.14-1",
		Git: opsgit.Evidence{
			RepositoryRoot: sourcePath,
			BaseCommit:     "0123456789abcdef0123456789abcdef01234567",
			State:          opsgit.StateClean,
			ContentSHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Preflight: opscloudflare.Request{
			SourcePath: sourcePath, Worker: "example-worker",
			AccountID: "0123456789abcdef0123456789abcdef", WranglerConfig: "wrangler.jsonc",
			Timeout: 5 * time.Second,
		},
	}
}

func createPlanDigest(t *testing.T, request opscloudflare.PlanRequest, version, dryRunOutput string) string {
	t.Helper()
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: version + "\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"` + request.Preflight.AccountID + `"}]}`},
		{ExitCode: 0, Stdout: dryRunOutput},
	}}
	plan, err := opscloudflare.CreatePlan(context.Background(), executor, request)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := opscloudflare.Digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}
