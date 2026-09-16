package opscli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/paths"
)

func TestCloudflareProductionRouteRejectsBeforeTrustedClient(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *int)
	}{
		{
			name: "preview",
			run: func(t *testing.T, clientCalls *int) {
				p, args := cloudflareDeployMatrixFixture(t)
				stubCLICloudflareExecutor(t, successfulCLICloudflareExecutor())
				var stdout, stderr bytes.Buffer
				if code, _ := executeRootCommand(p, args, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "preview-digest: ") {
					t.Fatalf("code=%d out=%q err=%q clients=%d", code, stdout.String(), stderr.String(), *clientCalls)
				}
			},
		},
		{
			name: "missing digest",
			run: func(t *testing.T, clientCalls *int) {
				p, args := cloudflareDeployMatrixFixture(t)
				var stdout, stderr bytes.Buffer
				confirm := append(append([]string(nil), args...), "--confirm")
				if code, _ := executeRootCommand(p, confirm, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "preview-digest") {
					t.Fatalf("code=%d out=%q err=%q clients=%d", code, stdout.String(), stderr.String(), *clientCalls)
				}
			},
		},
		{
			name: "stale digest",
			run: func(t *testing.T, clientCalls *int) {
				p, args := cloudflareDeployMatrixFixture(t)
				stubCLICloudflareExecutor(t, successfulCLICloudflareExecutor())
				var stdout, stderr bytes.Buffer
				confirm := append(append([]string(nil), args...), "--confirm", "--preview-digest", strings.Repeat("0", 64))
				if code, _ := executeRootCommand(p, confirm, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "stale") {
					t.Fatalf("code=%d out=%q err=%q clients=%d", code, stdout.String(), stderr.String(), *clientCalls)
				}
			},
		},
		{
			name: "unsupported profile",
			run: func(t *testing.T, clientCalls *int) {
				p, args := cloudflareDeployMatrixFixture(t)
				servicePath := filepath.Join(p.OperationsRoot, "services", "example-relay.yaml")
				data, err := os.ReadFile(servicePath)
				if err != nil {
					t.Fatal(err)
				}
				data = []byte(strings.Replace(string(data), "apiProfile: wrangler-4.107-preveal-v1", "apiProfile: wrangler-4.108-unsupported", 1))
				if err := os.WriteFile(servicePath, data, 0o644); err != nil {
					t.Fatal(err)
				}
				var stdout, stderr bytes.Buffer
				if code, _ := executeRootCommand(p, args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "apiProfile") {
					t.Fatalf("code=%d out=%q err=%q clients=%d", code, stdout.String(), stderr.String(), *clientCalls)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientCalls := 0
			stubCloudflareProductionClient(t, func() (cloudflareProductionWriter, error) {
				clientCalls++
				return &recordingCloudflareProductionWriter{}, nil
			})
			test.run(t, &clientCalls)
			if clientCalls != 0 {
				t.Fatalf("trusted client constructed before route authorization: %d", clientCalls)
			}
		})
	}
}

func TestCloudflareProductionDeployUsesReviewedEndpointSequenceWithFake(t *testing.T) {
	p, args := cloudflareDeployMatrixFixture(t)
	writer := &recordingCloudflareProductionWriter{}
	clientCalls := 0
	stubCloudflareProductionClient(t, func() (cloudflareProductionWriter, error) {
		clientCalls++
		return writer, nil
	})
	stubCLICloudflareHealth(t, opshealth.Result{Type: "http", Healthy: true, StatusCode: 200})

	stubCLICloudflareExecutor(t, successfulCLICloudflareExecutor())
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}
	stubCLICloudflareExecutor(t, successfulCLICloudflareExecutor())
	var stdout, stderr bytes.Buffer
	confirm := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirm, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "deployment: succeeded") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	want := []string{"domains-read", "schedules-read", "current-deployment-read", "version-create", "deployment-create", "identity-read"}
	got, err := opscloudflarepayload.EndpointSequence(writer.deployRequest)
	if err != nil || !reflect.DeepEqual(got, want) || clientCalls != 1 || writer.deployCalls != 1 || writer.rollbackCalls != 0 {
		t.Fatalf("sequence=%v want=%v err=%v clientCalls=%d writer=%+v", got, want, err, clientCalls, writer)
	}
}

func TestCloudflareProductionRollbackUsesReviewedEndpointSequenceWithFake(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	target := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	args := []string{"ops", "rollback", "example-relay", "--environment", "production", "--version", target}
	writer := &recordingCloudflareProductionWriter{}
	clientCalls := 0
	stubCloudflareProductionClient(t, func() (cloudflareProductionWriter, error) {
		clientCalls++
		return writer, nil
	})
	stubCLICloudflareHealth(t, opshealth.Result{Type: "http", Healthy: true, StatusCode: 200})

	stubCLICloudflareExecutor(t, successfulCLICloudflareRollbackExecutor(target))
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}
	stubCLICloudflareExecutor(t, successfulCLICloudflareRollbackExecutor(target))
	var stdout, stderr bytes.Buffer
	confirm := append(append([]string(nil), args...), "--confirm", "--preview-digest", previewDigest(t, preview.String()))
	if code, _ := executeRootCommand(p, confirm, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "rollback: succeeded") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	want := []string{"current-deployment-read", "deployment-create", "identity-read"}
	got := opscloudflarepayload.RollbackEndpointSequence(writer.rollbackRequest)
	if !reflect.DeepEqual(got, want) || clientCalls != 1 || writer.rollbackCalls != 1 || writer.deployCalls != 0 {
		t.Fatalf("sequence=%v want=%v clientCalls=%d writer=%+v", got, want, clientCalls, writer)
	}
}

func TestSSHRouteDoesNotConstructCloudflareProductionClient(t *testing.T) {
	p := opsTestPaths(t, "valid")
	clientCalls := 0
	stubCloudflareProductionClient(t, func() (cloudflareProductionWriter, error) {
		clientCalls++
		return &recordingCloudflareProductionWriter{}, nil
	})
	fake := &cliRollbackExecutor{}
	previous := opsRollbackExecutor
	opsRollbackExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsRollbackExecutor = previous })

	var stdout, stderr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.5.0"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "preview-digest: ") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	if clientCalls != 0 {
		t.Fatalf("SSH route constructed Cloudflare client: %d", clientCalls)
	}
}

type recordingCloudflareProductionWriter struct {
	deployCalls     int
	rollbackCalls   int
	deployRequest   opscloudflarepayload.Request
	rollbackRequest opscloudflarepayload.RollbackRequest
}

func (w *recordingCloudflareProductionWriter) Deploy(_ context.Context, request opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	w.deployCalls++
	w.deployRequest = request
	return opscloudflarepayload.Evidence{
		ClientVersion: opscloudflarepayload.ProductionClientVersion,
		RequestID:     "22222222-2222-4222-8222-222222222222",
		VersionIDs:    []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
		InputSHA256:   request.ExpectedSHA256,
	}, nil
}

func (w *recordingCloudflareProductionWriter) Rollback(_ context.Context, request opscloudflarepayload.RollbackRequest) (opscloudflarepayload.Evidence, error) {
	w.rollbackCalls++
	w.rollbackRequest = request
	return opscloudflarepayload.Evidence{
		ClientVersion: opscloudflarepayload.ProductionClientVersion,
		RequestID:     "22222222-2222-4222-8222-222222222222",
		VersionIDs:    []string{request.TargetVersionID},
		InputSHA256:   request.ExpectedSHA256,
	}, nil
}

func cloudflareDeployMatrixFixture(t *testing.T) (paths.Paths, []string) {
	t.Helper()
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	return p, []string{"ops", "deploy", "example-relay", "--environment", "production", "--version", "2026.09.15-1"}
}

func stubCloudflareProductionClient(t *testing.T, factory func() (cloudflareProductionWriter, error)) {
	t.Helper()
	previous := opsCloudflareProductionClient
	opsCloudflareProductionClient = factory
	t.Cleanup(func() { opsCloudflareProductionClient = previous })
}
