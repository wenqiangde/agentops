package opscloudflare_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestApplyUsesOnlyConfirmedOwnedPayload(t *testing.T) {
	request := deployPayloadRequest(t)
	plan := deployConfirmedPlan(request.ExpectedSHA256)
	identity := deployProductionIdentity()
	digest, err := opscloudflare.ProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := opscloudflare.ConfirmProduction(plan, request, identity, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.Payload.Modules[0].Bytes[0] ^= 0xff
	writer := &recordingDeploymentWriter{evidence: opscloudflarepayload.Evidence{ClientVersion: "fake-v1", RequestID: "22222222-2222-4222-8222-222222222222", VersionIDs: []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, InputSHA256: request.ExpectedSHA256}}
	result, err := opscloudflare.Apply(context.Background(), writer, confirmed)
	if err != nil || !result.Success || !result.ProductionWriteSucceeded || result.DeploymentID != writer.evidence.RequestID || len(result.VersionIDs) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if writer.calls != 1 || writer.request.AccountID != plan.AccountID || writer.request.Worker != plan.Worker || writer.request.ExpectedSHA256 != plan.DeploymentInputSHA256 {
		t.Fatalf("writer=%+v", writer)
	}
}

func TestApplyRejectsStaleOrMismatchedPayloadBeforeWriter(t *testing.T) {
	request := deployPayloadRequest(t)
	plan := deployConfirmedPlan(request.ExpectedSHA256)
	identity := deployProductionIdentity()
	digest, err := opscloudflare.ProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		providedDigest string
		mutate         func(*opscloudflarepayload.Request)
	}{
		{name: "stale confirmation", providedDigest: strings.Repeat("0", 64)},
		{name: "wrong account", providedDigest: digest, mutate: func(r *opscloudflarepayload.Request) { r.AccountID = "other-account" }},
		{name: "wrong worker", providedDigest: digest, mutate: func(r *opscloudflarepayload.Request) { r.Worker = "other-worker" }},
		{name: "wrong digest", providedDigest: digest, mutate: func(r *opscloudflarepayload.Request) { r.ExpectedSHA256 = strings.Repeat("0", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := request
			if tt.mutate != nil {
				tt.mutate(&candidate)
			}
			if _, err := opscloudflare.ConfirmProduction(plan, candidate, identity, tt.providedDigest); err == nil {
				t.Fatal("invalid payload was accepted")
			}
		})
	}
}

func TestApplyPreservesUnknownRemoteStateFromWriterError(t *testing.T) {
	request := deployPayloadRequest(t)
	plan := deployConfirmedPlan(request.ExpectedSHA256)
	identity := deployProductionIdentity()
	digest, err := opscloudflare.ProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := opscloudflare.ConfirmProduction(plan, request, identity, digest)
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingDeploymentWriter{
		evidence: opscloudflarepayload.Evidence{
			RemoteWritePossible: true,
			RequestID:           "22222222-2222-4222-8222-222222222222",
			VersionIDs:          []string{"11111111-1111-4111-8111-111111111111"},
		},
		err: errors.New("identity read failed"),
	}
	result, err := opscloudflare.Apply(context.Background(), writer, confirmed)
	if err == nil {
		t.Fatal("unknown remote state was reported as success")
	}
	if !result.ProductionWriteSucceeded || result.DeploymentID != writer.evidence.RequestID || len(result.VersionIDs) != 1 || result.VersionIDs[0] != writer.evidence.VersionIDs[0] {
		t.Fatalf("unknown remote state evidence was lost: %#v", result)
	}
}

func deployProductionIdentity() opscloudflare.ProductionConfirmationIdentity {
	return opscloudflare.ProductionConfirmationIdentity{
		APIProfile: "wrangler-4.107-preveal-v1", ClientVersion: "cloudflare-go/v7.7.0",
		EndpointSequence: []string{"version-create", "deployment-create", "identity-read"}, TokenProviderIdentity: "environment",
	}
}

type recordingDeploymentWriter struct {
	calls    int
	request  opscloudflarepayload.Request
	evidence opscloudflarepayload.Evidence
	err      error
}

func (w *recordingDeploymentWriter) Deploy(_ context.Context, request opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	w.calls++
	w.request = request
	return w.evidence, w.err
}

func deployPayloadRequest(t *testing.T) opscloudflarepayload.Request {
	t.Helper()
	metadata := []byte(`{"profile":"wrangler-4.107-preveal-v1","name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`)
	payload, err := opscloudflarepayload.NewPayload("worker.mjs", []opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}}, nil, metadata)
	if err != nil {
		t.Fatal(err)
	}
	request, err := opscloudflarepayload.NewRequest("0123456789abcdef0123456789abcdef", "example-worker", payload.SHA256, payload, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func deployConfirmedPlan(payloadDigest string) opscloudflare.CloudflareDeployPlan {
	return opscloudflare.CloudflareDeployPlan{Service: "example-relay", Environment: "production", RequestedVersion: "2026.09.14-1", Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef", WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64), WranglerVersion: "4.35.0", BaseCommit: strings.Repeat("2", 40), ScopeState: "clean", ScopeContentSHA256: strings.Repeat("3", 64), DeploymentInputSHA256: payloadDigest, DryRunVerified: true, SourcePath: "/tmp/example-relay", Timeout: 5 * time.Second}
}
