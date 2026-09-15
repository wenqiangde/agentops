package opscloudflare

import (
	"context"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestApplyRevalidatesOwnedProductionConfirmationImmediatelyBeforeWrite(t *testing.T) {
	request := internalDeployRequest(t)
	plan := internalDeployPlan(request.ExpectedSHA256)
	identity := internalProductionIdentity()
	digest, err := ProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := ConfirmProduction(plan, request, identity, digest)
	if err != nil {
		t.Fatal(err)
	}
	confirmed.request.Payload.Modules[0].Bytes[0] ^= 0xff
	writer := &internalDeploymentWriter{}
	if _, err := Apply(context.Background(), writer, confirmed); err == nil {
		t.Fatal("mutated confirmed payload was accepted")
	}
	if writer.calls != 0 {
		t.Fatalf("writer called %d times", writer.calls)
	}
}

func TestApplyRollbackRevalidatesOwnedProductionConfirmationImmediatelyBeforeWrite(t *testing.T) {
	plan := internalRollbackPlan()
	request, err := opscloudflarepayload.NewRollbackRequest(plan.AccountID, plan.Worker, plan.TargetVersionID, plan.CurrentDeploymentID, plan.DeploymentInputSHA256, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity := internalProductionIdentity()
	digest, err := RollbackProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := ConfirmProductionRollback(plan, request, identity, digest)
	if err != nil {
		t.Fatal(err)
	}
	confirmed.request.TargetVersionID = "44444444-4444-4444-8444-444444444444"
	writer := &internalRollbackWriter{}
	if _, err := ApplyRollback(context.Background(), writer, confirmed); err == nil {
		t.Fatal("mutated confirmed rollback request was accepted")
	}
	if writer.calls != 0 {
		t.Fatalf("writer called %d times", writer.calls)
	}
}

type internalDeploymentWriter struct{ calls int }

func (w *internalDeploymentWriter) Deploy(context.Context, opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	w.calls++
	return opscloudflarepayload.Evidence{}, nil
}

type internalRollbackWriter struct{ calls int }

func (w *internalRollbackWriter) Rollback(context.Context, opscloudflarepayload.RollbackRequest) (opscloudflarepayload.Evidence, error) {
	w.calls++
	return opscloudflarepayload.Evidence{}, nil
}

func internalDeployRequest(t *testing.T) opscloudflarepayload.Request {
	t.Helper()
	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := opscloudflarepayload.NewRequest("0123456789abcdef0123456789abcdef", "example-worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func internalProductionIdentity() ProductionConfirmationIdentity {
	return ProductionConfirmationIdentity{
		APIProfile: "wrangler-4.107-preveal-v1", ClientVersion: "cloudflare-go/v7.7.0",
		EndpointSequence: []string{"version-create", "deployment-create", "identity-read"}, TokenProviderIdentity: "environment",
	}
}

func internalDeployPlan(payloadDigest string) CloudflareDeployPlan {
	return CloudflareDeployPlan{
		Service: "example-relay", Environment: "production", RequestedVersion: "2026.09.15-1",
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: "1111111111111111111111111111111111111111111111111111111111111111", WranglerVersion: "4.35.0",
		BaseCommit: "2222222222222222222222222222222222222222", ScopeState: "clean", ScopeContentSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
		DeploymentInputSHA256: payloadDigest, DryRunVerified: true,
	}
}

func internalRollbackPlan() CloudflareRollbackPlan {
	return CloudflareRollbackPlan{
		Service: "example-relay", Environment: "production", Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: "1111111111111111111111111111111111111111111111111111111111111111", WranglerVersion: "4.35.0",
		BaseCommit: "2222222222222222222222222222222222222222", ScopeState: "clean", ScopeContentSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
		DeploymentInputSHA256: "4444444444444444444444444444444444444444444444444444444444444444",
		TargetVersionID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CurrentDeploymentID: "11111111-1111-4111-8111-111111111111",
		CurrentVersionIDs: []string{"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, TargetVerified: true,
	}
}
