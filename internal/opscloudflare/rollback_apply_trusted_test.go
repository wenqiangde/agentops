package opscloudflare_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestApplyRollbackUsesOnlyConfirmedTypedRequest(t *testing.T) {
	plan := sampleCloudflareRollbackPlan()
	request, err := opscloudflarepayload.NewRollbackRequest(plan.AccountID, plan.Worker, plan.TargetVersionID, plan.CurrentDeploymentID, plan.DeploymentInputSHA256, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity := rollbackProductionIdentity()
	digest, err := opscloudflare.RollbackProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := opscloudflare.ConfirmProductionRollback(plan, request, identity, digest)
	if err != nil {
		t.Fatal(err)
	}
	request.TargetVersionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	writer := &recordingRollbackWriter{evidence: opscloudflarepayload.Evidence{
		ClientVersion: "fake-v1", RequestID: "22222222-2222-4222-8222-222222222222",
		VersionIDs: []string{plan.TargetVersionID}, InputSHA256: plan.DeploymentInputSHA256,
	}}
	result, err := opscloudflare.ApplyRollback(context.Background(), writer, confirmed)
	if err != nil || !result.Success || !result.ProductionWriteSucceeded || result.DeploymentID != writer.evidence.RequestID || result.VersionID != plan.TargetVersionID {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if writer.calls != 1 || writer.request.TargetVersionID != plan.TargetVersionID {
		t.Fatalf("writer=%+v", writer)
	}
}

func TestApplyRollbackRejectsDriftBeforeWriter(t *testing.T) {
	plan := sampleCloudflareRollbackPlan()
	base, err := opscloudflarepayload.NewRollbackRequest(plan.AccountID, plan.Worker, plan.TargetVersionID, plan.CurrentDeploymentID, plan.DeploymentInputSHA256, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity := rollbackProductionIdentity()
	digest, err := opscloudflare.RollbackProductionDigest(plan, base, identity)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*opscloudflarepayload.RollbackRequest)
	}{
		{name: "account", mutate: func(r *opscloudflarepayload.RollbackRequest) { r.AccountID = "other-account" }},
		{name: "worker", mutate: func(r *opscloudflarepayload.RollbackRequest) { r.Worker = "other-worker" }},
		{name: "target", mutate: func(r *opscloudflarepayload.RollbackRequest) {
			r.TargetVersionID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		}},
		{name: "previous deployment", mutate: func(r *opscloudflarepayload.RollbackRequest) {
			r.PreviousDeploymentID = "33333333-3333-4333-8333-333333333333"
		}},
		{name: "digest", mutate: func(r *opscloudflarepayload.RollbackRequest) { r.ExpectedSHA256 = strings.Repeat("0", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := base
			tt.mutate(&request)
			if _, err := opscloudflare.ConfirmProductionRollback(plan, request, identity, digest); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}

func rollbackProductionIdentity() opscloudflare.ProductionConfirmationIdentity {
	return opscloudflare.ProductionConfirmationIdentity{
		APIProfile: "wrangler-4.107-preveal-v1", ClientVersion: "cloudflare-go/v7.7.0",
		EndpointSequence: []string{"deployment-create", "identity-read"}, TokenProviderIdentity: "environment",
	}
}

type recordingRollbackWriter struct {
	calls    int
	request  opscloudflarepayload.RollbackRequest
	evidence opscloudflarepayload.Evidence
}

func (w *recordingRollbackWriter) Rollback(_ context.Context, request opscloudflarepayload.RollbackRequest) (opscloudflarepayload.Evidence, error) {
	w.calls++
	w.request = request
	return w.evidence, nil
}
