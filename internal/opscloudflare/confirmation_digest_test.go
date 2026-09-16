package opscloudflare_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestProductionDigestBindsTrustedExecutionIdentityAndCompleteOwnedPayload(t *testing.T) {
	plan, request, identity := productionDigestFixture(t)
	baseline := productionDigest(t, plan, request, identity)

	tests := []struct {
		name   string
		reject bool
		mutate func(*opscloudflare.CloudflareDeployPlan, *opscloudflarepayload.Request, *opscloudflare.ProductionConfirmationIdentity)
	}{
		{name: "unsupported API profile", reject: true, mutate: func(_ *opscloudflare.CloudflareDeployPlan, _ *opscloudflarepayload.Request, identity *opscloudflare.ProductionConfirmationIdentity) {
			identity.APIProfile = "wrangler-4.108-next-v1"
		}},
		{name: "client version", mutate: func(_ *opscloudflare.CloudflareDeployPlan, _ *opscloudflarepayload.Request, identity *opscloudflare.ProductionConfirmationIdentity) {
			identity.ClientVersion = "cloudflare-go/v7.8.0"
		}},
		{name: "canonical metadata", mutate: func(plan *opscloudflare.CloudflareDeployPlan, request *opscloudflarepayload.Request, _ *opscloudflare.ProductionConfirmationIdentity) {
			request.Payload = mustProductionPayload(t, "2026-09-16", "approved module", "approved asset")
			request.ExpectedSHA256 = request.Payload.SHA256
			plan.DeploymentInputSHA256 = request.Payload.SHA256
		}},
		{name: "module bytes", mutate: func(plan *opscloudflare.CloudflareDeployPlan, request *opscloudflarepayload.Request, _ *opscloudflare.ProductionConfirmationIdentity) {
			request.Payload = mustProductionPayload(t, "2026-09-15", "changed module", "approved asset")
			request.ExpectedSHA256 = request.Payload.SHA256
			plan.DeploymentInputSHA256 = request.Payload.SHA256
		}},
		{name: "asset bytes", mutate: func(plan *opscloudflare.CloudflareDeployPlan, request *opscloudflarepayload.Request, _ *opscloudflare.ProductionConfirmationIdentity) {
			request.Payload = mustProductionPayload(t, "2026-09-15", "approved module", "changed asset")
			request.ExpectedSHA256 = request.Payload.SHA256
			plan.DeploymentInputSHA256 = request.Payload.SHA256
		}},
		{name: "endpoint sequence", reject: true, mutate: func(_ *opscloudflare.CloudflareDeployPlan, _ *opscloudflarepayload.Request, identity *opscloudflare.ProductionConfirmationIdentity) {
			identity.EndpointSequence[0], identity.EndpointSequence[1] = identity.EndpointSequence[1], identity.EndpointSequence[0]
		}},
		{name: "token provider identity", mutate: func(_ *opscloudflare.CloudflareDeployPlan, _ *opscloudflarepayload.Request, identity *opscloudflare.ProductionConfirmationIdentity) {
			identity.TokenProviderIdentity = "workload-identity"
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidatePlan := plan
			candidateRequest := request
			candidateIdentity := identity
			candidateIdentity.EndpointSequence = append([]string(nil), identity.EndpointSequence...)
			test.mutate(&candidatePlan, &candidateRequest, &candidateIdentity)
			got, err := opscloudflare.ProductionDigest(candidatePlan, candidateRequest, candidateIdentity)
			if test.reject {
				if err == nil {
					t.Fatalf("%s was accepted", test.name)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got == baseline {
				t.Fatalf("%s did not change production confirmation digest", test.name)
			}
		})
	}
}

func TestProductionDigestIsCanonicalAndExcludesCredentialBytes(t *testing.T) {
	plan, request, identity := productionDigestFixture(t)
	first, err := opscloudflare.ProductionCanonicalJSON(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	reordered := identity
	reordered.EndpointSequence = append([]string(nil), identity.EndpointSequence...)
	second, err := opscloudflare.ProductionCanonicalJSON(plan, request, reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("identical production inputs produced unstable canonical bytes:\n%s\n%s", first, second)
	}
	var material struct {
		APIProfile              string   `json:"api_profile"`
		ClientVersion           string   `json:"client_version"`
		CanonicalMetadataSHA256 string   `json:"canonical_metadata_sha256"`
		PayloadSHA256           string   `json:"payload_sha256"`
		EndpointSequence        []string `json:"endpoint_sequence"`
		TokenProviderIdentity   string   `json:"token_provider_identity"`
	}
	if err := json.Unmarshal(first, &material); err != nil {
		t.Fatalf("production confirmation material is not JSON: %v", err)
	}
	metadataDigest := sha256.Sum256(request.Payload.Metadata)
	if material.APIProfile != identity.APIProfile || material.ClientVersion != identity.ClientVersion ||
		material.CanonicalMetadataSHA256 != hex.EncodeToString(metadataDigest[:]) || material.PayloadSHA256 != request.Payload.SHA256 ||
		!reflect.DeepEqual(material.EndpointSequence, identity.EndpointSequence) || material.TokenProviderIdentity != identity.TokenProviderIdentity {
		t.Fatalf("production confirmation material is incomplete: %+v", material)
	}

	secret := []byte("cf-production-secret-must-not-enter-confirmation")
	if bytes.Contains(first, secret) || bytes.Contains(first, []byte(`"token":`)) || strings.Contains(productionDigest(t, plan, request, identity), string(secret)) {
		t.Fatal("credential bytes entered production confirmation material")
	}
	identityType := reflect.TypeOf(identity)
	for index := 0; index < identityType.NumField(); index++ {
		name := strings.ToLower(identityType.Field(index).Name)
		if strings.Contains(name, "token") && name != "tokenprovideridentity" || strings.Contains(name, "secret") || strings.Contains(name, "credential") {
			t.Fatalf("production confirmation identity exposes credential field %q", identityType.Field(index).Name)
		}
	}
}

func TestRollbackProductionDigestBindsTargetAndTrustedExecutionIdentity(t *testing.T) {
	plan := opscloudflare.CloudflareRollbackPlan{
		Service: "example-relay", Environment: "production", Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", WranglerConfigSHA256: strings.Repeat("1", 64), WranglerVersion: "4.107.0",
		BaseCommit: strings.Repeat("2", 40), ScopeState: "clean", ScopeContentSHA256: strings.Repeat("3", 64), DeploymentInputSHA256: strings.Repeat("4", 64),
		RequestedTargetID: "33333333-3333-4333-8333-333333333333", TargetVersionID: "33333333-3333-4333-8333-333333333333",
		CurrentDeploymentID: "22222222-2222-4222-8222-222222222222", CurrentVersionIDs: []string{"11111111-1111-4111-8111-111111111111"}, TargetVerified: true,
	}
	request, err := opscloudflarepayload.NewRollbackRequest(plan.AccountID, plan.Worker, plan.TargetVersionID, plan.CurrentDeploymentID, plan.DeploymentInputSHA256, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	identity := opscloudflare.ProductionConfirmationIdentity{
		APIProfile: "wrangler-4.107-preveal-v1", ClientVersion: "cloudflare-go/v7.7.0",
		EndpointSequence: []string{"current-deployment-read", "deployment-create", "identity-read"}, TokenProviderIdentity: "environment",
	}
	baseline, err := opscloudflare.RollbackProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.TargetVersionID = "44444444-4444-4444-8444-444444444444"
	changedRequest, err := opscloudflarepayload.NewRollbackRequest(changed.AccountID, changed.Worker, changed.TargetVersionID, changed.CurrentDeploymentID, changed.DeploymentInputSHA256, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := opscloudflare.RollbackProductionDigest(changed, changedRequest, identity); err != nil || digest == baseline {
		t.Fatalf("rollback target was not bound: digest=%q err=%v", digest, err)
	}
	identity.ClientVersion = "cloudflare-go/v7.8.0"
	if digest, err := opscloudflare.RollbackProductionDigest(plan, request, identity); err != nil || digest == baseline {
		t.Fatalf("rollback client identity was not bound: digest=%q err=%v", digest, err)
	}
}

func productionDigestFixture(t *testing.T) (opscloudflare.CloudflareDeployPlan, opscloudflarepayload.Request, opscloudflare.ProductionConfirmationIdentity) {
	t.Helper()
	payload := mustProductionPayload(t, "2026-09-15", "approved module", "approved asset")
	request, err := opscloudflarepayload.NewRequest("0123456789abcdef0123456789abcdef", "example-worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	plan := deployConfirmedPlan(payload.SHA256)
	identity := opscloudflare.ProductionConfirmationIdentity{
		APIProfile:            "wrangler-4.107-preveal-v1",
		ClientVersion:         "cloudflare-go/v7.7.0",
		EndpointSequence:      mustEndpointSequence(t, request),
		TokenProviderIdentity: "environment",
	}
	return plan, request, identity
}

func mustEndpointSequence(t *testing.T, request opscloudflarepayload.Request) []string {
	t.Helper()
	sequence, err := opscloudflarepayload.EndpointSequence(request)
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

func mustProductionPayload(t *testing.T, compatibilityDate, module, asset string) opscloudflarepayload.Payload {
	t.Helper()
	metadata := []byte(`{"profile":"wrangler-4.107-preveal-v1","name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","main":"worker.mjs","compatibility_date":"` + compatibilityDate + `","workers_dev":false,"preview_urls":false,"assets":{"binding":"ASSETS","run_worker_first":true,"not_found_handling":"single-page-application"}}`)
	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte(module)}},
		[]opscloudflarepayload.Asset{{Path: "index.html", Bytes: []byte(asset)}},
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func productionDigest(t *testing.T, plan opscloudflare.CloudflareDeployPlan, request opscloudflarepayload.Request, identity opscloudflare.ProductionConfirmationIdentity) string {
	t.Helper()
	digest, err := opscloudflare.ProductionDigest(plan, request, identity)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
