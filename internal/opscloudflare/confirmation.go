package opscloudflare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

type ProductionConfirmationIdentity struct {
	APIProfile            string   `json:"api_profile"`
	ClientVersion         string   `json:"client_version"`
	EndpointSequence      []string `json:"endpoint_sequence"`
	TokenProviderIdentity string   `json:"token_provider_identity"`
}

type productionConfirmationMaterial struct {
	Plan                    json.RawMessage `json:"plan"`
	APIProfile              string          `json:"api_profile"`
	ClientVersion           string          `json:"client_version"`
	CanonicalMetadataSHA256 string          `json:"canonical_metadata_sha256"`
	PayloadSHA256           string          `json:"payload_sha256"`
	EndpointSequence        []string        `json:"endpoint_sequence"`
	TokenProviderIdentity   string          `json:"token_provider_identity"`
}

type rollbackProductionConfirmationMaterial struct {
	Plan                  json.RawMessage `json:"plan"`
	APIProfile            string          `json:"api_profile"`
	ClientVersion         string          `json:"client_version"`
	EndpointSequence      []string        `json:"endpoint_sequence"`
	TokenProviderIdentity string          `json:"token_provider_identity"`
}

var productionIdentityPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+/-]{0,127}$`)

func ProductionCanonicalJSON(plan CloudflareDeployPlan, request opscloudflarepayload.Request, identity ProductionConfirmationIdentity) ([]byte, error) {
	if err := opscloudflarepayload.ValidateWranglerVersion(identity.APIProfile, plan.WranglerVersion); err != nil {
		return nil, errors.New("Cloudflare production execution profile is unsupported")
	}
	planJSON, err := CanonicalJSON(plan)
	if err != nil {
		return nil, errors.New("Cloudflare production plan is invalid")
	}
	payloadDigest, err := opscloudflarepayload.CanonicalDigest(request.Payload)
	if err != nil || request.ExpectedSHA256 != payloadDigest || request.AccountID != plan.AccountID || request.Worker != plan.Worker || request.ExpectedDeploymentID != plan.CurrentDeploymentID || !equalStringSet(request.ExpectedVersionIDs, plan.CurrentVersionIDs) || plan.DeploymentInputSHA256 != payloadDigest {
		return nil, errors.New("Cloudflare production payload is invalid")
	}
	var metadataIdentity struct {
		Profile   string `json:"profile"`
		Name      string `json:"name"`
		AccountID string `json:"account_id"`
		Main      string `json:"main"`
	}
	if json.Unmarshal(request.Payload.Metadata, &metadataIdentity) != nil || metadataIdentity.Profile != identity.APIProfile || metadataIdentity.Name != request.Worker || metadataIdentity.AccountID != request.AccountID || metadataIdentity.Main != request.Payload.MainModule {
		return nil, errors.New("Cloudflare production metadata identity is invalid")
	}
	if !validProductionIdentity(identity) {
		return nil, errors.New("Cloudflare production execution identity is invalid")
	}
	expectedSequence, err := opscloudflarepayload.EndpointSequence(request)
	if err != nil || !equalEndpointSequence(identity.EndpointSequence, expectedSequence) {
		return nil, errors.New("Cloudflare production endpoint sequence is invalid")
	}
	metadataDigest := sha256.Sum256(request.Payload.Metadata)
	material := productionConfirmationMaterial{
		Plan: planJSON, APIProfile: identity.APIProfile, ClientVersion: identity.ClientVersion,
		CanonicalMetadataSHA256: hex.EncodeToString(metadataDigest[:]), PayloadSHA256: payloadDigest,
		EndpointSequence: append([]string(nil), identity.EndpointSequence...), TokenProviderIdentity: identity.TokenProviderIdentity,
	}
	return json.Marshal(material)
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]int, len(left))
	for _, value := range left {
		want[value]++
	}
	for _, value := range right {
		want[value]--
		if want[value] < 0 {
			return false
		}
	}
	return true
}

func ProductionDigest(plan CloudflareDeployPlan, request opscloudflarepayload.Request, identity ProductionConfirmationIdentity) (string, error) {
	canonical, err := ProductionCanonicalJSON(plan, request, identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func RollbackProductionCanonicalJSON(plan CloudflareRollbackPlan, request opscloudflarepayload.RollbackRequest, identity ProductionConfirmationIdentity) ([]byte, error) {
	if err := opscloudflarepayload.ValidateWranglerVersion(identity.APIProfile, plan.WranglerVersion); err != nil {
		return nil, errors.New("Cloudflare rollback production execution profile is unsupported")
	}
	planJSON, err := RollbackCanonicalJSON(plan)
	if err != nil {
		return nil, errors.New("Cloudflare rollback plan is invalid")
	}
	if request.AccountID != plan.AccountID || request.Worker != plan.Worker || request.TargetVersionID != plan.TargetVersionID || request.PreviousDeploymentID != plan.CurrentDeploymentID || request.ExpectedSHA256 != plan.DeploymentInputSHA256 {
		return nil, errors.New("Cloudflare rollback request is invalid")
	}
	if !validProductionIdentity(identity) {
		return nil, errors.New("Cloudflare production execution identity is invalid")
	}
	if !equalEndpointSequence(identity.EndpointSequence, opscloudflarepayload.RollbackEndpointSequence(request)) {
		return nil, errors.New("Cloudflare rollback endpoint sequence is invalid")
	}
	material := rollbackProductionConfirmationMaterial{
		Plan: planJSON, APIProfile: identity.APIProfile, ClientVersion: identity.ClientVersion,
		EndpointSequence: append([]string(nil), identity.EndpointSequence...), TokenProviderIdentity: identity.TokenProviderIdentity,
	}
	return json.Marshal(material)
}

func equalEndpointSequence(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func RollbackProductionDigest(plan CloudflareRollbackPlan, request opscloudflarepayload.RollbackRequest, identity ProductionConfirmationIdentity) (string, error) {
	canonical, err := RollbackProductionCanonicalJSON(plan, request, identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func validProductionIdentity(identity ProductionConfirmationIdentity) bool {
	if !productionIdentityPattern.MatchString(identity.APIProfile) || !productionIdentityPattern.MatchString(identity.ClientVersion) || !productionIdentityPattern.MatchString(identity.TokenProviderIdentity) || len(identity.EndpointSequence) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(identity.EndpointSequence))
	for _, endpoint := range identity.EndpointSequence {
		if !productionIdentityPattern.MatchString(endpoint) || strings.Contains(strings.ToLower(endpoint), "token") {
			return false
		}
		if _, exists := seen[endpoint]; exists {
			return false
		}
		seen[endpoint] = struct{}{}
	}
	return true
}
