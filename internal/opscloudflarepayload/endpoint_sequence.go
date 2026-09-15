package opscloudflarepayload

import (
	"encoding/json"
	"errors"
)

const (
	endpointDomainsRead      = "domains-read"
	endpointSchedulesRead    = "schedules-read"
	endpointAssetSession     = "asset-session"
	endpointAssetUpload      = "asset-upload"
	endpointVersionCreate    = "version-create"
	endpointDeploymentCreate = "deployment-create"
	endpointIdentityRead     = "identity-read"
)

func EndpointSequence(request Request) ([]string, error) {
	if !payloadDigestMatches(request.Payload, request.ExpectedSHA256) {
		return nil, errors.New("Cloudflare endpoint sequence request is invalid")
	}
	var config CanonicalConfig
	if json.Unmarshal(request.Payload.Metadata, &config) != nil || config.validate() != nil || !sdkProfileSupported(config, request.Payload) {
		return nil, errors.New("Cloudflare endpoint sequence profile is invalid")
	}
	sequence := []string{endpointDomainsRead, endpointSchedulesRead}
	if len(request.Payload.Assets) > 0 {
		sequence = append(sequence, endpointAssetSession, endpointAssetUpload)
	}
	return append(sequence, endpointVersionCreate, endpointDeploymentCreate, endpointIdentityRead), nil
}

func RollbackEndpointSequence(RollbackRequest) []string {
	return []string{endpointDeploymentCreate, endpointIdentityRead}
}

func newRollbackEndpointSequenceGuard(request RollbackRequest) *endpointSequenceGuard {
	return &endpointSequenceGuard{expected: RollbackEndpointSequence(request)}
}

type endpointSequenceGuard struct {
	expected []string
	index    int
}

func newEndpointSequenceGuard(request Request) (*endpointSequenceGuard, error) {
	sequence, err := EndpointSequence(request)
	if err != nil {
		return nil, err
	}
	return &endpointSequenceGuard{expected: sequence}, nil
}

func (g *endpointSequenceGuard) consume(endpoint string) error {
	if g == nil || g.index >= len(g.expected) || g.expected[g.index] != endpoint {
		return errors.New("Cloudflare SDK endpoint sequence mismatch")
	}
	g.index++
	return nil
}

func (g *endpointSequenceGuard) complete() error {
	if g == nil || g.index != len(g.expected) {
		return errors.New("Cloudflare SDK endpoint sequence is incomplete")
	}
	return nil
}
