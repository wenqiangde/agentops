package opscloudflarepayload

import (
	"bytes"
	"context"
	"errors"
	"time"
)

const maxProductionTokenBytes = 64 * 1024

type Request struct {
	AccountID            string
	Worker               string
	ExpectedDeploymentID string
	ExpectedVersionIDs   []string
	ExpectedSHA256       string
	Payload              Payload
	Timeout              time.Duration
}

type Evidence struct {
	ClientVersion        string
	RequestID            string
	VersionIDs           []string
	InputSHA256          string
	RemoteWritePossible  bool
	ObservedMigrations   []MigrationObservationEvidence
	PendingMigrationTags []string
	MigrationOmitted     bool
	StartedAt            time.Time
	FinishedAt           time.Time
}

type MigrationObservationEvidence struct {
	VersionID string `json:"version_id"`
	State     string `json:"state"`
	Tag       string `json:"tag,omitempty"`
}

type TrustedTransport interface {
	Execute(context.Context, Request) (Evidence, error)
}

type TokenProvider interface {
	Token(context.Context) ([]byte, error)
	Identity() string
}

type ProductionTransport interface {
	Deploy(context.Context, []byte, Request) (Evidence, error)
}

type RollbackRequest struct {
	AccountID            string
	Worker               string
	TargetVersionID      string
	PreviousDeploymentID string
	ExpectedSHA256       string
	Timeout              time.Duration
}

type RollbackTransport interface {
	Rollback(context.Context, []byte, RollbackRequest) (Evidence, error)
}

type Client struct {
	tokenProvider TokenProvider
	transport     ProductionTransport
}

func NewClient(tokenProvider TokenProvider, transport ProductionTransport) (*Client, error) {
	if tokenProvider == nil || transport == nil || tokenProvider.Identity() == "" {
		return nil, errors.New("Cloudflare production client is invalid")
	}
	return &Client{tokenProvider: tokenProvider, transport: transport}, nil
}

func (c *Client) Deploy(ctx context.Context, request Request) (Evidence, error) {
	if c == nil || c.tokenProvider == nil || c.transport == nil || ctx == nil {
		return Evidence{}, errors.New("Cloudflare production client is invalid")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	if request.Timeout <= 0 || request.ExpectedDeploymentID == "" || len(request.ExpectedVersionIDs) == 0 || request.ExpectedSHA256 == "" || !payloadDigestMatches(request.Payload, request.ExpectedSHA256) {
		return Evidence{}, errors.New("Cloudflare client request is invalid")
	}
	requestContext, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	token, err := c.tokenProvider.Token(requestContext)
	if err != nil {
		if requestContext.Err() != nil {
			return Evidence{}, requestContext.Err()
		}
		return Evidence{}, errors.New("Cloudflare production token is unavailable")
	}
	token = append([]byte(nil), token...)
	defer clearBytes(token)
	if len(token) == 0 || len(token) > maxProductionTokenBytes || len(bytes.TrimSpace(token)) == 0 {
		return Evidence{}, errors.New("Cloudflare production token is invalid")
	}
	request.Payload = request.Payload.clone()
	evidence, err := c.transport.Deploy(requestContext, token, request)
	if err != nil {
		if requestContext.Err() != nil {
			return evidence, requestContext.Err()
		}
		return evidence, errors.New("Cloudflare production deploy failed")
	}
	if evidence.InputSHA256 != request.ExpectedSHA256 {
		return Evidence{}, errors.New("Cloudflare production evidence is invalid")
	}
	return evidence, nil
}

func (c *Client) Rollback(ctx context.Context, request RollbackRequest) (Evidence, error) {
	transport, ok := c.transport.(RollbackTransport)
	if c == nil || c.tokenProvider == nil || !ok || ctx == nil || request.Timeout <= 0 || emptyRollbackRequest(request) {
		return Evidence{}, errors.New("Cloudflare rollback client request is invalid")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	token, err := c.tokenProvider.Token(requestContext)
	if err != nil {
		if requestContext.Err() != nil {
			return Evidence{}, requestContext.Err()
		}
		return Evidence{}, errors.New("Cloudflare production token is unavailable")
	}
	token = append([]byte(nil), token...)
	defer clearBytes(token)
	if len(token) == 0 || len(token) > maxProductionTokenBytes || len(bytes.TrimSpace(token)) == 0 {
		return Evidence{}, errors.New("Cloudflare production token is invalid")
	}
	evidence, err := transport.Rollback(requestContext, token, request)
	if err != nil {
		if requestContext.Err() != nil {
			return evidence, requestContext.Err()
		}
		return evidence, errors.New("Cloudflare production rollback failed")
	}
	if evidence.InputSHA256 != request.ExpectedSHA256 {
		return Evidence{}, errors.New("Cloudflare production evidence is invalid")
	}
	return evidence, nil
}

func NewRollbackRequest(accountID, worker, targetVersionID, previousDeploymentID, expectedSHA256 string, timeout time.Duration) (RollbackRequest, error) {
	request := RollbackRequest{AccountID: accountID, Worker: worker, TargetVersionID: targetVersionID, PreviousDeploymentID: previousDeploymentID, ExpectedSHA256: expectedSHA256, Timeout: timeout}
	if timeout <= 0 || emptyRollbackRequest(request) {
		return RollbackRequest{}, errors.New("Cloudflare rollback client request is invalid")
	}
	return request, nil
}

func emptyRollbackRequest(request RollbackRequest) bool {
	return request.AccountID == "" || request.Worker == "" || request.TargetVersionID == "" || request.PreviousDeploymentID == "" || request.ExpectedSHA256 == ""
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func NewRequest(accountID, worker, expectedDeploymentID string, expectedVersionIDs []string, expectedSHA256 string, payload Payload, timeout time.Duration) (Request, error) {
	if accountID == "" || worker == "" || expectedDeploymentID == "" || !uniqueNonEmptyValues(expectedVersionIDs) || expectedSHA256 == "" || timeout <= 0 || !payloadDigestMatches(payload, expectedSHA256) {
		return Request{}, errors.New("Cloudflare client request is invalid")
	}
	return Request{
		AccountID:            accountID,
		Worker:               worker,
		ExpectedDeploymentID: expectedDeploymentID,
		ExpectedVersionIDs:   append([]string(nil), expectedVersionIDs...),
		ExpectedSHA256:       expectedSHA256,
		Payload:              payload.clone(),
		Timeout:              timeout,
	}, nil
}

func uniqueNonEmptyValues(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func OwnRequest(request Request) (Request, error) {
	owned, err := NewRequest(request.AccountID, request.Worker, request.ExpectedDeploymentID, request.ExpectedVersionIDs, request.ExpectedSHA256, request.Payload, request.Timeout)
	if err != nil {
		return Request{}, errors.New("Cloudflare client request is invalid")
	}
	return owned, nil
}

func OwnRollbackRequest(request RollbackRequest) (RollbackRequest, error) {
	return NewRollbackRequest(request.AccountID, request.Worker, request.TargetVersionID, request.PreviousDeploymentID, request.ExpectedSHA256, request.Timeout)
}

func Execute(ctx context.Context, request Request, transport TrustedTransport) (Evidence, error) {
	if ctx == nil || transport == nil {
		return Evidence{}, errors.New("Cloudflare trusted transport is invalid")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	if request.Timeout <= 0 || request.ExpectedSHA256 == "" || !payloadDigestMatches(request.Payload, request.ExpectedSHA256) {
		return Evidence{}, errors.New("Cloudflare client request is invalid")
	}
	request.Payload = request.Payload.clone()
	requestContext, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()
	return transport.Execute(requestContext, request)
}

func payloadDigestMatches(payload Payload, expected string) bool {
	return payload.SHA256 != "" && payload.SHA256 == expected && digestPayload(payload) == expected
}
