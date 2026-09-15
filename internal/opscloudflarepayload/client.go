package opscloudflarepayload

import (
	"context"
	"errors"
	"time"
)

type Request struct {
	AccountID      string
	Worker         string
	ExpectedSHA256 string
	Payload        Payload
	Timeout        time.Duration
}

type Evidence struct {
	ClientVersion string
	RequestID     string
	InputSHA256   string
	StartedAt     time.Time
	FinishedAt    time.Time
}

type TrustedTransport interface {
	Execute(context.Context, Request) (Evidence, error)
}

func NewRequest(accountID, worker, expectedSHA256 string, payload Payload, timeout time.Duration) (Request, error) {
	if accountID == "" || worker == "" || expectedSHA256 == "" || timeout <= 0 || !payloadDigestMatches(payload, expectedSHA256) {
		return Request{}, errors.New("Cloudflare client request is invalid")
	}
	return Request{
		AccountID:      accountID,
		Worker:         worker,
		ExpectedSHA256: expectedSHA256,
		Payload:        payload.clone(),
		Timeout:        timeout,
	}, nil
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
