package opscloudflarepayload_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestClientRequestUsesOwnedPayloadAndExpectedDigest(t *testing.T) {
	payload := contractTestPayload(t)
	request, err := opscloudflarepayload.NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload.Modules[0].Bytes[0] = 'X'
	transport := &recordingContractTransport{}

	evidence, err := opscloudflarepayload.Execute(context.Background(), request, transport)
	if err != nil {
		t.Fatal(err)
	}
	if transport.request.AccountID != "account" || transport.request.Worker != "worker" {
		t.Fatalf("unexpected production identity: %#v", transport.request)
	}
	if transport.request.ExpectedSHA256 != request.ExpectedSHA256 || evidence.InputSHA256 != request.ExpectedSHA256 {
		t.Fatalf("digest evidence mismatch: request=%q transport=%q evidence=%q", request.ExpectedSHA256, transport.request.ExpectedSHA256, evidence.InputSHA256)
	}
	if got := string(transport.request.Payload.Modules[0].Bytes); got != "export default {}" {
		t.Fatalf("transport received mutable payload: %q", got)
	}
}

func TestClientRequestRejectsDigestMismatch(t *testing.T) {
	payload := contractTestPayload(t)
	if _, err := opscloudflarepayload.NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, "wrong", payload, time.Second); err == nil {
		t.Fatal("mismatched expected digest was accepted")
	}
}

func TestClientRequestRejectsPayloadMutationAfterConstruction(t *testing.T) {
	payload := contractTestPayload(t)
	request, err := opscloudflarepayload.NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request.Payload.Modules[0].Bytes[0] = 'X'
	transport := &recordingContractTransport{}
	if _, err := opscloudflarepayload.Execute(context.Background(), request, transport); err == nil {
		t.Fatal("mutated request payload was accepted")
	}
	if transport.calls != 0 {
		t.Fatalf("mutated request reached transport %d times", transport.calls)
	}
}

func TestClientRequestTimesOutTrustedTransport(t *testing.T) {
	payload := contractTestPayload(t)
	request, err := opscloudflarepayload.NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = opscloudflarepayload.Execute(context.Background(), request, blockingContractTransport{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestClientRequestPropagatesCancellation(t *testing.T) {
	payload := contractTestPayload(t)
	request, err := opscloudflarepayload.NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transport := &recordingContractTransport{}
	_, err = opscloudflarepayload.Execute(ctx, request, transport)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("cancelled request reached transport %d times", transport.calls)
	}
}

type recordingContractTransport struct {
	calls   int
	request opscloudflarepayload.Request
}

func (r *recordingContractTransport) Execute(_ context.Context, request opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	r.calls++
	r.request = request
	now := time.Now()
	return opscloudflarepayload.Evidence{
		ClientVersion: "fake-v1",
		RequestID:     "request-1",
		InputSHA256:   request.ExpectedSHA256,
		StartedAt:     now,
		FinishedAt:    now,
	}, nil
}

type blockingContractTransport struct{}

func (blockingContractTransport) Execute(ctx context.Context, _ opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	<-ctx.Done()
	return opscloudflarepayload.Evidence{}, ctx.Err()
}

func contractTestPayload(t *testing.T) opscloudflarepayload.Payload {
	t.Helper()
	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("export default {}")}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
