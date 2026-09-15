package opscloudflarepayload_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestProductionClientDeployUsesOwnedPathFreeRequest(t *testing.T) {
	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("export default {}")}},
		[]opscloudflarepayload.Asset{{Path: "index.html", Bytes: []byte("approved asset")}},
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := opscloudflarepayload.NewRequest("account", "worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("bounded-test-token")
	provider := &productionTokenProvider{token: append([]byte(nil), token...)}
	transport := &recordingProductionTransport{}
	client, err := opscloudflarepayload.NewClient(provider, transport)
	if err != nil {
		t.Fatal(err)
	}

	payload.Modules[0].Bytes[0] = 'X'
	payload.Assets[0].Bytes[0] = 'X'
	token[0] = 'X'
	evidence, err := client.Deploy(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	if provider.calls != 1 || transport.calls != 1 {
		t.Fatalf("provider calls=%d transport calls=%d", provider.calls, transport.calls)
	}
	if got := string(transport.token); got != "bounded-test-token" {
		t.Fatalf("transport received mutable token: %q", got)
	}
	if transport.request.AccountID != "account" || transport.request.Worker != "worker" {
		t.Fatalf("unexpected production identity: %#v", transport.request)
	}
	if transport.request.ExpectedSHA256 != payload.SHA256 || evidence.InputSHA256 != payload.SHA256 {
		t.Fatalf("digest evidence mismatch: request=%q evidence=%q", transport.request.ExpectedSHA256, evidence.InputSHA256)
	}
	if got := string(transport.request.Payload.Metadata); !strings.Contains(got, `"profile":"wrangler-4.107-preveal-v1"`) {
		t.Fatalf("canonical metadata missing: %q", got)
	}
	if got := string(transport.request.Payload.Modules[0].Bytes); got != "export default {}" {
		t.Fatalf("transport received mutable module: %q", got)
	}
	if got := string(transport.request.Payload.Assets[0].Bytes); got != "approved asset" {
		t.Fatalf("transport received mutable asset: %q", got)
	}
}

func TestProductionRequestContainsNoProcessPathOrEnvironmentFields(t *testing.T) {
	requestType := reflect.TypeOf(opscloudflarepayload.Request{})
	for index := 0; index < requestType.NumField(); index++ {
		name := strings.ToLower(requestType.Field(index).Name)
		for _, forbidden := range []string{"path", "file", "directory", "executable", "program", "command", "argv", "argument", "environment", "env", "wrangler", "shell"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("production request exposes forbidden field %q", requestType.Field(index).Name)
			}
		}
	}
}

func TestProductionClientRejectsMissingAndOversizedTokenBeforeTransport(t *testing.T) {
	request := productionClientRequest(t, time.Second)
	for _, test := range []struct {
		name  string
		token []byte
	}{
		{name: "missing", token: nil},
		{name: "whitespace", token: []byte(" \n\t")},
		{name: "oversized", token: []byte(strings.Repeat("x", 1<<20))},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &recordingProductionTransport{}
			client, err := opscloudflarepayload.NewClient(&productionTokenProvider{token: test.token}, transport)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Deploy(context.Background(), request); err == nil {
				t.Fatal("invalid production token was accepted")
			}
			if transport.calls != 0 {
				t.Fatalf("invalid token reached transport %d times", transport.calls)
			}
		})
	}
}

func TestProductionClientBoundsDeployTimeout(t *testing.T) {
	request := productionClientRequest(t, 10*time.Millisecond)
	client, err := opscloudflarepayload.NewClient(&productionTokenProvider{token: []byte("token")}, blockingProductionTransport{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Deploy(context.Background(), request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestProductionClientPropagatesCancellationBeforeReadingToken(t *testing.T) {
	request := productionClientRequest(t, time.Second)
	provider := &productionTokenProvider{token: []byte("token")}
	transport := &recordingProductionTransport{}
	client, err := opscloudflarepayload.NewClient(provider, transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Deploy(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if provider.calls != 0 || transport.calls != 0 {
		t.Fatalf("cancelled deploy read token %d times and called transport %d times", provider.calls, transport.calls)
	}
}

func TestProductionClientRejectsPayloadMutationAfterPreviewBeforeReadingToken(t *testing.T) {
	request := productionClientRequest(t, time.Second)
	request.Payload.Modules[0].Bytes[0] = 'X'
	provider := &productionTokenProvider{token: []byte("token")}
	transport := &recordingProductionTransport{}
	client, err := opscloudflarepayload.NewClient(provider, transport)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Deploy(context.Background(), request); err == nil {
		t.Fatal("stale preview payload was accepted")
	}
	if provider.calls != 0 || transport.calls != 0 {
		t.Fatalf("stale payload read token %d times and called transport %d times", provider.calls, transport.calls)
	}
}

func TestProductionClientRetainedDescriptorCannotChangePreparedPayload(t *testing.T) {
	root := t.TempDir()
	modulePath := filepath.Join(root, "worker.mjs")
	if err := os.WriteFile(modulePath, []byte("approved"), 0o600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.OpenFile(modulePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	moduleBytes, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: moduleBytes}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := opscloudflarepayload.NewRequest("account", "worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	provider := &productionTokenProvider{token: []byte("token")}
	transport := &recordingProductionTransport{}
	client, err := opscloudflarepayload.NewClient(provider, transport)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := retained.WriteAt([]byte("mutated!"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Deploy(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := string(transport.request.Payload.Modules[0].Bytes); got != "approved" {
		t.Fatalf("retained descriptor changed prepared payload: %q", got)
	}
	if transport.request.ExpectedSHA256 != payload.SHA256 {
		t.Fatalf("prepared payload digest changed: got %q want %q", transport.request.ExpectedSHA256, payload.SHA256)
	}
}

func TestProductionClientPreservesUnknownRemoteStateEvidence(t *testing.T) {
	request := productionClientRequest(t, time.Second)
	want := opscloudflarepayload.Evidence{
		RemoteWritePossible: true,
		RequestID:           "22222222-2222-4222-8222-222222222222",
		VersionIDs:          []string{"11111111-1111-4111-8111-111111111111"},
		InputSHA256:         request.ExpectedSHA256,
	}
	transport := &recordingProductionTransport{evidence: want, err: errors.New("identity read failed")}
	client, err := opscloudflarepayload.NewClient(&productionTokenProvider{token: []byte("token")}, transport)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Deploy(context.Background(), request)
	if err == nil {
		t.Fatal("transport failure was reported as success")
	}
	if !got.RemoteWritePossible || got.RequestID != want.RequestID || !reflect.DeepEqual(got.VersionIDs, want.VersionIDs) {
		t.Fatalf("unknown-state evidence was lost: %#v", got)
	}
}

type productionTokenProvider struct {
	token []byte
	calls int
}

func (p *productionTokenProvider) Token(context.Context) ([]byte, error) {
	p.calls++
	return append([]byte(nil), p.token...), nil
}

func (p *productionTokenProvider) Identity() string { return "environment" }

type recordingProductionTransport struct {
	calls    int
	token    []byte
	request  opscloudflarepayload.Request
	evidence opscloudflarepayload.Evidence
	err      error
}

func (r *recordingProductionTransport) Deploy(_ context.Context, token []byte, request opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	r.calls++
	r.token = append([]byte(nil), token...)
	r.request = request
	now := time.Now()
	if r.evidence.RemoteWritePossible || r.err != nil {
		return r.evidence, r.err
	}
	return opscloudflarepayload.Evidence{
		ClientVersion: "fake-v1", RequestID: "request-1", InputSHA256: request.ExpectedSHA256,
		StartedAt: now, FinishedAt: now,
	}, nil
}

type blockingProductionTransport struct{}

func (blockingProductionTransport) Deploy(ctx context.Context, _ []byte, _ opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error) {
	<-ctx.Done()
	return opscloudflarepayload.Evidence{}, ctx.Err()
}

func productionClientRequest(t *testing.T, timeout time.Duration) opscloudflarepayload.Request {
	t.Helper()
	payload := contractTestPayload(t)
	request, err := opscloudflarepayload.NewRequest("account", "worker", payload.SHA256, payload, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
