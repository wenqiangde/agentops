package opscloudflarepayload_test

import (
	"bytes"
	"testing"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestCaptureOwnsCanonicalModulesAssetsAndMetadata(t *testing.T) {
	moduleBytes := []byte("export default { fetch() { return new Response('ok') } }")
	assetBytes := []byte("<html>approved</html>")
	metadata := []byte(`{"profile":"wrangler-4.107-preveal-v1","name":"example-worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","compatibility_flags":["nodejs_compat"],"workers_dev":false,"preview_urls":false}`)

	payload, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: moduleBytes}},
		[]opscloudflarepayload.Asset{{Path: "index.html", Bytes: assetBytes}},
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := payload.SHA256

	moduleBytes[0] = 'X'
	assetBytes[0] = 'X'
	metadata[0] = 'X'
	if got := payload.Modules[0].Bytes; bytes.HasPrefix(got, []byte("X")) {
		t.Fatalf("module bytes share caller storage: %q", got)
	}
	if got := payload.Assets[0].Bytes; bytes.HasPrefix(got, []byte("X")) {
		t.Fatalf("asset bytes share caller storage: %q", got)
	}
	if bytes.HasPrefix(payload.Metadata, []byte("X")) {
		t.Fatalf("metadata shares caller storage: %q", payload.Metadata)
	}
	if payload.SHA256 != wantDigest || payload.SHA256 == "" {
		t.Fatalf("payload digest changed: got %q want %q", payload.SHA256, wantDigest)
	}
}

func TestCaptureRejectsUnsupportedModuleType(t *testing.T) {
	_, err := opscloudflarepayload.NewPayload(
		"worker.py",
		[]opscloudflarepayload.Module{{Name: "worker.py", Type: "text/x-python", Bytes: []byte("print('no')")}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"example-worker","account_id":"account","main":"worker.py","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err == nil {
		t.Fatal("unsupported module type was accepted")
	}
}

func TestCaptureRejectsUnknownWranglerMetadata(t *testing.T) {
	_, err := opscloudflarepayload.NewPayload(
		"worker.mjs",
		[]opscloudflarepayload.Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("export default {}")}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false,"unknown_key":true}`),
	)
	if err == nil {
		t.Fatal("unknown Wrangler metadata was accepted")
	}
}
