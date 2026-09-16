package opscloudflarepayload_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

func TestBuildPayloadOwnsConfiguredModuleAssetsAndCanonicalMetadata(t *testing.T) {
	root := t.TempDir()
	writePayloadFixture(t, root, "wrangler.jsonc", `{
  "name": "example-worker",
  "account_id": "0123456789abcdef0123456789abcdef",
  "main": "src/index.mjs",
  "compatibility_date": "2026-09-15",
  "workers_dev": false,
  "preview_urls": false,
  "assets": {"directory": "public", "binding": "ASSETS", "not_found_handling": "single-page-application"}
}`)
	writePayloadFixture(t, root, "src/index.mjs", "export default { fetch() { return new Response('ok') } }")
	writePayloadFixture(t, root, ".agentops-production-bundle/index.js", "var bundled = true; export { bundled as default };")
	writePayloadFixture(t, root, "public/index.html", "<html>approved</html>")

	payload, config, err := opscloudflarepayload.BuildPayload(root, "wrangler.jsonc", ".agentops-production-bundle", "wrangler-4.107-preveal-v1")
	if err != nil {
		t.Fatal(err)
	}
	if config.Profile != "wrangler-4.107-preveal-v1" || payload.MainModule != "index.js" || len(payload.Modules) != 1 || string(payload.Modules[0].Bytes) != "var bundled = true; export { bundled as default };" || len(payload.Assets) != 1 || payload.Assets[0].Path != "index.html" || payload.SHA256 == "" {
		t.Fatalf("config=%+v payload=%+v", config, payload)
	}
}

func TestBuildPayloadRejectsMissingOrAmbiguousWranglerBundle(t *testing.T) {
	for _, test := range []struct {
		name  string
		files map[string]string
	}{
		{name: "missing", files: nil},
		{name: "multiple modules", files: map[string]string{"index.js": "one", "second.mjs": "two"}},
		{name: "raw source only", files: map[string]string{"index.ts": "raw source"}},
		{name: "source map", files: map[string]string{"index.js": "bundled", "index.js.map": "{}"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writePayloadFixture(t, root, "wrangler.jsonc", `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","main":"src/index.ts","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`)
			writePayloadFixture(t, root, "src/index.ts", "raw source")
			for name, content := range test.files {
				writePayloadFixture(t, root, filepath.Join(".agentops-production-bundle", name), content)
			}
			if _, _, err := opscloudflarepayload.BuildPayload(root, "wrangler.jsonc", ".agentops-production-bundle", "wrangler-4.107-preveal-v1"); err == nil {
				t.Fatal("invalid Wrangler bundle entered the production payload")
			}
		})
	}
}

func TestValidateWranglerVersionForProfile(t *testing.T) {
	if err := opscloudflarepayload.ValidateWranglerVersion("wrangler-4.107-preveal-v1", "4.107.3"); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"4.106.0", "4.108.0", "5.107.0", "4.107.0-beta.1"} {
		if err := opscloudflarepayload.ValidateWranglerVersion("wrangler-4.107-preveal-v1", version); err == nil {
			t.Fatalf("unsupported Wrangler version accepted: %s", version)
		}
	}
}

func TestBuildPayloadRejectsAssetSymlink(t *testing.T) {
	root := t.TempDir()
	writePayloadFixture(t, root, "wrangler.jsonc", `{
  "name": "example-worker",
  "account_id": "0123456789abcdef0123456789abcdef",
  "main": "src/index.mjs",
  "compatibility_date": "2026-09-15",
  "workers_dev": false,
  "preview_urls": false,
  "assets": {"directory": "public", "binding": "ASSETS", "not_found_handling": "single-page-application"}
}`)
	writePayloadFixture(t, root, "src/index.mjs", "export default {}")
	writePayloadFixture(t, root, ".agentops-production-bundle/index.js", "export default {}")
	external := filepath.Join(t.TempDir(), "private.txt")
	writePayloadFixture(t, filepath.Dir(external), filepath.Base(external), "private")
	if err := os.MkdirAll(filepath.Join(root, "public"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "public", "escape.txt")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := opscloudflarepayload.BuildPayload(root, "wrangler.jsonc", ".agentops-production-bundle", "wrangler-4.107-preveal-v1"); err == nil {
		t.Fatal("asset symlink entered the production payload")
	}
}

func writePayloadFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
