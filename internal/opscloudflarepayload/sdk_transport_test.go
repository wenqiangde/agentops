package opscloudflarepayload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSDKProductionTransportUploadsRequestedAssetsBeforeVersion(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.RequestURI())
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		switch len(paths) {
		case 1:
			var envelope struct {
				Manifest map[string]struct {
					Hash string `json:"hash"`
					Size int64  `json:"size"`
				} `json:"manifest"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("manifest is not JSON: %v", err)
			}
			asset := envelope.Manifest["/index.html"]
			if asset.Size != int64(len("<html>approved</html>")) || len(asset.Hash) != 32 {
				t.Fatalf("unexpected asset manifest: %#v", envelope.Manifest)
			}
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"jwt":"upload-jwt","buckets":[["` + asset.Hash + `"]]}}`))
		case 2:
			if request.Header.Get("Authorization") != "Bearer upload-jwt" || !strings.Contains(string(body), "PGh0bWw+YXBwcm92ZWQ8L2h0bWw+") {
				t.Fatalf("asset batch is not bounded to upload session: auth=%q body=%s", request.Header.Get("Authorization"), body)
			}
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"jwt":"completion-jwt"}}`))
		case 3:
			if !strings.Contains(string(body), "completion-jwt") || !strings.Contains(string(body), "worker.mjs") {
				t.Fatalf("version request missing completion token or module: %s", body)
			}
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"11111111-1111-4111-8111-111111111111","resources":{}}}`))
		case 4:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		default:
			t.Fatalf("unexpected SDK request %s", request.URL.Path)
		}
	}))
	defer server.Close()

	config := CanonicalConfig{
		Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs",
		CompatibilityDate: "2026-09-15", Assets: &AssetsConfig{Binding: "ASSETS", RunWorkerFirst: true, NotFoundHandling: "single-page-application"},
	}
	metadata, err := config.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NewPayload("worker.mjs", []Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}}, []Asset{{Path: "index.html", Bytes: []byte("<html>approved</html>")}}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("account", "worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /accounts/account/workers/scripts/worker/assets-upload-session",
		"POST /accounts/account/workers/assets/upload?base64=true",
		"POST /accounts/account/workers/workers/worker/versions?deploy=false",
		"POST /accounts/account/workers/scripts/worker/deployments",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, want)
	}
}

func TestSDKProductionTransportUsesTypedVersionThenDeploymentEndpoints(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer bounded-test-token" {
			t.Fatalf("unexpected authorization header")
		}
		if request.Header.Get("X-Auth-Key") != "" || request.Header.Get("X-Auth-Email") != "" {
			t.Fatal("SDK transport inherited broad Cloudflare credentials")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch len(paths) {
		case 1:
			if !strings.Contains(string(body), "approved module") || !strings.Contains(string(body), "worker.mjs") {
				t.Fatalf("version upload missing owned module: %s", body)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"11111111-1111-4111-8111-111111111111","resources":{}}}`))
		case 2:
			if !strings.Contains(string(body), "11111111-1111-4111-8111-111111111111") || !strings.Contains(string(body), "100") {
				t.Fatalf("deployment missing created version: %s", body)
			}
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		default:
			t.Fatalf("unexpected SDK request %s", request.URL.Path)
		}
	}))
	defer server.Close()

	payload, err := NewPayload(
		"worker.mjs",
		[]Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}},
		nil,
		[]byte(`{"profile":"wrangler-4.107-preveal-v1","name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("account", "worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"POST /accounts/account/workers/scripts/worker/versions",
		"POST /accounts/account/workers/scripts/worker/deployments",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, wantPaths)
	}
	if evidence.ClientVersion != "cloudflare-go/v7.7.0" || evidence.RequestID != "22222222-2222-4222-8222-222222222222" || evidence.InputSHA256 != payload.SHA256 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestSDKProductionTransportReconcilesAndReadsPostWriteIdentity(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch len(paths) {
		case 1:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"11111111-1111-4111-8111-111111111111","resources":{}}}`))
		case 2:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		case 3:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[{"id":"old-domain","hostname":"old.example.test","service":"worker","environment":"production","cert_id":"33333333-3333-4333-8333-333333333333","zone_id":"zone","zone_name":"example.test"}]}`))
		case 4:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`))
		case 5:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"new-domain","hostname":"admin.example.test","service":"worker","environment":"production","cert_id":"44444444-4444-4444-8444-444444444444","zone_id":"zone","zone_name":"example.test"}}`))
		case 6:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"schedules":[{"cron":"*/30 * * * *"}]}}`))
		case 7:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[{"version_id":"11111111-1111-4111-8111-111111111111","percentage":100}]}}`))
		case 8:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"schedules":[{"cron":"*/30 * * * *"}]}}`))
		case 9:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[{"id":"new-domain","hostname":"admin.example.test","service":"worker","environment":"production","cert_id":"44444444-4444-4444-8444-444444444444","zone_id":"zone","zone_name":"example.test"}]}`))
		default:
			t.Fatalf("unexpected request %s", request.URL.RequestURI())
		}
	}))
	defer server.Close()

	config := CanonicalConfig{
		Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15",
		Routes: []RouteConfig{{Pattern: "admin.example.test", CustomDomain: true}}, Crons: []string{"*/30 * * * *"},
	}
	metadata, err := config.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NewPayload("worker.mjs", []Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}}, nil, metadata)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewRequest("account", "worker", payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /accounts/account/workers/scripts/worker/versions",
		"POST /accounts/account/workers/scripts/worker/deployments",
		"GET /accounts/account/workers/domains?service=worker",
		"DELETE /accounts/account/workers/domains/old-domain",
		"PUT /accounts/account/workers/domains",
		"PUT /accounts/account/workers/scripts/worker/schedules",
		"GET /accounts/account/workers/scripts/worker/deployments/22222222-2222-4222-8222-222222222222",
		"GET /accounts/account/workers/scripts/worker/schedules",
		"GET /accounts/account/workers/domains?service=worker",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, want)
	}
}

func TestSDKProductionTransportRollbackCreatesAndVerifiesExplicitVersionDeployment(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer bounded-test-token" {
			t.Fatal("unexpected authorization header")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		switch len(paths) {
		case 1:
			if !strings.Contains(string(body), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || !strings.Contains(string(body), "100") {
				t.Fatalf("rollback deployment missing explicit target: %s", body)
			}
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		case 2:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}}`))
		default:
			t.Fatalf("unexpected request %s", request.URL.RequestURI())
		}
	}))
	defer server.Close()

	request, err := NewRollbackRequest("account", "worker", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111", strings.Repeat("4", 64), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Rollback(context.Background(), []byte("bounded-test-token"), request)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /accounts/account/workers/scripts/worker/deployments",
		"GET /accounts/account/workers/scripts/worker/deployments/22222222-2222-4222-8222-222222222222",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, want)
	}
	if evidence.RequestID != "22222222-2222-4222-8222-222222222222" || len(evidence.VersionIDs) != 1 || evidence.VersionIDs[0] != request.TargetVersionID || evidence.InputSHA256 != request.ExpectedSHA256 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestSDKProductionTransportMapsCompleteRelayVersionFields(t *testing.T) {
	config, payload := completeRelayFixture(t)
	version, err := versionParamFor(config, payload, "completion-jwt")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"type":"kv_namespace"`, `"namespace_id":"11111111111111111111111111111111"`,
		`"type":"d1"`, `"database_id":"11111111-1111-4111-8111-111111111111"`,
		`"type":"r2_bucket"`, `"bucket_name":"example-media"`, `"type":"ai"`,
		`"type":"vectorize"`, `"index_name":"example-index"`,
		`"type":"durable_object_namespace"`, `"class_name":"RunnerDO"`,
		`"type":"plain_text"`, `"text":"production"`,
		`"new_tag":"v1"`, `"new_sqlite_classes":["RunnerDO"]`,
	} {
		if !strings.Contains(string(body), required) {
			t.Fatalf("version metadata missing %s: %s", required, body)
		}
	}
}

func TestSDKProductionTransportAcceptsCompleteRelayProfile(t *testing.T) {
	config, payload := completeRelayFixture(t)
	if !sdkProfileSupported(config, payload) {
		t.Fatal("complete Relay profile is not mapped to the trusted SDK transport")
	}
}

func completeRelayFixture(t *testing.T) (CanonicalConfig, Payload) {
	t.Helper()
	config := CanonicalConfig{
		Profile: supportedProfile, Name: "example-relay", AccountID: "account", Main: "worker.mjs",
		CompatibilityDate: "2026-09-15", CompatibilityFlags: []string{"nodejs_compat"},
		Assets: &AssetsConfig{Directory: "../admin/dist", Binding: "ADMIN_ASSETS", RunWorkerFirst: true, NotFoundHandling: "single-page-application"},
		Routes: []RouteConfig{{Pattern: "admin.example.test", CustomDomain: true}}, Crons: []string{"*/30 * * * *"},
		KVNamespaces:   []KVNamespace{{Binding: "CACHE", ID: "11111111111111111111111111111111"}},
		D1Databases:    []D1Database{{Binding: "DB", DatabaseName: "example-db", DatabaseID: "11111111-1111-4111-8111-111111111111", MigrationsDir: "migrations"}},
		R2Buckets:      []R2Bucket{{Binding: "MEDIA", BucketName: "example-media"}},
		AI:             &AIBinding{Binding: "AI"},
		Vectorize:      []VectorizeIndex{{Binding: "SEARCH", IndexName: "example-index"}},
		DurableObjects: []DurableObject{{Name: "RUNNER", ClassName: "RunnerDO"}},
		Migrations:     []Migration{{Tag: "v1", NewSQLiteClasses: []string{"RunnerDO"}}},
		Vars:           map[string]string{"MODE": "production"},
	}
	metadata, err := config.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NewPayload(
		"worker.mjs",
		[]Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("export default {}")}},
		[]Asset{{Path: "index.html", Bytes: []byte("<html>approved</html>")}},
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	return config, payload
}
