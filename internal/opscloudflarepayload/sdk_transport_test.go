package opscloudflarepayload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSDKProductionTransportUploadsRequestedAssetsBeforeVersion(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.RequestURI())
		if writeEmptyEndpointRead(response, request) {
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		response.Header().Set("Content-Type", "application/json")
		switch len(paths) - 3 {
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
		case 5:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[{"version_id":"11111111-1111-4111-8111-111111111111","percentage":100}]}}`))
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
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /accounts/account/workers/domains?service=worker",
		"GET /accounts/account/workers/scripts/worker/schedules",
		"GET /accounts/account/workers/scripts/worker/deployments",
		"POST /accounts/account/workers/scripts/worker/assets-upload-session",
		"POST /accounts/account/workers/assets/upload?base64=true",
		"POST /accounts/account/workers/workers/worker/versions?deploy=false",
		"POST /accounts/account/workers/scripts/worker/deployments",
		"GET /accounts/account/workers/scripts/worker/deployments/22222222-2222-4222-8222-222222222222",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, want)
	}
}

func TestSDKProductionTransportUsesTypedVersionThenDeploymentEndpoints(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if writeEmptyEndpointRead(response, request) {
			return
		}
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
		switch len(paths) - 3 {
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
		case 3:
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[{"version_id":"11111111-1111-4111-8111-111111111111","percentage":100}]}}`))
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
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"GET /accounts/account/workers/domains",
		"GET /accounts/account/workers/scripts/worker/schedules",
		"GET /accounts/account/workers/scripts/worker/deployments",
		"POST /accounts/account/workers/scripts/worker/versions",
		"POST /accounts/account/workers/scripts/worker/deployments",
		"GET /accounts/account/workers/scripts/worker/deployments/22222222-2222-4222-8222-222222222222",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, wantPaths)
	}
	if evidence.ClientVersion != "cloudflare-go/v7.7.0" || evidence.RequestID != "22222222-2222-4222-8222-222222222222" || evidence.InputSHA256 != payload.SHA256 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
}

func TestSDKProductionTransportChecksEndpointsReadOnlyBeforeWriting(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch len(paths) {
		case 1:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[{"id":"domain","hostname":"admin.example.test","service":"worker","environment":"production","cert_id":"44444444-4444-4444-8444-444444444444","zone_id":"zone","zone_name":"example.test"}]}`))
		case 2:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"schedules":[{"cron":"*/30 * * * *"}]}}`))
		case 3:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]}}`))
		case 4:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"11111111-1111-4111-8111-111111111111","resources":{}}}`))
		case 5:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		case 6:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[{"version_id":"11111111-1111-4111-8111-111111111111","percentage":100}]}}`))
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
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET /accounts/account/workers/domains?service=worker",
		"GET /accounts/account/workers/scripts/worker/schedules",
		"GET /accounts/account/workers/scripts/worker/deployments",
		"POST /accounts/account/workers/scripts/worker/versions",
		"POST /accounts/account/workers/scripts/worker/deployments",
		"GET /accounts/account/workers/scripts/worker/deployments/22222222-2222-4222-8222-222222222222",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("endpoint sequence=%v want=%v", paths, want)
	}
}

func TestSDKProductionTransportRejectsEndpointDriftBeforeAnyWrite(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[]}`))
	}))
	defer server.Close()

	config := CanonicalConfig{
		Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15",
		Routes: []RouteConfig{{Pattern: "admin.example.test", CustomDomain: true}},
	}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err == nil {
		t.Fatal("endpoint drift was accepted")
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("endpoint drift caused remote write: %v", methods)
		}
	}
}

func TestSDKProductionTransportRejectsUnmappedNoAssetConfigurationBeforeNetwork(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CanonicalConfig)
	}{
		{name: "KV", mutate: func(c *CanonicalConfig) {
			c.KVNamespaces = []KVNamespace{{Binding: "CACHE", ID: strings.Repeat("1", 32)}}
		}},
		{name: "D1", mutate: func(c *CanonicalConfig) {
			c.D1Databases = []D1Database{{Binding: "DB", DatabaseName: "db", DatabaseID: "11111111-1111-4111-8111-111111111111"}}
		}},
		{name: "R2", mutate: func(c *CanonicalConfig) { c.R2Buckets = []R2Bucket{{Binding: "MEDIA", BucketName: "media"}} }},
		{name: "AI", mutate: func(c *CanonicalConfig) { c.AI = &AIBinding{Binding: "AI"} }},
		{name: "Vectorize", mutate: func(c *CanonicalConfig) { c.Vectorize = []VectorizeIndex{{Binding: "SEARCH", IndexName: "index"}} }},
		{name: "Durable Objects", mutate: func(c *CanonicalConfig) { c.DurableObjects = []DurableObject{{Name: "RUNNER", ClassName: "Runner"}} }},
		{name: "migration", mutate: func(c *CanonicalConfig) { c.Migrations = []Migration{{Tag: "v1", NewClasses: []string{"Runner"}}} }},
		{name: "vars", mutate: func(c *CanonicalConfig) { c.Vars = map[string]string{"MODE": "production"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			defer server.Close()
			config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
			test.mutate(&config)
			payload := payloadForConfig(t, config, nil)
			request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err == nil {
				t.Fatal("unmapped no-asset configuration was accepted")
			}
			if calls != 0 {
				t.Fatalf("unmapped no-asset configuration reached network %d times", calls)
			}
		})
	}
}

func TestEndpointSequenceIsProfileOwnedAndStrict(t *testing.T) {
	config := CanonicalConfig{
		Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15",
		Assets: &AssetsConfig{Binding: "ASSETS", RunWorkerFirst: true, NotFoundHandling: "single-page-application"},
		Routes: []RouteConfig{{Pattern: "admin.example.test", CustomDomain: true}}, Crons: []string{"*/30 * * * *"},
	}
	payload := payloadForConfig(t, config, []Asset{{Path: "index.html", Bytes: []byte("approved")}})
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{endpointDomainsRead, endpointSchedulesRead, endpointCurrentDeploymentRead, endpointAssetSession, endpointAssetUpload, endpointVersionCreate, endpointDeploymentCreate, endpointIdentityRead}
	got, err := EndpointSequence(request)
	if err != nil || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("sequence=%v err=%v", got, err)
	}
	guard, err := newEndpointSequenceGuard(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.consume(endpointSchedulesRead); err == nil {
		t.Fatal("reordered endpoint was accepted")
	}
	guard, _ = newEndpointSequenceGuard(request)
	if err := guard.consume(endpointDomainsRead); err != nil {
		t.Fatal(err)
	}
	if err := guard.complete(); err == nil {
		t.Fatal("incomplete endpoint sequence was accepted")
	}
	guard, _ = newEndpointSequenceGuard(request)
	for _, endpoint := range want {
		if err := guard.consume(endpoint); err != nil {
			t.Fatal(err)
		}
	}
	if err := guard.complete(); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointSequenceRequiresEmptyRemoteStateReads(t *testing.T) {
	config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{endpointDomainsRead, endpointSchedulesRead, endpointCurrentDeploymentRead, endpointVersionCreate, endpointDeploymentCreate, endpointIdentityRead}
	got, err := EndpointSequence(request)
	if err != nil || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("empty endpoint policy sequence=%v want=%v err=%v", got, want, err)
	}
}

func TestSDKProductionTransportRejectsChangedCurrentDeploymentBeforeAnyWrite(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && (strings.Contains(request.URL.Path, "/workers/domains") || strings.HasSuffix(request.URL.Path, "/schedules")) && writeEmptyEndpointRead(response, request) {
			return
		}
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"22222222-2222-4222-8222-222222222222","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]}}`))
	}))
	defer server.Close()

	config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err == nil {
		t.Fatal("changed current deployment was accepted")
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("changed current deployment caused remote write: %v", methods)
		}
	}
}

func TestSDKProductionTransportRejectsChangedCurrentVersionSetBeforeAnyWrite(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writes.Add(1)
		}
		if request.Method == http.MethodGet && (strings.Contains(request.URL.Path, "/workers/domains") || strings.HasSuffix(request.URL.Path, "/schedules")) && writeEmptyEndpointRead(response, request) {
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]}]}}`))
	}))
	defer server.Close()

	config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request); err == nil {
		t.Fatal("changed current version set was accepted")
	}
	if writes.Load() != 0 {
		t.Fatalf("changed current version set caused %d remote writes", writes.Load())
	}
}

func TestSDKProductionTransportRollbackRejectsChangedCurrentDeploymentBeforeAnyWrite(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"22222222-2222-4222-8222-222222222222","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]}}`))
	}))
	defer server.Close()

	request, err := NewRollbackRequest("account", "worker", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111", strings.Repeat("4", 64), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSDKProductionTransport(server.URL+"/").Rollback(context.Background(), []byte("bounded-test-token"), request); err == nil {
		t.Fatal("changed current rollback deployment was accepted")
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("changed current rollback deployment caused remote write: %v", methods)
		}
	}
}

func TestSDKProductionTransportRejectsUnreadableCurrentDeploymentBeforeAnyWrite(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
		write   func(http.ResponseWriter, *http.Request)
	}{
		{name: "malformed", timeout: time.Second, write: func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write([]byte(`{`)) }},
		{name: "timeout", timeout: 20 * time.Millisecond, write: func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet {
					writes.Add(1)
				}
				if request.Method == http.MethodGet && (strings.Contains(request.URL.Path, "/workers/domains") || strings.HasSuffix(request.URL.Path, "/schedules")) && writeEmptyEndpointRead(response, request) {
					return
				}
				response.Header().Set("Content-Type", "application/json")
				test.write(response, request)
			}))
			defer server.Close()
			config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
			payload := payloadForConfig(t, config, nil)
			request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, test.timeout)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			if _, err := newSDKProductionTransport(server.URL+"/").Deploy(ctx, []byte("bounded-test-token"), request); err == nil {
				t.Fatal("unreadable current deployment was accepted")
			}
			if writes.Load() != 0 {
				t.Fatalf("unreadable current deployment caused %d remote writes", writes.Load())
			}
		})
	}
}

func TestSDKProductionTransportRollbackRejectsUnreadableCurrentDeploymentBeforeAnyWrite(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
		write   func(http.ResponseWriter, *http.Request)
	}{
		{name: "malformed", timeout: time.Second, write: func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write([]byte(`{`)) }},
		{name: "timeout", timeout: 20 * time.Millisecond, write: func(_ http.ResponseWriter, request *http.Request) { <-request.Context().Done() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet {
					writes.Add(1)
				}
				response.Header().Set("Content-Type", "application/json")
				test.write(response, request)
			}))
			defer server.Close()
			request, err := NewRollbackRequest("account", "worker", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111", strings.Repeat("4", 64), test.timeout)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			if _, err := newSDKProductionTransport(server.URL+"/").Rollback(ctx, []byte("bounded-test-token"), request); err == nil {
				t.Fatal("unreadable current rollback deployment was accepted")
			}
			if writes.Load() != 0 {
				t.Fatalf("unreadable current rollback deployment caused %d remote writes", writes.Load())
			}
		})
	}
}

func TestSDKProductionTransportRejectsUndeclaredRemoteEndpointBeforeAnyWrite(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		methods = append(methods, request.Method)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[{"id":"domain","hostname":"unexpected.example.test","service":"worker","environment":"production"}]}`))
	}))
	defer server.Close()
	config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request)
	if err == nil || evidence.RemoteWritePossible {
		t.Fatalf("undeclared remote endpoint was accepted: evidence=%#v err=%v", evidence, err)
	}
	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("undeclared endpoint caused remote write: %v", methods)
		}
	}
}

func payloadForConfig(t *testing.T, config CanonicalConfig, assets []Asset) Payload {
	t.Helper()
	metadata, err := config.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := NewPayload("worker.mjs", []Module{{Name: "worker.mjs", Type: "application/javascript+module", Bytes: []byte("approved module")}}, assets, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return payload
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
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]}]}}`))
		case 2:
			if !strings.Contains(string(body), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || !strings.Contains(string(body), "100") {
				t.Fatalf("rollback deployment missing explicit target: %s", body)
			}
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","created_on":"2026-09-15T00:00:00Z","source":"api","strategy":"percentage","versions":[]}}`))
		case 3:
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
		"GET /accounts/account/workers/scripts/worker/deployments",
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

func TestSDKProductionTransportPreservesDeployIdentityOnReadbackFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if writeEmptyEndpointRead(response, request) {
			return
		}
		calls++
		response.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"11111111-1111-4111-8111-111111111111","resources":{}}}`))
		case 2:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","versions":[]}}`))
		default:
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":null}`))
		}
	}))
	defer server.Close()
	config := CanonicalConfig{Profile: supportedProfile, Name: "worker", AccountID: "account", Main: "worker.mjs", CompatibilityDate: "2026-09-15"}
	payload := payloadForConfig(t, config, nil)
	request, err := NewRequest("account", "worker", "11111111-1111-4111-8111-111111111111", []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}, payload.SHA256, payload, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Deploy(context.Background(), []byte("bounded-test-token"), request)
	if err == nil {
		t.Fatal("failed identity read was reported as success")
	}
	if !evidence.RemoteWritePossible || evidence.RequestID != "22222222-2222-4222-8222-222222222222" || len(evidence.VersionIDs) != 1 || evidence.VersionIDs[0] != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("deploy unknown-state evidence was lost: %#v", evidence)
	}
}

func writeEmptyEndpointRead(response http.ResponseWriter, request *http.Request) bool {
	response.Header().Set("Content-Type", "application/json")
	if request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/workers/domains") {
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":[]}`))
		return true
	}
	if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/schedules") {
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"schedules":[]}}`))
		return true
	}
	if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/deployments") {
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}]}}`))
		return true
	}
	return false
}

func TestSDKProductionTransportPreservesRollbackIdentityOnReadbackFailure(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/deployments") {
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"deployments":[{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","percentage":100}]}]}}`))
			return
		}
		calls++
		if calls == 1 {
			_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"id":"22222222-2222-4222-8222-222222222222","versions":[]}}`))
			return
		}
		_, _ = response.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":null}`))
	}))
	defer server.Close()
	request, err := NewRollbackRequest("account", "worker", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111", strings.Repeat("4", 64), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := newSDKProductionTransport(server.URL+"/").Rollback(context.Background(), []byte("bounded-test-token"), request)
	if err == nil {
		t.Fatal("failed rollback identity read was reported as success")
	}
	if !evidence.RemoteWritePossible || evidence.RequestID != "22222222-2222-4222-8222-222222222222" || len(evidence.VersionIDs) != 1 || evidence.VersionIDs[0] != request.TargetVersionID {
		t.Fatalf("rollback unknown-state evidence was lost: %#v", evidence)
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
