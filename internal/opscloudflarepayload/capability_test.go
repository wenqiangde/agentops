package opscloudflarepayload_test

import (
	"bytes"
	"testing"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

const supportedWranglerJSONC = `{
  // The first production profile accepts JSONC comments and trailing commas.
  "name": "example-worker",
  "account_id": "00000000000000000000000000000000",
  "main": "src/worker.mjs",
  "compatibility_date": "2026-09-15",
  "compatibility_flags": ["nodejs_compat",],
  "workers_dev": false,
  "preview_urls": false,
  "assets": {
    "directory": "../web/dist",
    "binding": "STATIC_ASSETS",
    "run_worker_first": true,
    "not_found_handling": "single-page-application",
  },
  "routes": [{"pattern": "api.example.test", "custom_domain": true}],
  "triggers": {"crons": ["*/30 * * * *"]},
  "kv_namespaces": [{"binding": "CACHE", "id": "11111111111111111111111111111111"}],
  "d1_databases": [{"binding": "DB", "database_name": "example-db", "database_id": "22222222-2222-2222-2222-222222222222", "migrations_dir": "migrations"}],
  "r2_buckets": [{"binding": "MEDIA", "bucket_name": "example-media"}],
  "ai": {"binding": "AI"},
  "vectorize": [{"binding": "SEARCH", "index_name": "example-index"}],
  "durable_objects": {"bindings": [{"name": "RUNNER", "class_name": "RunnerDO"}]},
  "migrations": [
    {"tag": "v1", "new_sqlite_classes": ["RunnerDO"]},
    {"tag": "v2", "renamed_classes": [{"from": "RunnerDO", "to": "TaskRunnerDO"}]},
  ],
  "vars": {"FEATURE_MODE": "enabled", "RETRY_LIMIT": "3"},
}`

const minimalWranglerJSON = `{"name":"worker","account_id":"account","main":"worker.mjs","compatibility_date":"2026-09-15","workers_dev":false,"preview_urls":false}`

func TestCapabilityAcceptsSupportedWranglerProfile(t *testing.T) {
	config, err := opscloudflarepayload.ParseWranglerConfig("wrangler-4.107-preveal-v1", []byte(supportedWranglerJSONC))
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "example-worker" || config.Main != "src/worker.mjs" || config.Assets == nil {
		t.Fatalf("canonical identity/assets missing: %#v", config)
	}
	if len(config.Routes) != 1 || len(config.Crons) != 1 || len(config.Migrations) != 2 {
		t.Fatalf("canonical read-only or migration state missing: %#v", config)
	}
	if len(config.KVNamespaces) != 1 || len(config.D1Databases) != 1 || len(config.R2Buckets) != 1 || len(config.Vectorize) != 1 || len(config.DurableObjects) != 1 {
		t.Fatalf("canonical bindings missing: %#v", config)
	}
	metadata, err := config.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(metadata, []byte(`"profile":"wrangler-4.107-preveal-v1"`)) || bytes.Contains(metadata, []byte("//")) {
		t.Fatalf("metadata is not canonical JSON: %s", metadata)
	}
	if bytes.Contains(metadata, []byte("../web/dist")) || bytes.Contains(metadata, []byte(`"directory"`)) {
		t.Fatalf("asset source path entered production metadata: %s", metadata)
	}
}

func TestCapabilityMetadataIsDeterministic(t *testing.T) {
	first, err := opscloudflarepayload.ParseWranglerConfig("wrangler-4.107-preveal-v1", []byte(supportedWranglerJSONC))
	if err != nil {
		t.Fatal(err)
	}
	second, err := opscloudflarepayload.ParseWranglerConfig("wrangler-4.107-preveal-v1", []byte(supportedWranglerJSONC))
	if err != nil {
		t.Fatal(err)
	}
	firstMetadata, _ := first.Metadata()
	secondMetadata, _ := second.Metadata()
	if !bytes.Equal(firstMetadata, secondMetadata) {
		t.Fatalf("metadata is not deterministic:\n%s\n%s", firstMetadata, secondMetadata)
	}
}

func TestCapabilityRejectsUnsupportedWranglerConfiguration(t *testing.T) {
	tests := map[string]string{
		"wrong profile":          minimalWranglerJSON,
		"missing identity":       `{"name":"worker"}`,
		"unknown top key":        withConfigField(`"unexpected":true`),
		"duplicate top key":      withConfigField(`"name":"other"`),
		"environment":            withConfigField(`"env":{"production":{}}`),
		"workers dev enabled":    replaceConfigField(`"workers_dev":false`, `"workers_dev":true`),
		"preview urls enabled":   replaceConfigField(`"preview_urls":false`, `"preview_urls":true`),
		"unknown flag":           withConfigField(`"compatibility_flags":["unsafe_unknown"]`),
		"unknown asset":          withConfigField(`"assets":{"directory":"dist","unknown":true}`),
		"unknown route":          withConfigField(`"routes":[{"pattern":"example.test","unknown":true}]`),
		"unknown trigger":        withConfigField(`"triggers":{"crons":[],"unknown":true}`),
		"unknown binding":        withConfigField(`"kv_namespaces":[{"binding":"CACHE","id":"id","unknown":true}]`),
		"unknown d1":             withConfigField(`"d1_databases":[{"binding":"DB","database_name":"db","database_id":"id","unknown":true}]`),
		"unknown r2":             withConfigField(`"r2_buckets":[{"binding":"MEDIA","bucket_name":"bucket","unknown":true}]`),
		"unknown ai":             withConfigField(`"ai":{"binding":"AI","unknown":true}`),
		"unknown vectorize":      withConfigField(`"vectorize":[{"binding":"SEARCH","index_name":"index","unknown":true}]`),
		"unknown durable object": withConfigField(`"durable_objects":{"bindings":[{"name":"DO","class_name":"Thing","unknown":true}]}`),
		"unknown migration":      withConfigField(`"migrations":[{"tag":"v1","unknown_classes":["Thing"]}]`),
		"unknown rename":         withConfigField(`"migrations":[{"tag":"v1","renamed_classes":[{"from":"Old","to":"New","unknown":true}]}]`),
		"non-string var":         withConfigField(`"vars":{"COUNT":3}`),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			profile := "wrangler-4.107-preveal-v1"
			if name == "wrong profile" {
				profile = "wrangler-4.108-unknown"
			}
			if _, err := opscloudflarepayload.ParseWranglerConfig(profile, []byte(input)); err == nil {
				t.Fatal("unsupported Wrangler configuration was accepted")
			}
		})
	}
}

func withConfigField(field string) string {
	return minimalWranglerJSON[:len(minimalWranglerJSON)-1] + "," + field + "}"
}

func replaceConfigField(old, replacement string) string {
	return string(bytes.ReplaceAll([]byte(minimalWranglerJSON), []byte(old), []byte(replacement)))
}
