package opsconfig_test

import (
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredentialsContract(t *testing.T) {
	tests := []struct {
		name, service, environment string
		invalid                    bool
	}{
		{"legacy", "", "", false},
		{"service", "credentials:\n  provider: cloudflare\n  tokenEnv: SERVICE_TOKEN\n", "", false},
		{"environment", "", "    credentials:\n      provider: cloudflare\n      tokenEnv: ENV_TOKEN\n", false},
		{"empty", "", "    credentials: {}\n", true},
		{"missing provider", "", "    credentials:\n      tokenEnv: TOKEN\n", true},
		{"missing variable", "", "    credentials:\n      provider: cloudflare\n", true},
		{"invalid provider", "", "    credentials:\n      provider: aws\n      tokenEnv: TOKEN\n", true},
		{"invalid variable", "", "    credentials:\n      provider: cloudflare\n      tokenEnv: BAD-NAME\n", true},
		{"unknown field", "", "    credentials:\n      provider: cloudflare\n      tokenEnv: TOKEN\n      profile: other\n", true},
		{"null", "", "    credentials: null\n", true},
		{"raw token", "", "    credentials:\n      provider: cloudflare\n      tokenEnv: TOKEN\n      token: sentinel-secret-value\n", true},
		{"misplaced reference", "tokenEnv: sentinel-secret-value\n", "", true},
		{"non scalar reference", "", "    credentials:\n      provider: cloudflare\n      tokenEnv: [sentinel-secret-value]\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			data := tt.service + cloudflareService("credentials")
			data = strings.Replace(data, "    kind: cloudflare-workers\n", "    kind: cloudflare-workers\n"+tt.environment, 1)
			writeFile(t, filepath.Join(root, "services", "credentials.yaml"), data)
			inv, issues := opsconfig.Load(root)
			_, exists := inv.Services["credentials"]
			if exists == tt.invalid {
				t.Fatalf("exists=%v issues=%v", exists, issues)
			}
			for _, issue := range issues {
				if strings.Contains(issue.Message, "sentinel-secret-value") {
					t.Fatal("credential content leaked in diagnostic")
				}
			}
		})
	}
}

func TestCredentialsSchemaContract(t *testing.T) {
	schema := readJSONSchema(t, "service.schema.json")
	defs := schema["$defs"].(map[string]any)
	credentials, ok := defs["credentials"].(map[string]any)
	if !ok {
		t.Fatal("missing credentials schema")
	}
	assertRequiredFields(t, credentials, "provider", "tokenEnv")
	if credentials["additionalProperties"] != false {
		t.Fatal("unknown credential fields allowed")
	}
	props := credentials["properties"].(map[string]any)
	assertJSONConst(t, props["provider"], "cloudflare")
	if props["tokenEnv"].(map[string]any)["pattern"] != opsconfig.CredentialVariablePattern {
		t.Fatal("variable pattern mismatch")
	}
	cf, ok := defs["cloudflareEnvironment"].(map[string]any)
	if !ok {
		t.Fatal("missing Cloudflare schema")
	}
	assertRequiredFields(t, cf, "kind", "runner", "worker", "accountId", "wranglerConfig", "apiProfile")
	if cf["properties"].(map[string]any)["credentials"] == nil {
		t.Fatal("missing environment credentials")
	}
	if schema["properties"].(map[string]any)["credentials"] == nil {
		t.Fatal("missing service credentials")
	}
	source := defs["source"].(map[string]any)["properties"].(map[string]any)
	if source["repositoryRoot"] == nil || source["deploymentScope"] == nil {
		t.Fatal("Cloudflare source fields missing")
	}
	if schema["properties"].(map[string]any)["deployment"] == nil {
		t.Fatal("deployment contract missing")
	}
	config := cf["properties"].(map[string]any)["wranglerConfig"].(map[string]any)
	if config["pattern"] != opsconfig.CloudflareConfigPathPattern {
		t.Fatal("config path pattern mismatch")
	}
}
