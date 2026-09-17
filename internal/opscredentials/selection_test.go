package opscredentials

import (
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"testing"
)

func TestSelection(t *testing.T) {
	cf := func(name string) *opsconfig.Credentials {
		return &opsconfig.Credentials{Provider: "cloudflare", TokenEnv: name}
	}
	tests := []struct {
		name                 string
		service, environment *opsconfig.Credentials
		kind, want           string
		invalid              bool
	}{
		{"legacy", nil, nil, "cloudflare-workers", "AGENTOPS_CLOUDFLARE_API_TOKEN", false},
		{"service", cf("SERVICE_TOKEN"), nil, "cloudflare-workers", "SERVICE_TOKEN", false},
		{"environment", cf("SERVICE_TOKEN"), cf("ENV_TOKEN"), "cloudflare-workers", "ENV_TOKEN", false},
		{"empty", nil, &opsconfig.Credentials{}, "cloudflare-workers", "", true},
		{"missing provider", nil, &opsconfig.Credentials{TokenEnv: "TOKEN"}, "cloudflare-workers", "", true},
		{"missing name", nil, &opsconfig.Credentials{Provider: "cloudflare"}, "cloudflare-workers", "", true},
		{"unknown provider", nil, &opsconfig.Credentials{Provider: "aws", TokenEnv: "TOKEN"}, "cloudflare-workers", "", true},
		{"invalid name", nil, cf("TOKEN-NAME"), "cloudflare-workers", "", true},
		{"ssh", nil, cf("TOKEN"), "ssh", "", true},
		{"invalid overridden default", cf("BAD-NAME"), cf("TOKEN"), "cloudflare-workers", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.service, opsconfig.Environment{Kind: tt.kind, Credentials: tt.environment})
			if (err != nil) != tt.invalid {
				t.Fatalf("error=%v invalid=%v", err, tt.invalid)
			}
			if err == nil && (got.TokenEnv != tt.want || got.Provider != "cloudflare" || got.PolicyVersion != "cloudflare-env-file-v1") {
				t.Fatalf("selection=%+v", got)
			}
		})
	}
}

func TestSelectionDoesNotReadSecret(t *testing.T) {
	t.Setenv("AGENTOPS_CLOUDFLARE_API_TOKEN", "")
	got, err := Select(nil, opsconfig.Environment{Kind: "cloudflare-workers"})
	if err != nil || got.TokenEnv != "AGENTOPS_CLOUDFLARE_API_TOKEN" {
		t.Fatalf("selection=%+v err=%v", got, err)
	}
}
