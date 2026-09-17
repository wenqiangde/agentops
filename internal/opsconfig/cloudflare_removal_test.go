package opsconfig

import (
	"strings"
	"testing"
)

func TestCloudflareProductionIsRejected(t *testing.T) {
	service := Service{}
	issues := validateEnvironment(service, EnvironmentProduction, Environment{Kind: "cloudflare-workers"}, nil)
	for _, issue := range issues {
		if strings.Contains(issue.Message, "Cloudflare operations have been removed") {
			return
		}
	}
	t.Fatal("Cloudflare production must be rejected before service execution")
}
