package opscredentials

import (
	"errors"
	"github.com/wenqiangde/agentops/internal/opsconfig"
)

const PolicyVersion = "cloudflare-env-file-v1"

type Selection struct {
	Provider      string
	TokenEnv      string
	PolicyVersion string
}

func Select(service *opsconfig.Credentials, environment opsconfig.Environment) (Selection, error) {
	if environment.Kind != opsconfig.EnvironmentKindCloudflareWorkers {
		return Selection{}, errors.New("Cloudflare credentials require cloudflare-workers")
	}
	if err := opsconfig.ValidateCredentials(service); err != nil {
		return Selection{}, err
	}
	if err := opsconfig.ValidateCredentials(environment.Credentials); err != nil {
		return Selection{}, err
	}
	selected := service
	if environment.Credentials != nil {
		selected = environment.Credentials
	}
	if selected == nil {
		selected = &opsconfig.Credentials{Provider: "cloudflare", TokenEnv: "AGENTOPS_CLOUDFLARE_API_TOKEN"}
	}
	return Selection{Provider: selected.Provider, TokenEnv: selected.TokenEnv, PolicyVersion: PolicyVersion}, nil
}
