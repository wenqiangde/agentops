package opsconfig

import (
	"errors"
	"regexp"
)

const CredentialVariablePattern = `^[A-Za-z_][A-Za-z0-9_]*$`
const CloudflareConfigPathPattern = `^(?!/)(?!.*(?:^|/)\.\.?(?:/|$))(?!.*//)[^\u0000-\u001F\u007F/](?:[^\u0000-\u001F\u007F]*[^\u0000-\u001F\u007F/])?$`

var credentialVariable = regexp.MustCompile(CredentialVariablePattern)

type Credentials struct {
	Provider string `yaml:"provider"`
	TokenEnv string `yaml:"tokenEnv"`
}

func ValidateCredentials(c *Credentials) error {
	if c == nil {
		return nil
	}
	if c.Provider != "cloudflare" {
		return errors.New("credentials provider must be cloudflare")
	}
	if !credentialVariable.MatchString(c.TokenEnv) {
		return errors.New("credentials tokenEnv must be an environment variable name")
	}
	return nil
}

func validateServiceCredentials(service Service) []Issue {
	if err := ValidateCredentials(service.Credentials); err != nil {
		return []Issue{issue(service, "credentials", err.Error())}
	}
	if service.Credentials != nil {
		supported := false
		for _, env := range service.Environments {
			supported = supported || env.Kind == EnvironmentKindCloudflareWorkers
		}
		if !supported {
			return []Issue{issue(service, "credentials", "requires a cloudflare-workers environment")}
		}
	}
	return nil
}
