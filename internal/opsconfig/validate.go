package opsconfig

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

const DurationPattern = `^(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:ns|us|ms|s|m|h)(?:(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:ns|us|ms|s|m|h))*$`
const SSHAliasPattern = `^[A-Za-z0-9][A-Za-z0-9._-]*$`
const HealthHTTPURLPattern = `^https?://(?![^/?#]*@)[^/?#\s]+(?:[/?#].*)?$`
const HealthTCPAddressPattern = `^(?:[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:.]+\]):(?:[1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`
const ConfigOwnerPattern = `^[A-Za-z_][A-Za-z0-9_.-]*$`
const ProcessCommandPattern = `^(?:/|\./)?[A-Za-z0-9_+@-][A-Za-z0-9_+@.-]*(?:/[A-Za-z0-9_+@-][A-Za-z0-9_+@.-]*)*$`

var defaultProductionRoots = []string{"/opt/apps"}

var durationPattern = regexp.MustCompile(DurationPattern)
var sshAliasPattern = regexp.MustCompile(SSHAliasPattern)
var configOwnerPattern = regexp.MustCompile(ConfigOwnerPattern)
var processCommandPattern = regexp.MustCompile(ProcessCommandPattern)
var cloudflareWorkerPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var cloudflareAccountIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validateServices(services []Service, hosts map[string]Host) []Issue {
	byID := make(map[string][]Service)
	for _, service := range services {
		byID[service.ID] = append(byID[service.ID], service)
	}

	var issues []Issue
	for _, service := range services {
		if service.Version != 1 {
			issues = append(issues, issue(service, "version", "must be 1"))
		}
		filenameID := strings.TrimSuffix(filepath.Base(service.SourceFile), filepath.Ext(service.SourceFile))
		if service.ID != filenameID {
			issues = append(issues, issue(service, "id", fmt.Sprintf("must match filename %q", filenameID)))
		}
		if len(byID[service.ID]) > 1 {
			issues = append(issues, issue(service, "id", fmt.Sprintf("duplicate id %q", service.ID)))
		}
		issues = append(issues, validateServiceIdentity(service)...)
		issues = append(issues, validateBuild(service)...)
		issues = append(issues, validateServiceCredentials(service)...)
		for _, name := range []string{EnvironmentLocal, EnvironmentProduction} {
			if _, exists := service.Environments[name]; !exists {
				issues = append(issues, issue(service, "environments."+name, "is required"))
			}
		}
		for name, environment := range service.Environments {
			if name != EnvironmentLocal && name != EnvironmentProduction {
				issues = append(issues, issue(service, "environments."+name, "environment must be local or production"))
				continue
			}
			issues = append(issues, validateEnvironment(service, name, environment, hosts)...)
		}
	}
	return issues
}

func validateHosts(file HostsFile) []Issue {
	var issues []Issue
	if file.Version != 1 {
		issues = append(issues, Issue{File: "hosts.yaml", Field: "version", Message: "must be 1"})
	}
	aliases := make([]string, 0, len(file.Hosts))
	for alias := range file.Hosts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		host := file.Hosts[alias]
		prefix := "hosts." + alias + "."
		if !sshAliasPattern.MatchString(host.SSHAlias) {
			issues = append(issues, Issue{File: "hosts.yaml", Field: prefix + "sshAlias", Message: "must match the safe SSH alias format"})
		}
		if host.Platform != "ubuntu" {
			issues = append(issues, Issue{File: "hosts.yaml", Field: prefix + "platform", Message: "must be ubuntu"})
		}
		if strings.TrimSpace(host.Architecture) == "" {
			issues = append(issues, Issue{File: "hosts.yaml", Field: prefix + "architecture", Message: "must not be empty"})
		}
		if host.AllowedRoots != nil && len(host.AllowedRoots) == 0 {
			issues = append(issues, Issue{File: "hosts.yaml", Field: prefix + "allowedRoots", Message: "must contain unique roots"})
		}
		seenRoots := make(map[string]struct{}, len(host.AllowedRoots))
		for index, root := range host.AllowedRoots {
			if !isCanonicalAllowedRoot(root) {
				issues = append(issues, Issue{File: "hosts.yaml", Field: fmt.Sprintf("%sallowedRoots.%d", prefix, index), Message: "must be a canonical absolute path other than /"})
			}
			if _, exists := seenRoots[root]; exists {
				issues = append(issues, Issue{File: "hosts.yaml", Field: prefix + "allowedRoots", Message: "must contain unique roots"})
			}
			seenRoots[root] = struct{}{}
		}
	}
	return issues
}

func validatePolicies(policies Policies) []Issue {
	var issues []Issue
	add := func(field, message string) {
		issues = append(issues, Issue{File: "policies.yaml", Field: field, Message: message})
	}
	if policies.Version != 1 {
		add("version", "must be 1")
	}
	validateDuration := func(field, value string) {
		if !durationPattern.MatchString(value) {
			add(field, "must be a positive duration")
			return
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			add(field, "must be a positive duration")
		}
	}
	validateDuration("execution.defaultTimeout", policies.Execution.DefaultTimeout)
	validateDuration("execution.healthTimeout", policies.Execution.HealthTimeout)
	if policies.Execution.BatchConcurrency != 1 {
		add("execution.batchConcurrency", "must be 1")
	}
	if !policies.Production.RequirePreviewDigest {
		add("production.requirePreviewDigest", "must be true")
	}
	if !policies.Production.RequireCleanArtifactManifest {
		add("production.requireCleanArtifactManifest", "must be true")
	}
	if policies.Releases.Retain < 1 {
		add("releases.retain", "must be at least 1")
	}
	if policies.Backups.ServerCopies < 1 {
		add("backups.serverCopies", "must be at least 1")
	}
	if policies.Backups.LocalCopies < 1 {
		add("backups.localCopies", "must be at least 1")
	}
	if !policies.Backups.RequireEncryption {
		add("backups.requireEncryption", "must be true")
	}
	return issues
}

func validateServiceIdentity(service Service) []Issue {
	var issues []Issue
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "language", value: service.Language},
		{name: "source.repository", value: service.Source.Repository},
	} {
		if strings.TrimSpace(field.value) == "" {
			issues = append(issues, issue(service, field.name, "must not be empty"))
		}
	}
	if strings.TrimSpace(service.Source.Path) == "" {
		issues = append(issues, issue(service, "source.path", "is required"))
	}
	if service.Source.Path != "" && !isCanonicalSourcePath(service.Source.Path) {
		issues = append(issues, issue(service, "source.path", "must be a canonical absolute path other than filesystem root without control characters"))
	}
	issues = append(issues, validateDeploymentSource(service)...)
	return issues
}

func validateDeploymentSource(service Service) []Issue {
	root := service.Source.RepositoryRoot
	scopes := service.Source.DeploymentScope
	cloudflare := service.Environments[EnvironmentProduction].Kind == EnvironmentKindCloudflareWorkers
	var issues []Issue
	if root == "" && len(scopes) == 0 && !cloudflare {
		return issues
	}
	if !isCanonicalSourcePath(root) {
		issues = append(issues, issue(service, "source.repositoryRoot", "must be a canonical absolute path other than filesystem root"))
	} else if service.Source.Path != root && !strings.HasPrefix(service.Source.Path, root+string(filepath.Separator)) {
		issues = append(issues, issue(service, "source.path", "must be within source.repositoryRoot"))
	}
	if len(scopes) == 0 {
		issues = append(issues, issue(service, "source.deploymentScope", "must contain at least one path"))
		return issues
	}
	cleanScopes := make([]string, 0, len(scopes))
	for index, scope := range scopes {
		clean := filepath.Clean(scope)
		if scope == "" || filepath.IsAbs(scope) || clean != scope || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.ContainsAny(scope, "\r\n\x00") {
			issues = append(issues, issue(service, fmt.Sprintf("source.deploymentScope.%d", index), "must be a clean relative path within source.repositoryRoot"))
			continue
		}
		cleanScopes = append(cleanScopes, clean)
	}
	for left := 0; left < len(cleanScopes); left++ {
		for right := left + 1; right < len(cleanScopes); right++ {
			if cleanScopes[left] == cleanScopes[right] || strings.HasPrefix(cleanScopes[left], cleanScopes[right]+string(filepath.Separator)) || strings.HasPrefix(cleanScopes[right], cleanScopes[left]+string(filepath.Separator)) {
				issues = append(issues, issue(service, "source.deploymentScope", "must contain unique non-overlapping paths"))
				return issues
			}
		}
	}
	return issues
}

func isCanonicalSourcePath(value string) bool {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
		return false
	}
	return !strings.ContainsAny(value, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f")
}

func validateEnvironment(service Service, name string, environment Environment, hosts map[string]Host) []Issue {
	prefix := "environments." + name + "."
	var issues []Issue
	if err := ValidateCredentials(environment.Credentials); err != nil {
		issues = append(issues, issue(service, prefix+"credentials", err.Error()))
	}
	if environment.Credentials != nil && environment.Kind != EnvironmentKindCloudflareWorkers {
		issues = append(issues, issue(service, prefix+"credentials", "requires cloudflare-workers"))
	}
	if name == EnvironmentLocal && environment.Kind != EnvironmentKindLocal {
		issues = append(issues, issue(service, prefix+"kind", fmt.Sprintf("must be %q", EnvironmentKindLocal)))
	}
	if name == EnvironmentProduction && environment.Kind != EnvironmentKindSSH && environment.Kind != EnvironmentKindCloudflareWorkers {
		issues = append(issues, issue(service, prefix+"kind", fmt.Sprintf("must be %q or %q", EnvironmentKindSSH, EnvironmentKindCloudflareWorkers)))
	}
	if name == EnvironmentProduction && environment.Kind == EnvironmentKindSSH {
		host, exists := hosts[environment.Host]
		if environment.Host == "" || !exists {
			issues = append(issues, issue(service, prefix+"host", fmt.Sprintf("unknown host %q", environment.Host)))
		} else if capabilityRequired(environment.Runner) && !contains(host.Capabilities, environment.Runner) {
			issues = append(issues, issue(service, prefix+"runner", fmt.Sprintf("host %q lacks %q capability", environment.Host, environment.Runner)))
		}
		if !isProductionRootAllowed(environment.Root, host.AllowedRoots) {
			issues = append(issues, issue(service, prefix+"root", "must be a canonical absolute path below an allowed root"))
		}
	} else if name == EnvironmentLocal {
		if environment.Host != "" {
			issues = append(issues, issue(service, prefix+"host", "is only allowed for production"))
		}
		if environment.Root != "" {
			issues = append(issues, issue(service, prefix+"root", "is only allowed for production"))
		}
	}
	issues = append(issues, validateCloudflareEnvironment(service, name, prefix, environment)...)
	issues = append(issues, validateRunner(service, name, prefix, environment)...)
	issues = append(issues, validateHealth(service, prefix, environment.Health)...)
	return issues
}

func validateCloudflareEnvironment(service Service, name, prefix string, environment Environment) []Issue {
	var issues []Issue
	if environment.Kind != EnvironmentKindCloudflareWorkers {
		if environment.Worker != "" {
			issues = append(issues, issue(service, prefix+"worker", "is only allowed for cloudflare-workers"))
		}
		if environment.WranglerConfig != "" {
			issues = append(issues, issue(service, prefix+"wranglerConfig", "is only allowed for cloudflare-workers"))
		}
		if environment.AccountID != "" {
			issues = append(issues, issue(service, prefix+"accountId", "is only allowed for cloudflare-workers"))
		}
		if environment.APIProfile != "" {
			issues = append(issues, issue(service, prefix+"apiProfile", "is only allowed for cloudflare-workers"))
		}
		return issues
	}
	if name != EnvironmentProduction {
		issues = append(issues, issue(service, prefix+"kind", "cloudflare-workers is only allowed for production"))
	}
	if environment.Host != "" {
		issues = append(issues, issue(service, prefix+"host", "is not allowed for cloudflare-workers"))
	}
	if environment.Root != "" {
		issues = append(issues, issue(service, prefix+"root", "is not allowed for cloudflare-workers"))
	}
	if environment.Runner != RunnerManual {
		issues = append(issues, issue(service, prefix+"runner", "must be manual for cloudflare-workers"))
	}
	if !cloudflareWorkerPattern.MatchString(environment.Worker) {
		issues = append(issues, issue(service, prefix+"worker", "must be a safe Cloudflare Worker name"))
	}
	if !cloudflareAccountIDPattern.MatchString(environment.AccountID) {
		issues = append(issues, issue(service, prefix+"accountId", "must be a 32 lowercase hexadecimal character Cloudflare account ID"))
	}
	config := filepath.Clean(environment.WranglerConfig)
	if environment.WranglerConfig == "" || strings.ContainsAny(environment.WranglerConfig, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f") || filepath.IsAbs(environment.WranglerConfig) || config != environment.WranglerConfig || config == "." || config == ".." || strings.HasPrefix(config, ".."+string(filepath.Separator)) {
		issues = append(issues, issue(service, prefix+"wranglerConfig", "must be a clean relative path within the source root"))
	}
	if environment.APIProfile != "wrangler-4.107-preveal-v1" {
		issues = append(issues, issue(service, prefix+"apiProfile", "must select a supported Cloudflare production API profile"))
	}
	return issues
}

func isCanonicalAllowedRoot(root string) bool {
	return filepath.IsAbs(root) && root != "/" && filepath.Clean(root) == root
}

func isProductionRootAllowed(root string, allowedRoots []string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	if len(allowedRoots) == 0 {
		allowedRoots = defaultProductionRoots
	}
	for _, allowedRoot := range allowedRoots {
		if isCanonicalAllowedRoot(allowedRoot) && strings.HasPrefix(root, allowedRoot+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateHealth(service Service, prefix string, health Health) []Issue {
	if health.Type == "" {
		return nil
	}
	var issues []Issue
	add := func(field, message string) { issues = append(issues, issue(service, prefix+"health."+field, message)) }
	require := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			add(field, "must not be empty")
		}
	}
	rejectStatuses := func() {
		if health.SuccessStatuses != nil {
			add("successStatuses", "is only allowed for http health")
		}
	}
	switch health.Type {
	case "http":
		require("url", health.URL)
		if health.URL != "" {
			if err := ValidateHealthHTTPURL(health.URL); err != nil {
				add("url", err.Error())
			}
		}
		if len(health.SuccessStatuses) == 0 {
			add("successStatuses", "must contain at least one status")
		}
		seen := map[int]bool{}
		for _, status := range health.SuccessStatuses {
			if status < 100 || status > 599 {
				add("successStatuses", "must contain only values from 100 through 599")
			}
			if seen[status] {
				add("successStatuses", "must contain unique values")
			}
			seen[status] = true
		}
	case "tcp":
		require("address", health.Address)
		if health.Address != "" {
			if _, _, err := ParseHealthTCPAddress(health.Address); err != nil {
				add("address", err.Error())
			}
		}
		rejectStatuses()
	case "process":
		rejectStatuses()
	case "command":
		if health.Command == nil {
			add("command", "must be configured")
		} else {
			require("command.program", health.Command.Program)
			if err := opsexec.ValidateCommandArgv(health.Command.Program, health.Command.Args); err != nil {
				add("command", err.Error())
			}
		}
		rejectStatuses()
	default:
		add("type", "must be one of process, tcp, http, command")
	}
	if health.Type != "http" && health.URL != "" {
		add("url", "is only allowed for http health")
	}
	if health.Type != "tcp" && health.Address != "" {
		add("address", "is only allowed for tcp health")
	}
	if health.Type != "command" && health.Command != nil {
		add("command", "is only allowed for command health")
	}
	return issues
}

func ValidateHealthHTTPURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return fmt.Errorf("must be an http/https URL with a host and without userinfo")
	}
	return nil
}

func ParseHealthTCPAddress(raw string) (string, string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, "\x00\r\n\t") {
		return "", "", fmt.Errorf("must contain a safe host and numeric port from 1 through 65535")
	}
	if net.ParseIP(host) == nil && !sshAliasPattern.MatchString(host) {
		return "", "", fmt.Errorf("must contain a safe host and numeric port from 1 through 65535")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", "", fmt.Errorf("must contain a safe host and numeric port from 1 through 65535")
	}
	return host, port, nil
}

func validateBuild(service Service) []Issue {
	if !service.BuildConfigured() {
		return nil
	}
	var issues []Issue
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "adapter", value: service.Build.Adapter},
		{name: "command", value: service.Build.Command},
	} {
		if strings.TrimSpace(field.value) == "" {
			issues = append(issues, issue(service, "build."+field.name, "must not be empty when build is configured"))
		}
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "artifact", value: service.Build.Artifact},
		{name: "manifest", value: service.Build.Manifest},
	} {
		clean := filepath.Clean(field.value)
		if strings.TrimSpace(field.value) == "" {
			issues = append(issues, issue(service, "build."+field.name, "must not be empty when build is configured"))
			continue
		}
		if filepath.IsAbs(field.value) || clean != field.value || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			issues = append(issues, issue(service, "build."+field.name, "must be a clean non-empty relative path within the project root"))
		}
	}
	return issues
}

func capabilityRequired(runner string) bool {
	return runner == RunnerSystemd || runner == RunnerPHPFPM || runner == RunnerPM2
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validateRunner(service Service, name, prefix string, environment Environment) []Issue {
	var issues []Issue
	require := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, issue(service, prefix+field, fmt.Sprintf("is required for %s runner", environment.Runner)))
		}
	}
	reject := func(field, value string) {
		if strings.TrimSpace(value) != "" {
			issues = append(issues, issue(service, prefix+field, fmt.Sprintf("is not allowed for %s runner", environment.Runner)))
		}
	}

	switch environment.Runner {
	case RunnerSystemd:
		require("unit", environment.Unit)
		reject("configOwner", environment.ConfigOwner)
		reject("configPath", environment.ConfigPath)
		reject("user", environment.User)
		reject("service", environment.Service)
		reject("app", environment.App)
		rejectProcessFields(service, prefix, environment, &issues)
	case RunnerPHPFPM:
		require("service", environment.Service)
		require("configOwner", environment.ConfigOwner)
		require("configPath", environment.ConfigPath)
		reject("user", environment.User)
		reject("unit", environment.Unit)
		reject("app", environment.App)
		rejectProcessFields(service, prefix, environment, &issues)
	case RunnerPM2:
		require("app", environment.App)
		require("configOwner", environment.ConfigOwner)
		require("configPath", environment.ConfigPath)
		reject("user", environment.User)
		reject("unit", environment.Unit)
		reject("service", environment.Service)
		rejectProcessFields(service, prefix, environment, &issues)
	case RunnerProcess:
		require("user", environment.User)
		require("command", environment.Command)
		if name == EnvironmentLocal && environment.Command != "" && (!filepath.IsAbs(environment.Command) || filepath.Clean(environment.Command) != environment.Command) {
			issues = append(issues, issue(service, prefix+"command", "must be a clean absolute path for local process runner"))
		}
		require("pidfile", environment.PIDFile)
		require("shutdownSignal", environment.ShutdownSignal)
		require("logs", environment.Logs)
		reject("unit", environment.Unit)
		reject("service", environment.Service)
		reject("app", environment.App)
		reject("configOwner", environment.ConfigOwner)
		reject("configPath", environment.ConfigPath)
		if environment.User != "" && !configOwnerPattern.MatchString(environment.User) {
			issues = append(issues, issue(service, prefix+"user", "must match the safe Unix identity format"))
		}
		if environment.Command != "" && !processCommandPattern.MatchString(environment.Command) {
			issues = append(issues, issue(service, prefix+"command", "must be a safe executable path without traversal or arguments"))
		}
		for _, field := range []struct{ name, value string }{{"pidfile", environment.PIDFile}, {"logs", environment.Logs}} {
			if field.value != "" && (!filepath.IsAbs(field.value) || filepath.Clean(field.value) != field.value || strings.ContainsAny(field.value, "\r\n\x00")) {
				issues = append(issues, issue(service, prefix+field.name, "must be a clean absolute path"))
			}
		}
		if environment.ShutdownSignal != "" && !isGracefulSignal(environment.ShutdownSignal) {
			issues = append(issues, issue(service, prefix+"shutdownSignal", "must be one of SIGTERM, SIGINT, SIGHUP, SIGQUIT"))
		}
	case RunnerManual:
		reject("unit", environment.Unit)
		reject("service", environment.Service)
		reject("app", environment.App)
		reject("command", environment.Command)
		reject("pidfile", environment.PIDFile)
		reject("shutdownSignal", environment.ShutdownSignal)
		reject("logs", environment.Logs)
		reject("configOwner", environment.ConfigOwner)
		reject("configPath", environment.ConfigPath)
		reject("user", environment.User)
	default:
		reject("configOwner", environment.ConfigOwner)
		reject("configPath", environment.ConfigPath)
		reject("user", environment.User)
		issues = append(issues, issue(service, prefix+"runner", fmt.Sprintf("must be one of %s", strings.Join(RunnerKinds, ", "))))
	}
	if environment.ConfigOwner != "" && !configOwnerPattern.MatchString(environment.ConfigOwner) {
		issues = append(issues, issue(service, prefix+"configOwner", "must match the safe Unix identity format"))
	}
	if environment.ConfigPath != "" && (!filepath.IsAbs(environment.ConfigPath) || filepath.Clean(environment.ConfigPath) != environment.ConfigPath || strings.ContainsAny(environment.ConfigPath, "\r\n\x00")) {
		issues = append(issues, issue(service, prefix+"configPath", "must be a clean absolute path"))
	}
	return issues
}

func isGracefulSignal(signal string) bool {
	switch signal {
	case "SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT":
		return true
	default:
		return false
	}
}

func rejectProcessFields(service Service, prefix string, environment Environment, issues *[]Issue) {
	fields := []struct{ name, value string }{
		{"command", environment.Command},
		{"pidfile", environment.PIDFile},
		{"shutdownSignal", environment.ShutdownSignal},
		{"logs", environment.Logs},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.value) != "" {
			*issues = append(*issues, issue(service, prefix+field.name, fmt.Sprintf("is not allowed for %s runner", environment.Runner)))
		}
	}
}

func issue(service Service, field, message string) Issue {
	return Issue{File: service.SourceFile, Field: field, Message: message}
}
