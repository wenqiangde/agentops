package opsconfig_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestLoadValidInventory(t *testing.T) {
	inv, issues := opsconfig.Load(filepath.Join("testdata", "valid"))
	if len(issues) != 0 {
		t.Fatalf("issues=%+v", issues)
	}
	service, ok := inv.Services["demo-api"]
	if !ok || service.SourceFile != "services/demo-api.yaml" {
		t.Fatalf("services=%+v", inv.Services)
	}
	if service.Environments[opsconfig.EnvironmentProduction].Runner != opsconfig.RunnerSystemd {
		t.Fatalf("production=%+v", service.Environments[opsconfig.EnvironmentProduction])
	}
	if inv.Hosts["prod-demo"].Architecture != "amd64" || inv.Policies.Releases.Retain != 3 {
		t.Fatalf("inventory=%+v", inv)
	}
	if service.FutureResources["redis"].Status != "planned" {
		t.Fatalf("futureResources=%+v", service.FutureResources)
	}
	if inv.Services["demo-php"].Environments[opsconfig.EnvironmentProduction].ConfigOwner != "www-data" {
		t.Fatalf("php-fpm configOwner was not loaded: %+v", inv.Services["demo-php"])
	}
	if inv.Services["demo-node"].Environments[opsconfig.EnvironmentProduction].ConfigOwner != "node_app" {
		t.Fatalf("pm2 configOwner was not loaded: %+v", inv.Services["demo-node"])
	}
}

func TestLoadKeepsValidServicesWhenAnotherFileIsInvalid(t *testing.T) {
	inv, issues := opsconfig.Load(filepath.Join("testdata", "partially-invalid"))
	if len(inv.Services) != 1 || inv.Services["healthy-api"].ID != "healthy-api" {
		t.Fatalf("valid services=%v", inv.Services)
	}
	if len(issues) != 1 || issues[0].File != "services/broken-api.yaml" {
		t.Fatalf("issues=%+v", issues)
	}
}

func TestLoadRejectsUnknownFieldsStrictly(t *testing.T) {
	root := copyValidInventory(t)
	writeFile(t, filepath.Join(root, "services", "unknown.yaml"), strings.Replace(validService("unknown"), "language: go", "language: go\nunknownField: true", 1))

	inv, issues := opsconfig.Load(root)
	if _, ok := inv.Services["unknown"]; ok {
		t.Fatalf("unknown-field service loaded: %+v", inv.Services["unknown"])
	}
	assertIssue(t, issues, "services/unknown.yaml", "unknownField")
}

func TestLoadReportsUnknownFieldForEveryFileType(t *testing.T) {
	tests := []struct {
		name string
		file string
		old  string
		add  string
	}{
		{name: "service", file: filepath.Join("services", "unknown.yaml"), old: validService("unknown"), add: "unknownServiceField: true\n"},
		{name: "hosts", file: "hosts.yaml", add: "unknownHostsField: true\n"},
		{name: "policies", file: "policies.yaml", add: "unknownPoliciesField: true\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			content := tt.old
			if content == "" {
				data, err := os.ReadFile(filepath.Join(root, tt.file))
				if err != nil {
					t.Fatal(err)
				}
				content = string(data)
			}
			writeFile(t, filepath.Join(root, tt.file), content+tt.add)

			_, issues := opsconfig.Load(root)
			field := strings.TrimSuffix(strings.TrimSpace(tt.add), ": true")
			assertIssue(t, issues, filepath.ToSlash(tt.file), field)
		})
	}
}

func TestLoadReportsIssuesInDeterministicFileOrder(t *testing.T) {
	root := copyValidInventory(t)
	writeFile(t, filepath.Join(root, "services", "z-last.yaml"), "version: 1\nid: [\n")
	writeFile(t, filepath.Join(root, "services", "a-first.yaml"), "version: 1\nid: [\n")

	_, issues := opsconfig.Load(root)
	var files []string
	for _, issue := range issues {
		if strings.HasSuffix(issue.File, ".yaml") && strings.Contains(issue.File, "-") {
			files = append(files, issue.File)
		}
	}
	if !sort.StringsAreSorted(files) {
		t.Fatalf("issue files are not sorted: %v", files)
	}
}

func TestLoadValidatesIdentityEnvironmentsHostsAndRoots(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		id      string
		yaml    string
		field   string
		message string
	}{
		{name: "filename ID", file: "wrong-name.yaml", id: "actual-id", yaml: validService("actual-id"), field: "id", message: "filename"},
		{name: "version", file: "versioned.yaml", yaml: strings.Replace(validService("versioned"), "version: 1", "version: 2", 1), field: "version", message: "1"},
		{name: "environment name", file: "staging.yaml", yaml: strings.Replace(validService("staging"), "  local:", "  staging:", 1), field: "environments.staging", message: "local or production"},
		{name: "production kind", file: "kind.yaml", yaml: strings.Replace(validService("kind"), "kind: ssh", "kind: local", 1), field: "environments.production.kind", message: "ssh"},
		{name: "unknown host", file: "host.yaml", yaml: strings.Replace(validService("host"), "host: prod-demo", "host: missing", 1), field: "environments.production.host", message: "unknown"},
		{name: "unsafe root", file: "root.yaml", yaml: strings.Replace(validService("root"), "root: /opt/apps/", "root: /srv/", 1), field: "environments.production.root", message: "allowed root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			writeFile(t, filepath.Join(root, "services", tt.file), tt.yaml)
			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/"+tt.file, tt.field, tt.message)
			invalidID := tt.id
			if invalidID == "" {
				invalidID = strings.TrimSuffix(tt.file, ".yaml")
			}
			assertInvalidAbsentWithHealthySibling(t, inv, invalidID, "demo-api")
		})
	}
}

func TestLoadRejectsNonCanonicalProductionRoots(t *testing.T) {
	tests := []struct {
		name string
		root string
	}{
		{name: "traversal", root: "/opt/apps/root/../other"},
		{name: "dot segment", root: "/opt/apps/root/./release"},
		{name: "redundant separator", root: "/opt/apps//root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := strings.Replace(validService("canonical-root"), "root: /opt/apps/canonical-root", "root: "+tt.root, 1)
			writeFile(t, filepath.Join(root, "services", "canonical-root.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/canonical-root.yaml", "environments.production.root", "canonical")
			assertInvalidAbsentWithHealthySibling(t, inv, "canonical-root", "demo-api")
		})
	}
}

func TestLoadAcceptsProductionRootUnderHostAllowedRoot(t *testing.T) {
	root := copyValidInventory(t)
	hostsPath := filepath.Join(root, "hosts.yaml")
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostsPath, strings.Replace(string(hosts), "    architecture: amd64\n", "    architecture: amd64\n    allowedRoots:\n      - /opt/apps\n      - /home/maidou/projects/www\n", 1))
	service := strings.Replace(validService("resourcehub"), "root: /opt/apps/resourcehub", "root: /home/maidou/projects/www/ResourceHub", 1)
	writeFile(t, filepath.Join(root, "services", "resourcehub.yaml"), service)

	inv, issues := opsconfig.Load(root)
	if len(issues) != 0 {
		t.Fatalf("issues=%v", issues)
	}
	if _, ok := inv.Services["resourcehub"]; !ok {
		t.Fatal("resourcehub service was not loaded")
	}
}

func TestLoadRejectsProductionRootOutsideHostAllowedRoots(t *testing.T) {
	root := copyValidInventory(t)
	hostsPath := filepath.Join(root, "hosts.yaml")
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostsPath, strings.Replace(string(hosts), "    architecture: amd64\n", "    architecture: amd64\n    allowedRoots:\n      - /opt/apps\n      - /home/maidou/projects/www\n", 1))
	service := strings.Replace(validService("outside-root"), "root: /opt/apps/outside-root", "root: /home/maidou/other/outside-root", 1)
	writeFile(t, filepath.Join(root, "services", "outside-root.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/outside-root.yaml", "environments.production.root", "allowed root")
	assertInvalidAbsentWithHealthySibling(t, inv, "outside-root", "demo-api")
}

func TestLoadRejectsInvalidHostAllowedRootsAndRootItself(t *testing.T) {
	for _, allowedRoot := range []string{"/", "relative", "/home/maidou/projects/../www", "/home/maidou/projects/www/"} {
		t.Run(allowedRoot, func(t *testing.T) {
			root := copyValidInventory(t)
			hostsPath := filepath.Join(root, "hosts.yaml")
			hosts, err := os.ReadFile(hostsPath)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, hostsPath, strings.Replace(string(hosts), "    architecture: amd64\n", "    architecture: amd64\n    allowedRoots:\n      - "+allowedRoot+"\n", 1))

			_, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "hosts.yaml", "hosts.prod-demo.allowedRoots", "canonical absolute path")
		})
	}

	root := copyValidInventory(t)
	hostsPath := filepath.Join(root, "hosts.yaml")
	hosts, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, hostsPath, strings.Replace(string(hosts), "    architecture: amd64\n", "    architecture: amd64\n    allowedRoots:\n      - /opt/apps\n      - /home/maidou/projects/www\n", 1))
	service := strings.Replace(validService("root-itself"), "root: /opt/apps/root-itself", "root: /home/maidou/projects/www", 1)
	writeFile(t, filepath.Join(root, "services", "root-itself.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/root-itself.yaml", "environments.production.root", "below an allowed root")
	assertInvalidAbsentWithHealthySibling(t, inv, "root-itself", "demo-api")
}

func TestLoadRejectsEmptyAndDuplicateHostAllowedRoots(t *testing.T) {
	for _, roots := range []string{"[]", "\n      - /opt/apps\n      - /opt/apps"} {
		t.Run(strings.ReplaceAll(roots, "\n", "_"), func(t *testing.T) {
			root := copyValidInventory(t)
			hostsPath := filepath.Join(root, "hosts.yaml")
			hosts, err := os.ReadFile(hostsPath)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, hostsPath, strings.Replace(string(hosts), "    architecture: amd64\n", "    architecture: amd64\n    allowedRoots: "+roots+"\n", 1))

			_, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "hosts.yaml", "hosts.prod-demo.allowedRoots", "must contain unique roots")
		})
	}
}

func TestLoadRequiresLocalAndProductionEnvironments(t *testing.T) {
	root := copyValidInventory(t)
	service := validService("local-only")
	production := strings.Index(service, "  production:\n")
	service = service[:production]
	writeFile(t, filepath.Join(root, "services", "local-only.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/local-only.yaml", "environments.production", "required")
	assertInvalidAbsentWithHealthySibling(t, inv, "local-only", "demo-api")
}

func TestLoadAcceptsReadOnlyServiceWithoutBuild(t *testing.T) {
	root := copyValidInventory(t)
	service := validService("observe-only")
	start := strings.Index(service, "build:\n")
	end := strings.Index(service, "environments:\n")
	service = service[:start] + service[end:]
	writeFile(t, filepath.Join(root, "services", "observe-only.yaml"), service)

	inv, issues := opsconfig.Load(root)
	if len(issues) != 0 {
		t.Fatalf("issues=%v", issues)
	}
	if service, ok := inv.Services["observe-only"]; !ok || service.BuildConfigured() {
		t.Fatalf("observe-only service=%+v ok=%v", service, ok)
	}
}

func TestLoadAcceptsCloudflareWorkersProductionEnvironment(t *testing.T) {
	root := copyValidInventory(t)
	service := `version: 1
id: edge-relay
language: typescript
source:
  path: /Users/example/workspace/edge-relay
  repository: git@github.com:example/edge-relay.git
  repositoryRoot: /Users/example/workspace
  deploymentScope:
    - edge-relay
    - edge-admin
deployment:
  requireCommittedScope: false
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: edge-relay
    accountId: 0123456789abcdef0123456789abcdef
    wranglerConfig: wrangler.jsonc
    health:
      type: http
      url: https://api.example.test/health
      successStatuses: [200]
`
	writeFile(t, filepath.Join(root, "services", "edge-relay.yaml"), service)

	inv, issues := opsconfig.Load(root)
	if len(issues) != 0 {
		t.Fatalf("issues=%+v", issues)
	}
	production := inv.Services["edge-relay"].Environments[opsconfig.EnvironmentProduction]
	if production.Kind != opsconfig.EnvironmentKindCloudflareWorkers || production.Worker != "edge-relay" || production.AccountID != "0123456789abcdef0123456789abcdef" || production.WranglerConfig != "wrangler.jsonc" {
		t.Fatalf("production=%+v", production)
	}
	loaded := inv.Services["edge-relay"]
	if loaded.Source.RepositoryRoot != "/Users/example/workspace" || !reflect.DeepEqual(loaded.Source.DeploymentScope, []string{"edge-relay", "edge-admin"}) || loaded.Deployment.RequireCommittedScope {
		t.Fatalf("deployment identity=%+v policy=%+v", loaded.Source, loaded.Deployment)
	}
}

func TestLoadRejectsIncompleteCloudflareWorkersIdentity(t *testing.T) {
	root := copyValidInventory(t)
	service := `version: 1
id: invalid-worker
language: typescript
source:
  path: /Users/example/workspace/edge-relay
  repository: git@github.com:example/edge-relay.git
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: ''
    wranglerConfig: ../wrangler.jsonc
`
	writeFile(t, filepath.Join(root, "services", "invalid-worker.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssue(t, issues, "services/invalid-worker.yaml", "environments.production.worker")
	assertIssue(t, issues, "services/invalid-worker.yaml", "environments.production.wranglerConfig")
	assertInvalidAbsentWithHealthySibling(t, inv, "invalid-worker", "demo-api")
}

func TestLoadRejectsInvalidCloudflareAccountID(t *testing.T) {
	root := copyValidInventory(t)
	service := cloudflareService("invalid-account")
	service = strings.Replace(service, "accountId: 0123456789abcdef0123456789abcdef", "accountId: token-like-value", 1)
	writeFile(t, filepath.Join(root, "services", "invalid-account.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/invalid-account.yaml", "environments.production.accountId", "32 lowercase hexadecimal")
	assertInvalidAbsentWithHealthySibling(t, inv, "invalid-account", "demo-api")
}

func TestLoadRejectsUnsafeDeploymentScope(t *testing.T) {
	tests := []struct {
		name        string
		replacement string
		field       string
	}{
		{name: "relative repository root", replacement: "repositoryRoot: workspace", field: "source.repositoryRoot"},
		{name: "source outside repository root", replacement: "path: /Users/example/other/edge-relay", field: "source.path"},
		{name: "scope traversal", replacement: "    - ../edge-relay\n    - edge-admin", field: "source.deploymentScope.0"},
		{name: "duplicate scope", replacement: "    - edge-relay\n    - edge-relay", field: "source.deploymentScope"},
		{name: "overlapping scope", replacement: "    - edge-relay\n    - edge-relay/admin", field: "source.deploymentScope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := cloudflareService("unsafe-scope")
			switch tt.name {
			case "relative repository root":
				service = strings.Replace(service, "repositoryRoot: /Users/example/workspace", tt.replacement, 1)
			case "source outside repository root":
				service = strings.Replace(service, "path: /Users/example/workspace/edge-relay", tt.replacement, 1)
			default:
				service = strings.Replace(service, "    - edge-relay\n    - edge-admin", tt.replacement, 1)
			}
			writeFile(t, filepath.Join(root, "services", "unsafe-scope.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/unsafe-scope.yaml", tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, "unsafe-scope", "demo-api")
		})
	}
}

func TestLoadRejectsCloudflareAndSSHFieldMixing(t *testing.T) {
	tests := []struct {
		name    string
		service string
		field   string
	}{
		{
			name:    "Cloudflare account on SSH",
			service: strings.Replace(validService("mixed-ssh"), "    runner: systemd", "    accountId: 0123456789abcdef0123456789abcdef\n    runner: systemd", 1),
			field:   "environments.production.accountId",
		},
		{
			name:    "SSH host on Cloudflare",
			service: strings.Replace(cloudflareService("mixed-cloudflare"), "  production:\n    kind: cloudflare-workers\n    runner: manual", "  production:\n    kind: cloudflare-workers\n    host: prod-demo\n    runner: manual", 1),
			field:   "environments.production.host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			id := "mixed-ssh"
			if strings.Contains(tt.service, "id: mixed-cloudflare") {
				id = "mixed-cloudflare"
			}
			writeFile(t, filepath.Join(root, "services", id+".yaml"), tt.service)

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/"+id+".yaml", tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, id, "demo-api")
		})
	}
}

func cloudflareService(id string) string {
	return `version: 1
id: ` + id + `
language: typescript
source:
  path: /Users/example/workspace/edge-relay
  repository: git@github.com:example/edge-relay.git
  repositoryRoot: /Users/example/workspace
  deploymentScope:
    - edge-relay
    - edge-admin
deployment:
  requireCommittedScope: true
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: edge-relay
    accountId: 0123456789abcdef0123456789abcdef
    wranglerConfig: wrangler.jsonc
`
}

func TestLoadRejectsPartialBuildConfiguration(t *testing.T) {
	root := copyValidInventory(t)
	service := strings.Replace(validService("partial-build"), "  manifest: dist/demo.manifest.json\n", "", 1)
	writeFile(t, filepath.Join(root, "services", "partial-build.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/partial-build.yaml", "build.manifest", "must not be empty")
	assertInvalidAbsentWithHealthySibling(t, inv, "partial-build", "demo-api")
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	root := copyValidInventory(t)
	writeFile(t, filepath.Join(root, "services", "copy.yaml"), validService("demo-api"))

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/copy.yaml", "id", "duplicate")
	assertIssueContains(t, issues, "services/demo-api.yaml", "id", "duplicate")
	if len(inv.Services) != 0 {
		t.Fatalf("duplicate ID occurrences must all be excluded: %+v", inv.Services)
	}
}

func TestLoadValidatesRunnerSpecificFields(t *testing.T) {
	tests := []struct {
		name   string
		runner string
		extra  string
		field  string
	}{
		{name: "systemd requires unit", runner: "systemd", field: "unit"},
		{name: "php-fpm requires service", runner: "php-fpm", field: "service"},
		{name: "pm2 requires app", runner: "pm2", field: "app"},
		{name: "process requires command", runner: "process", extra: "    pidfile: /tmp/demo.pid\n    shutdownSignal: SIGTERM\n    logs: /tmp/demo.log\n", field: "command"},
		{name: "manual rejects lifecycle fields", runner: "manual", extra: "    unit: demo.service\n", field: "unit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := validService("runner")
			start := strings.Index(service, "    runner: systemd\n    unit: demo-api.service\n")
			service = service[:start] + "    runner: " + tt.runner + "\n" + tt.extra + service[start+len("    runner: systemd\n    unit: demo-api.service\n"):]
			writeFile(t, filepath.Join(root, "services", "runner.yaml"), service)
			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/runner.yaml", "environments.production."+tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, "runner", "demo-api")
		})
	}
}

func TestLoadRequiresConfigOwnerForPHPFPMAndPM2(t *testing.T) {
	tests := []struct {
		name   string
		runner string
		field  string
	}{
		{name: "php-fpm", runner: "php-fpm", field: "service: php8.3-fpm.service\n"},
		{name: "pm2", runner: "pm2", field: "app: demo-api\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := validService("config-owner-required")
			service = strings.Replace(service, "runner: systemd\n    unit: demo-api.service\n", "runner: "+tt.runner+"\n    "+tt.field, 1)
			writeFile(t, filepath.Join(root, "services", "config-owner-required.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/config-owner-required.yaml", "environments.production.configOwner", "required")
			assertInvalidAbsentWithHealthySibling(t, inv, "config-owner-required", "demo-api")
		})
	}
}

func TestLoadAcceptsSafeConfigOwnerForPHPFPMAndPM2(t *testing.T) {
	tests := []struct {
		name   string
		runner string
		fields string
		owner  string
	}{
		{name: "php-fpm", runner: "php-fpm", fields: "service: php8.3-fpm.service\n    configPath: /lib/systemd/system/php8.3-fpm.service\n", owner: "www-data"},
		{name: "pm2", runner: "pm2", fields: "app: demo-api\n    configPath: /opt/apps/demo-api/ecosystem.config.js\n", owner: "node_app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			enableHostCapability(t, root, tt.runner)
			service := validService("config-owner-valid")
			replacement := "runner: " + tt.runner + "\n    " + tt.fields + "    configOwner: " + tt.owner + "\n"
			service = strings.Replace(service, "runner: systemd\n    unit: demo-api.service\n", replacement, 1)
			writeFile(t, filepath.Join(root, "services", "config-owner-valid.yaml"), service)

			inv, issues := opsconfig.Load(root)
			if len(issues) != 0 {
				t.Fatalf("issues=%+v", issues)
			}
			if got := inv.Services["config-owner-valid"].Environments[opsconfig.EnvironmentProduction].ConfigOwner; got != tt.owner {
				t.Fatalf("configOwner=%q, want %q", got, tt.owner)
			}
		})
	}
}

func TestLoadRequiresCleanAbsolutePM2ConfigPath(t *testing.T) {
	for _, configPath := range []string{"", "ecosystem.config.js", "/opt/apps/demo/../shared.js", "/opt/apps/demo/config\n.js"} {
		root := copyValidInventory(t)
		enableHostCapability(t, root, opsconfig.RunnerPM2)
		service := validService("pm2-config-path")
		replacement := "runner: pm2\n    app: demo-api\n    configOwner: deploy\n"
		if configPath != "" {
			replacement += "    configPath: " + strconv.Quote(configPath) + "\n"
		}
		service = strings.Replace(service, "runner: systemd\n    unit: demo-api.service\n", replacement, 1)
		writeFile(t, filepath.Join(root, "services", "pm2-config-path.yaml"), service)
		inv, issues := opsconfig.Load(root)
		if _, exists := inv.Services["pm2-config-path"]; exists || !hasIssueField(issues, "configPath") {
			t.Fatalf("configPath=%q issues=%+v", configPath, issues)
		}
	}
}

func TestLoadRequiresCleanAbsolutePHPFPMConfigPath(t *testing.T) {
	for _, configPath := range []string{"", "php8.3-fpm.service", "/lib/systemd/system/../php8.3-fpm.service", "/lib/systemd/system/php8.3-fpm\n.service"} {
		root := copyValidInventory(t)
		enableHostCapability(t, root, opsconfig.RunnerPHPFPM)
		service := validService("php-fpm-config-path")
		replacement := "runner: php-fpm\n    service: php8.3-fpm.service\n    configOwner: root\n"
		if configPath != "" {
			replacement += "    configPath: " + strconv.Quote(configPath) + "\n"
		}
		service = strings.Replace(service, "runner: systemd\n    unit: demo-api.service\n", replacement, 1)
		writeFile(t, filepath.Join(root, "services", "php-fpm-config-path.yaml"), service)
		inv, issues := opsconfig.Load(root)
		if _, exists := inv.Services["php-fpm-config-path"]; exists || !hasIssueField(issues, "configPath") {
			t.Fatalf("configPath=%q issues=%+v", configPath, issues)
		}
	}
}

func TestLoadRejectsConfigOwnerForOtherRunners(t *testing.T) {
	for _, runner := range []string{"systemd", "process", "manual"} {
		t.Run(runner, func(t *testing.T) {
			root := copyValidInventory(t)
			service := validService("config-owner-forbidden")
			replacement := "    runner: systemd\n    unit: demo-api.service\n    configOwner: deploy\n"
			switch runner {
			case "process":
				replacement = "    runner: process\n    command: ./bin/demo-api\n    pidfile: /tmp/demo-api.pid\n    shutdownSignal: SIGTERM\n    logs: /tmp/demo-api.log\n    configOwner: deploy\n"
			case "manual":
				replacement = "    runner: manual\n    configOwner: deploy\n"
			}
			service = strings.Replace(service, "    runner: systemd\n    unit: demo-api.service\n", replacement, 1)
			writeFile(t, filepath.Join(root, "services", "config-owner-forbidden.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/config-owner-forbidden.yaml", "environments.production.configOwner", "not allowed")
			assertInvalidAbsentWithHealthySibling(t, inv, "config-owner-forbidden", "demo-api")
		})
	}
}

func TestConfigOwnerMatchesSafeUnixIdentityContract(t *testing.T) {
	valid := []string{"deploy", "www-data", "node_app", "app.user"}
	invalid := []string{"", "-deploy", "deploy user", "deploy\tuser", "deploy\nuser", "deploy/user", "deploy$user"}
	for _, owner := range append(valid, invalid...) {
		root := copyValidInventory(t)
		enableHostCapability(t, root, opsconfig.RunnerPM2)
		service := validService("config-owner-identity")
		replacement := "runner: pm2\n    app: demo-api\n    configOwner: " + strconv.Quote(owner) + "\n    configPath: /opt/apps/demo-api/ecosystem.config.js\n"
		service = strings.Replace(service, "runner: systemd\n    unit: demo-api.service\n", replacement, 1)
		writeFile(t, filepath.Join(root, "services", "config-owner-identity.yaml"), service)

		inv, issues := opsconfig.Load(root)
		_, exists := inv.Services["config-owner-identity"]
		wantValid := containsString(valid, owner)
		if exists != wantValid {
			t.Fatalf("owner=%q exists=%v issues=%+v", owner, exists, issues)
		}
		if !wantValid && !hasIssueField(issues, "configOwner") {
			t.Fatalf("owner=%q issues=%+v", owner, issues)
		}
	}
	schema := readJSONSchema(t, "service.schema.json")
	definitions := schema["$defs"].(map[string]any)
	for _, name := range []string{"localEnvironment", "productionEnvironment"} {
		properties := definitions[name].(map[string]any)["properties"].(map[string]any)
		if got := properties["configOwner"].(map[string]any)["pattern"]; got != opsconfig.ConfigOwnerPattern {
			t.Fatalf("%s configOwner pattern=%v, want %s", name, got, opsconfig.ConfigOwnerPattern)
		}
	}
}

func TestLoadRejectsTrailingYAMLDocumentsIndependently(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{name: "service", file: filepath.Join("services", "trailing.yaml")},
		{name: "hosts", file: "hosts.yaml"},
		{name: "policies", file: "policies.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			var content string
			if tt.name == "service" {
				content = validService("trailing")
			} else {
				data, err := os.ReadFile(filepath.Join(root, tt.file))
				if err != nil {
					t.Fatal(err)
				}
				content = string(data)
			}
			writeFile(t, filepath.Join(root, tt.file), content+"---\nversion: 1\n")

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, filepath.ToSlash(tt.file), "", "multiple YAML documents")
			if tt.name == "service" {
				assertInvalidAbsentWithHealthySibling(t, inv, "trailing", "demo-api")
			}
		})
	}
}

func TestLoadRejectsUnsafeBuildPaths(t *testing.T) {
	tests := []struct {
		name        string
		field       string
		replacement string
		message     string
	}{
		{name: "empty artifact", field: "artifact", replacement: "", message: "must not be empty"},
		{name: "directory artifact", field: "artifact", replacement: ".", message: "relative path"},
		{name: "absolute artifact", field: "artifact", replacement: "/tmp/demo.tar.gz", message: "relative path"},
		{name: "traversing artifact", field: "artifact", replacement: "dist/../../demo.tar.gz", message: "relative path"},
		{name: "empty manifest", field: "manifest", replacement: "", message: "must not be empty"},
		{name: "absolute manifest", field: "manifest", replacement: "/tmp/demo.json", message: "relative path"},
		{name: "traversing manifest", field: "manifest", replacement: "../demo.json", message: "relative path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := validService("unsafe-build")
			old := map[string]string{"artifact": "dist/demo.tar.gz", "manifest": "dist/demo.manifest.json"}[tt.field]
			service = strings.Replace(service, "  "+tt.field+": "+old, "  "+tt.field+": "+tt.replacement, 1)
			writeFile(t, filepath.Join(root, "services", "unsafe-build.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/unsafe-build.yaml", "build."+tt.field, tt.message)
			assertInvalidAbsentWithHealthySibling(t, inv, "unsafe-build", "demo-api")
		})
	}
}

func TestLoadRejectsProductionFieldsOnLocalEnvironment(t *testing.T) {
	root := copyValidInventory(t)
	service := strings.Replace(validService("local-production-fields"), "    kind: local\n", "    kind: local\n    host: prod-demo\n    root: /opt/apps/local-production-fields\n", 1)
	writeFile(t, filepath.Join(root, "services", "local-production-fields.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssue(t, issues, "services/local-production-fields.yaml", "environments.local.host")
	assertIssue(t, issues, "services/local-production-fields.yaml", "environments.local.root")
	assertInvalidAbsentWithHealthySibling(t, inv, "local-production-fields", "demo-api")
}

func TestLoadRequiresAbsoluteLocalProcessCommand(t *testing.T) {
	root := copyValidInventory(t)
	service := strings.Replace(validService("relative-local-command"), "command: /tmp/bin/demo", "command: ./bin/demo", 1)
	writeFile(t, filepath.Join(root, "services", "relative-local-command.yaml"), service)

	inv, issues := opsconfig.Load(root)
	assertIssueContains(t, issues, "services/relative-local-command.yaml", "environments.local.command", "absolute path")
	assertInvalidAbsentWithHealthySibling(t, inv, "relative-local-command", "demo-api")
}

func TestLoadRejectsUnsafeProcessContracts(t *testing.T) {
	tests := []struct {
		name, old, replacement, field string
	}{
		{"user", "user: deploy", "user: root;admin", "user"},
		{"command arguments", "command: /tmp/bin/demo", "command: /tmp/bin/demo --debug", "command"},
		{"pidfile", "pidfile: /tmp/demo.pid", "pidfile: tmp/demo.pid", "pidfile"},
		{"logs", "logs: /tmp/demo.log", "logs: /tmp/../demo.log", "logs"},
		{"signal", "shutdownSignal: SIGTERM", "shutdownSignal: SIGKILL", "shutdownSignal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := strings.Replace(validService("unsafe-process"), tt.old, tt.replacement, 1)
			writeFile(t, filepath.Join(root, "services", "unsafe-process.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/unsafe-process.yaml", "environments.local."+tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, "unsafe-process", "demo-api")
		})
	}
}

func TestLoadRequiresProductionRunnerHostCapability(t *testing.T) {
	tests := []struct {
		runner string
		fields string
	}{
		{runner: opsconfig.RunnerSystemd, fields: "    unit: demo.service\n"},
		{runner: opsconfig.RunnerPHPFPM, fields: "    service: php8.3-fpm\n"},
		{runner: opsconfig.RunnerPM2, fields: "    app: demo\n"},
	}
	for _, tt := range tests {
		t.Run(tt.runner, func(t *testing.T) {
			root := copyValidInventory(t)
			hosts := `version: 1
hosts:
  prod-demo:
    sshAlias: prod-demo
    platform: ubuntu
    architecture: amd64
    capabilities:
      - systemd
  prod-limited:
    sshAlias: prod-limited
    platform: ubuntu
    architecture: amd64
    capabilities: []
`
			writeFile(t, filepath.Join(root, "hosts.yaml"), hosts)
			service := strings.Replace(validService("unsupported-runner"), "host: prod-demo", "host: prod-limited", 1)
			start := strings.Index(service, "    runner: systemd\n    unit: demo-api.service\n")
			service = service[:start] + "    runner: " + tt.runner + "\n" + tt.fields + service[start+len("    runner: systemd\n    unit: demo-api.service\n"):]
			writeFile(t, filepath.Join(root, "services", "unsupported-runner.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/unsupported-runner.yaml", "environments.production.runner", "capability")
			assertInvalidAbsentWithHealthySibling(t, inv, "unsupported-runner", "demo-api")
		})
	}
}

func TestLoadRejectsSecretValuesButAllowsSecretKeyNames(t *testing.T) {
	for _, key := range []string{"password", "token", "private_key"} {
		t.Run(key, func(t *testing.T) {
			root := copyValidInventory(t)
			service := strings.Replace(validService("secret"), "secretKeys:\n        - DATABASE_PASSWORD", "secretKeys:\n        - DATABASE_PASSWORD\n      "+key+": plaintext", 1)
			writeFile(t, filepath.Join(root, "services", "secret.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssueContains(t, issues, "services/secret.yaml", key, "secret value")
			assertInvalidAbsentWithHealthySibling(t, inv, "secret", "demo-api")
		})
	}
}

func TestLoadAllowsApprovedReferences(t *testing.T) {
	inv, issues := opsconfig.Load(filepath.Join("testdata", "valid"))
	if len(issues) != 0 {
		t.Fatalf("approved references rejected: %+v", issues)
	}
	service := inv.Services["demo-api"]
	config := service.Environments[opsconfig.EnvironmentProduction].Config
	if inv.Hosts["prod-demo"].SSHAlias != "prod-demo" || len(config.Files) != 1 || len(config.RequiredKeys) != 1 || len(config.SecretKeys) != 1 {
		t.Fatalf("approved references not loaded: host=%+v config=%+v", inv.Hosts["prod-demo"], config)
	}
}

func TestLoadDoesNotExposeInvalidHostsOrDependentServices(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		field       string
	}{
		{name: "unsupported version", old: "version: 1", replacement: "version: 2", field: "version"},
		{name: "missing ssh alias", old: "sshAlias: prod-demo", replacement: "sshAlias: ''", field: "hosts.prod-demo.sshAlias"},
		{name: "whitespace ssh alias", old: "sshAlias: prod-demo", replacement: "sshAlias: '   '", field: "hosts.prod-demo.sshAlias"},
		{name: "non ubuntu platform", old: "platform: ubuntu", replacement: "platform: debian", field: "hosts.prod-demo.platform"},
		{name: "missing architecture", old: "architecture: amd64", replacement: "architecture: ''", field: "hosts.prod-demo.architecture"},
		{name: "whitespace architecture", old: "architecture: amd64", replacement: "architecture: '   '", field: "hosts.prod-demo.architecture"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			data, err := os.ReadFile(filepath.Join(root, "hosts.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "hosts.yaml"), strings.Replace(string(data), tt.old, tt.replacement, 1))

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "hosts.yaml", tt.field)
			assertIssue(t, issues, "services/demo-api.yaml", "environments.production.host")
			if len(inv.Hosts) != 0 || len(inv.Services) != 0 {
				t.Fatalf("invalid hosts or dependent services exposed: hosts=%+v services=%+v", inv.Hosts, inv.Services)
			}
		})
	}
}

func TestLoadDoesNotExposeInvalidPolicies(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		field       string
	}{
		{name: "unsupported version", old: "version: 1", replacement: "version: 2", field: "version"},
		{name: "empty default timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: ''", field: "execution.defaultTimeout"},
		{name: "invalid default timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: soon", field: "execution.defaultTimeout"},
		{name: "whitespace timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: ' 1s'", field: "execution.defaultTimeout"},
		{name: "non-positive health timeout", old: "healthTimeout: 10s", replacement: "healthTimeout: 0s", field: "execution.healthTimeout"},
		{name: "negative default timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: -1s", field: "execution.defaultTimeout"},
		{name: "leading plus timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: +1s", field: "execution.defaultTimeout"},
		{name: "micro sign timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: 1µs", field: "execution.defaultTimeout"},
		{name: "greek mu timeout", old: "defaultTimeout: 30s", replacement: "defaultTimeout: 1μs", field: "execution.defaultTimeout"},
		{name: "parallel batch", old: "batchConcurrency: 1", replacement: "batchConcurrency: 2", field: "execution.batchConcurrency"},
		{name: "preview disabled", old: "requirePreviewDigest: true", replacement: "requirePreviewDigest: false", field: "production.requirePreviewDigest"},
		{name: "manifest check disabled", old: "requireCleanArtifactManifest: true", replacement: "requireCleanArtifactManifest: false", field: "production.requireCleanArtifactManifest"},
		{name: "no retained releases", old: "retain: 3", replacement: "retain: 0", field: "releases.retain"},
		{name: "no server backups", old: "serverCopies: 1", replacement: "serverCopies: 0", field: "backups.serverCopies"},
		{name: "no local backups", old: "localCopies: 7", replacement: "localCopies: 0", field: "backups.localCopies"},
		{name: "encryption disabled", old: "requireEncryption: true", replacement: "requireEncryption: false", field: "backups.requireEncryption"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			data, err := os.ReadFile(filepath.Join(root, "policies.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "policies.yaml"), strings.Replace(string(data), tt.old, tt.replacement, 1))

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "policies.yaml", tt.field)
			if !reflect.DeepEqual(inv.Policies, opsconfig.Policies{}) {
				t.Fatalf("invalid policies exposed: %+v", inv.Policies)
			}
			if _, exists := inv.Services["demo-api"]; !exists {
				t.Fatalf("healthy service excluded by policy error: %+v", inv.Services)
			}
		})
	}
}

func TestLoadAcceptsPositiveGoDurationForms(t *testing.T) {
	for _, duration := range []string{"1.5s", "500.5ms", "1h30m", ".5s"} {
		t.Run(duration, func(t *testing.T) {
			root := copyValidInventory(t)
			data, err := os.ReadFile(filepath.Join(root, "policies.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "policies.yaml"), strings.Replace(string(data), "defaultTimeout: 30s", "defaultTimeout: "+duration, 1))

			inv, issues := opsconfig.Load(root)
			if len(issues) != 0 || inv.Policies.Execution.DefaultTimeout != duration {
				t.Fatalf("duration %q rejected: policies=%+v issues=%+v", duration, inv.Policies, issues)
			}
		})
	}
}

func TestLoadDoesNotExposeServicesWithIncompleteIdentity(t *testing.T) {
	tests := []struct {
		name        string
		old         string
		replacement string
		field       string
	}{
		{name: "language", old: "language: go", replacement: "language: ''", field: "language"},
		{name: "whitespace language", old: "language: go", replacement: "language: '   '", field: "language"},
		{name: "source location", old: "path: /Users/example/workspace/Demo", replacement: "path: ''", field: "source.path"},
		{name: "source repository", old: "repository: git@example.com:demo.git", replacement: "repository: ''", field: "source.repository"},
		{name: "build adapter", old: "adapter: command", replacement: "adapter: ''", field: "build.adapter"},
		{name: "build command", old: "command: ./scripts/build.sh", replacement: "command: ''", field: "build.command"},
		{name: "whitespace build command", old: "command: ./scripts/build.sh", replacement: "command: '   '", field: "build.command"},
		{name: "build artifact", old: "artifact: dist/demo.tar.gz", replacement: "artifact: ''", field: "build.artifact"},
		{name: "build manifest", old: "manifest: dist/demo.manifest.json", replacement: "manifest: ''", field: "build.manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := strings.Replace(validService("incomplete"), tt.old, tt.replacement, 1)
			writeFile(t, filepath.Join(root, "services", "incomplete.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/incomplete.yaml", tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, "incomplete", "demo-api")
		})
	}
}

func TestLoadAcceptsCanonicalSourcePathWithoutProject(t *testing.T) {
	root := copyValidInventory(t)
	service := strings.Replace(validService("direct-source"), "  path: /Users/example/workspace/Demo\n", "  path: /Users/example/workspace/direct-source\n", 1)
	writeFile(t, filepath.Join(root, "services", "direct-source.yaml"), service)

	inv, issues := opsconfig.Load(root)
	if len(issues) != 0 {
		t.Fatalf("direct source rejected: %+v", issues)
	}
	got := inv.Services["direct-source"].Source
	if got.Path != "/Users/example/workspace/direct-source" {
		t.Fatalf("source=%+v", got)
	}
}

func TestLoadRejectsMissingAndUnsafeSourceLocations(t *testing.T) {
	tests := []struct {
		name        string
		replacement string
		field       string
	}{
		{name: "missing", replacement: "", field: "source"},
		{name: "relative", replacement: "  path: workspace/demo\n", field: "source.path"},
		{name: "root", replacement: "  path: /\n", field: "source.path"},
		{name: "non canonical", replacement: "  path: /Users/example/../demo\n", field: "source.path"},
		{name: "control character", replacement: "  path: \"/Users/example/demo\\tbad\"\n", field: "source.path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			service := strings.Replace(validService("bad-source"), "  path: /Users/example/workspace/Demo\n", tt.replacement, 1)
			writeFile(t, filepath.Join(root, "services", "bad-source.yaml"), service)

			inv, issues := opsconfig.Load(root)
			assertIssue(t, issues, "services/bad-source.yaml", tt.field)
			assertInvalidAbsentWithHealthySibling(t, inv, "bad-source", "demo-api")
		})
	}
}

func TestFutureResourcesRemainPlanningOnly(t *testing.T) {
	root := copyValidInventory(t)
	writeFile(t, filepath.Join(root, "services", "future.yaml"), validService("future"))

	inv, issues := opsconfig.Load(root)
	if len(issues) != 0 || inv.Services["future"].FutureResources["redis"].Status != "planned" {
		t.Fatalf("planning metadata should load without runtime validation: inventory=%+v issues=%+v", inv, issues)
	}
}

func TestSchemasParseAndEnumsMatchGoConstants(t *testing.T) {
	for _, name := range []string{"service.schema.json", "hosts.schema.json", "policies.schema.json"} {
		data, err := os.ReadFile(filepath.Join("schema", name))
		if err != nil {
			t.Fatal(err)
		}
		var schema any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join("schema", "service.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	defs := schema["$defs"].(map[string]any)
	local := defs["localEnvironment"].(map[string]any)
	production := defs["productionEnvironment"].(map[string]any)
	localProperties := local["properties"].(map[string]any)
	productionProperties := production["properties"].(map[string]any)
	assertJSONConst(t, localProperties["kind"], opsconfig.EnvironmentKindLocal)
	assertJSONConst(t, productionProperties["kind"], opsconfig.EnvironmentKindSSH)
	assertJSONEnum(t, defs["runnerFields"].(map[string]any)["properties"].(map[string]any)["runner"], opsconfig.RunnerKinds)
	assertJSONEnum(t, localProperties["runner"], opsconfig.RunnerKinds)
	assertJSONEnum(t, productionProperties["runner"], opsconfig.RunnerKinds)
	if _, exists := localProperties["host"]; exists {
		t.Fatal("local schema must prohibit production host")
	}
	if _, exists := localProperties["root"]; exists {
		t.Fatal("local schema must prohibit production root")
	}
	assertRequiredFields(t, production, "kind", "host", "root", "runner")
	assertRunnerConditions(t, local)
	assertRunnerConditions(t, production)
	build := defs["build"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"artifact", "manifest"} {
		if build[field].(map[string]any)["pattern"] == "" {
			t.Fatalf("build.%s lacks safe relative-path pattern", field)
		}
	}

	policyData, err := os.ReadFile(filepath.Join("schema", "policies.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policies map[string]any
	if err := json.Unmarshal(policyData, &policies); err != nil {
		t.Fatal(err)
	}
	policyProperties := policies["properties"].(map[string]any)
	productionPolicy := policyProperties["production"].(map[string]any)["properties"].(map[string]any)
	assertJSONConst(t, productionPolicy["requirePreviewDigest"], true)
	assertJSONConst(t, productionPolicy["requireCleanArtifactManifest"], true)
	backupPolicy := policyProperties["backups"].(map[string]any)["properties"].(map[string]any)
	assertJSONConst(t, backupPolicy["requireEncryption"], true)
}

func TestServiceSchemaObjectDefinitionsAreStrict(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("schema", "service.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	for name, raw := range definitions {
		definition := raw.(map[string]any)
		if definition["type"] != "object" {
			continue
		}
		if strict, exists := definition["additionalProperties"]; !exists || strict != false {
			t.Errorf("$defs.%s additionalProperties=%v, want false", name, strict)
		}
	}
}

func TestSchemasMatchRuntimeStringAndPathConstraints(t *testing.T) {
	service := readJSONSchema(t, "service.schema.json")
	serviceProperties := service["properties"].(map[string]any)
	for _, required := range service["required"].([]any) {
		if required == "build" {
			t.Fatal("read-only services must not require build in the schema")
		}
	}
	assertRequiredStringSchema(t, serviceProperties["id"])
	assertRequiredStringSchema(t, serviceProperties["language"])
	definitions := service["$defs"].(map[string]any)
	for definition, fields := range map[string][]string{
		"source": {"repository"},
		"build":  {"adapter", "command", "artifact", "manifest"},
	} {
		properties := definitions[definition].(map[string]any)["properties"].(map[string]any)
		for _, field := range fields {
			assertRequiredStringSchema(t, properties[field])
		}
	}
	source := definitions["source"].(map[string]any)["properties"].(map[string]any)
	assertCanonicalPathPattern(t, source["path"], []string{"/Users/example/workspace/demo", "/opt/apps/demo"}, []string{"/", "relative/demo", "/Users/example/../demo", "/Users//demo"})
	if pattern := source["path"].(map[string]any)["pattern"].(string); !strings.Contains(pattern, "\\u0000") || !strings.Contains(pattern, "\\u007F") {
		t.Fatalf("source.path pattern lacks control-character guards: %q", pattern)
	}
	production := definitions["productionEnvironment"].(map[string]any)["properties"].(map[string]any)
	assertRequiredStringSchema(t, production["host"])
	assertCanonicalPathPattern(t, production["root"], []string{"/opt/apps/demo", "/opt/apps/demo/releases", "/home/maidou/projects/www/ResourceHub"}, []string{"/opt/apps/demo/../other", "/opt/apps/demo/./release", "/opt/apps//demo", "/home/maidou/projects/www/"})
	build := definitions["build"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"artifact", "manifest"} {
		pattern := build[field].(map[string]any)["pattern"].(string)
		if !strings.Contains(pattern, "\\.\\.") || !strings.Contains(pattern, "//") {
			t.Fatalf("build.%s pattern lacks traversal/separator guards: %q", field, pattern)
		}
	}

	hosts := readJSONSchema(t, "hosts.schema.json")
	hostProperties := hosts["properties"].(map[string]any)["hosts"].(map[string]any)["additionalProperties"].(map[string]any)["properties"].(map[string]any)
	sshAlias := hostProperties["sshAlias"].(map[string]any)
	if sshAlias["minLength"] != float64(1) || sshAlias["pattern"] != opsconfig.SSHAliasPattern {
		t.Fatalf("sshAlias schema=%v", sshAlias)
	}
	assertRequiredStringSchema(t, hostProperties["architecture"])
	assertJSONConst(t, hostProperties["platform"], "ubuntu")
	allowedRoots := hostProperties["allowedRoots"].(map[string]any)
	if allowedRoots["minItems"] != float64(1) || allowedRoots["uniqueItems"] != true {
		t.Fatalf("allowedRoots schema=%v", allowedRoots)
	}
	assertCanonicalPathPattern(t, allowedRoots["items"], []string{"/opt/apps", "/home/maidou/projects/www"}, []string{"/", "relative", "/home/maidou/projects/www/", "/home/maidou/projects/../www"})

	policies := readJSONSchema(t, "policies.schema.json")
	execution := policies["properties"].(map[string]any)["execution"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"defaultTimeout", "healthTimeout"} {
		definition := execution[field].(map[string]any)
		patternText := definition["pattern"].(string)
		if patternText != opsconfig.DurationPattern {
			t.Fatalf("%s pattern=%q, want Go runtime pattern %q", field, patternText, opsconfig.DurationPattern)
		}
		pattern := regexp.MustCompile(patternText)
		notDefinition, ok := definition["not"].(map[string]any)
		if !ok {
			t.Fatalf("%s must define an all-zero not.pattern", field)
		}
		notPattern := regexp.MustCompile(notDefinition["pattern"].(string))
		for _, valid := range []string{"30s", "10s", "500ms", "1m30s", "1.5s", "500.5ms", "1h30m", ".5s"} {
			if !durationAllowedBySchema(pattern, notPattern, valid) {
				t.Errorf("%s pattern rejects valid duration %q", field, valid)
			}
		}
		for _, invalid := range []string{"", "soon", " 1s", "1s ", "-1s", "+1s", "1µs", "1μs", "0s", "0.0s", "0s0ms"} {
			if durationAllowedBySchema(pattern, notPattern, invalid) {
				t.Errorf("%s pattern accepts invalid duration %q", field, invalid)
			}
		}
	}
}

func TestHealthContractValidationAndSchemaParity(t *testing.T) {
	tests := []struct {
		name        string
		health      string
		wantField   string
		wantInvalid bool
	}{
		{name: "http requires statuses", health: "      type: http\n      url: http://127.0.0.1/health\n", wantField: "successStatuses", wantInvalid: true},
		{name: "http accepts unique statuses", health: "      type: http\n      url: http://127.0.0.1/health\n      successStatuses: [200, 204]\n"},
		{name: "http rejects duplicates", health: "      type: http\n      url: http://127.0.0.1/health\n      successStatuses: [200, 200]\n", wantField: "successStatuses", wantInvalid: true},
		{name: "http rejects out of range", health: "      type: http\n      url: http://127.0.0.1/health\n      successStatuses: [99]\n", wantField: "successStatuses", wantInvalid: true},
		{name: "tcp rejects statuses", health: "      type: tcp\n      address: 127.0.0.1:8080\n      successStatuses: [200]\n", wantField: "successStatuses", wantInvalid: true},
		{name: "tcp rejects explicit empty statuses", health: "      type: tcp\n      address: 127.0.0.1:8080\n      successStatuses: []\n", wantField: "successStatuses", wantInvalid: true},
		{name: "command requires structured argv", health: "      type: command\n      command:\n        program: php\n        args: [-v]\n"},
		{name: "command rejects empty object", health: "      type: command\n      command: {}\n", wantField: "command.program", wantInvalid: true},
		{name: "tcp rejects empty command object", health: "      type: tcp\n      address: 127.0.0.1:8080\n      command: {}\n", wantField: "command", wantInvalid: true},
		{name: "command rejects scalar", health: "      type: command\n      command: php -v\n", wantInvalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			path := filepath.Join(root, "services", "demo-api.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(string(data), "    health:\n")
			if start < 0 {
				t.Fatal("health fixture missing")
			}
			data = []byte(string(data)[:start] + "    health:\n" + tt.health + "futureResources:\n  redis:\n    status: planned\n    intendedRoles:\n      - rate-limit\n")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			inv, issues := opsconfig.Load(root)
			_, exists := inv.Services["demo-api"]
			if tt.wantInvalid == exists {
				t.Fatalf("exists=%v issues=%+v", exists, issues)
			}
			if tt.wantInvalid && tt.wantField != "" && !hasIssueField(issues, tt.wantField) {
				t.Fatalf("issues=%+v want field %q", issues, tt.wantField)
			}
		})
	}

	schema := readJSONSchema(t, "service.schema.json")
	health := schema["$defs"].(map[string]any)["health"].(map[string]any)
	properties := health["properties"].(map[string]any)
	statuses := properties["successStatuses"].(map[string]any)
	if statuses["minItems"] != float64(1) || statuses["uniqueItems"] != true {
		t.Fatalf("successStatuses schema=%v", statuses)
	}
	command := properties["command"].(map[string]any)
	if command["$ref"] != "#/$defs/commandProbe" {
		t.Fatalf("command schema=%v", command)
	}
}

func TestSSHHostAliasMatchesExecutorSafetyContractAndSchema(t *testing.T) {
	valid := []string{"prod", "prod-1", "prod_1", "prod.example"}
	invalid := []string{"", "-prod", "prod host", "prod;rm", "prod/other", "prod\nother"}
	for _, alias := range append(valid, invalid...) {
		root := copyValidInventory(t)
		path := filepath.Join(root, "hosts.yaml")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), "sshAlias: prod-demo", "sshAlias: "+strconv.Quote(alias), 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, issues := opsconfig.Load(root)
		gotValid := !hasIssueField(issues, "sshAlias")
		wantValid := containsString(valid, alias)
		if gotValid != wantValid {
			t.Fatalf("alias=%q issues=%+v", alias, issues)
		}
	}
	hosts := readJSONSchema(t, "hosts.schema.json")
	definition := hosts["properties"].(map[string]any)["hosts"].(map[string]any)["additionalProperties"].(map[string]any)["properties"].(map[string]any)["sshAlias"].(map[string]any)
	if definition["pattern"] != opsconfig.SSHAliasPattern {
		t.Fatalf("schema pattern=%v runtime=%s", definition["pattern"], opsconfig.SSHAliasPattern)
	}
}

func TestHealthHTTPAndTCPConfigUseRuntimeSafetyContracts(t *testing.T) {
	tests := []struct{ name, health string }{{"http relative", "      type: http\n      url: /health\n      successStatuses: [200]\n"}, {"http ftp", "      type: http\n      url: ftp://example.com/health\n      successStatuses: [200]\n"}, {"http userinfo", "      type: http\n      url: http://user:secret@example.com/health\n      successStatuses: [200]\n"}, {"tcp option host", "      type: tcp\n      address: -host:80\n"}, {"tcp named port", "      type: tcp\n      address: host:http\n"}, {"tcp zero port", "      type: tcp\n      address: host:0\n"}, {"tcp high port", "      type: tcp\n      address: host:65536\n"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			path := filepath.Join(root, "services", "demo-api.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(string(data), "    health:\n")
			data = []byte(string(data)[:start] + "    health:\n" + tt.health + "futureResources:\n  redis:\n    status: planned\n")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			inv, issues := opsconfig.Load(root)
			if _, ok := inv.Services["demo-api"]; ok || len(issues) == 0 {
				t.Fatalf("issues=%+v", issues)
			}
		})
	}
	schema := readJSONSchema(t, "service.schema.json")
	health := schema["$defs"].(map[string]any)["health"].(map[string]any)["properties"].(map[string]any)
	if health["url"].(map[string]any)["pattern"] != opsconfig.HealthHTTPURLPattern || health["address"].(map[string]any)["pattern"] != opsconfig.HealthTCPAddressPattern {
		t.Fatalf("health schema=%v", health)
	}
}

func TestHealthTCPAddressSchemaMatchesRuntimePortBounds(t *testing.T) {
	schema := readJSONSchema(t, "service.schema.json")
	patternText := schema["$defs"].(map[string]any)["health"].(map[string]any)["properties"].(map[string]any)["address"].(map[string]any)["pattern"].(string)
	if patternText != opsconfig.HealthTCPAddressPattern {
		t.Fatalf("schema=%q runtime=%q", patternText, opsconfig.HealthTCPAddressPattern)
	}
	pattern := regexp.MustCompile(patternText)
	for _, value := range []string{"host:1", "host:65535", "[::1]:443"} {
		if !pattern.MatchString(value) {
			t.Errorf("schema rejects valid %q", value)
		}
	}
	for _, value := range []string{"host:0", "host:65536", "host:99999"} {
		if pattern.MatchString(value) {
			t.Errorf("schema accepts invalid %q", value)
		}
		if _, _, err := opsconfig.ParseHealthTCPAddress(value); err == nil {
			t.Errorf("runtime accepts invalid %q", value)
		}
	}
}

func TestCommandProbeControlCharactersMatchExecutorAndSchema(t *testing.T) {
	tests := []struct{ name, command string }{{"program newline", "        program: \"php\\nsecret\"\n"}, {"arg tab", "        program: php\n        args: [\"safe\\tunsafe\"]\n"}, {"arg nul", "        program: php\n        args: [\"safe\\0unsafe\"]\n"}, {"arg del", "        program: php\n        args: [\"safe\\x7Funsafe\"]\n"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := copyValidInventory(t)
			path := filepath.Join(root, "services", "demo-api.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(string(data), "    health:\n")
			health := "    health:\n      type: command\n      command:\n" + tt.command
			data = []byte(string(data)[:start] + health + "futureResources:\n  redis:\n    status: planned\n")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			inv, issues := opsconfig.Load(root)
			if _, ok := inv.Services["demo-api"]; ok || len(issues) == 0 {
				t.Fatalf("issues=%+v", issues)
			}
		})
	}
	schema := readJSONSchema(t, "service.schema.json")
	command := schema["$defs"].(map[string]any)["commandProbe"].(map[string]any)["properties"].(map[string]any)
	programPattern := regexp.MustCompile(command["program"].(map[string]any)["pattern"].(string))
	argPattern := regexp.MustCompile(command["args"].(map[string]any)["items"].(map[string]any)["pattern"].(string))
	if programPattern.String() != opsexec.CommandProgramPattern || argPattern.String() != opsexec.CommandArgumentPattern {
		t.Fatalf("schema patterns drifted from executor")
	}
	for _, value := range []string{"php\nsecret", "php\tsecret", "php\x00secret", "php\x7fsecret"} {
		if programPattern.MatchString(value) || argPattern.MatchString(value) {
			t.Errorf("schema accepts control value %q", value)
		}
	}
}

func hasIssueField(issues []opsconfig.Issue, suffix string) bool {
	for _, issue := range issues {
		if strings.HasSuffix(issue.Field, suffix) || strings.Contains(issue.Message, suffix) {
			return true
		}
	}
	return false
}

func durationAllowedBySchema(pattern, notPattern *regexp.Regexp, value string) bool {
	return pattern.MatchString(value) && !notPattern.MatchString(value)
}

func readJSONSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("schema", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertRequiredStringSchema(t *testing.T, value any) {
	t.Helper()
	definition := value.(map[string]any)
	if got := definition["minLength"]; got != float64(1) {
		t.Fatalf("minLength=%v, want 1", got)
	}
	pattern, ok := definition["pattern"].(string)
	if !ok || !strings.Contains(pattern, "\\S") {
		t.Fatalf("pattern=%q must require at least one non-whitespace character", pattern)
	}
}

func assertCanonicalPathPattern(t *testing.T, value any, valid, invalid []string) {
	t.Helper()
	pattern := value.(map[string]any)["pattern"].(string)
	if !strings.Contains(pattern, "\\.\\.") || !strings.Contains(pattern, "\\.") || !strings.Contains(pattern, "//") {
		t.Fatalf("canonical path pattern lacks required guards: %q", pattern)
	}
	for _, example := range append(valid, invalid...) {
		if example == "" {
			t.Fatal("path examples must be explicit")
		}
	}
}

func assertRunnerConditions(t *testing.T, environment map[string]any) {
	t.Helper()
	conditions := environment["allOf"].([]any)
	if len(conditions) != len(opsconfig.RunnerKinds) {
		t.Fatalf("runner condition count=%d, want %d", len(conditions), len(opsconfig.RunnerKinds))
	}
	wantRequired := map[string][]string{
		opsconfig.RunnerSystemd: {"unit"},
		opsconfig.RunnerPHPFPM:  {"service", "configOwner", "configPath"},
		opsconfig.RunnerPM2:     {"app", "configOwner", "configPath"},
		opsconfig.RunnerProcess: {"user", "command", "pidfile", "shutdownSignal", "logs"},
		opsconfig.RunnerManual:  {},
	}
	seen := make(map[string]bool)
	for _, raw := range conditions {
		condition := raw.(map[string]any)
		ifProperties := condition["if"].(map[string]any)["properties"].(map[string]any)
		runner := ifProperties["runner"].(map[string]any)["const"].(string)
		seen[runner] = true
		then := condition["then"].(map[string]any)
		assertRequiredFields(t, then, wantRequired[runner]...)
		prohibited := then["properties"].(map[string]any)
		for _, field := range []string{"unit", "service", "app", "command", "pidfile", "shutdownSignal", "logs", "configOwner", "configPath"} {
			if containsString(wantRequired[runner], field) {
				continue
			}
			if value, exists := prohibited[field]; !exists || value != false {
				t.Fatalf("runner %q must prohibit field %q", runner, field)
			}
		}
	}
	for _, runner := range opsconfig.RunnerKinds {
		if !seen[runner] {
			t.Fatalf("runner schema lacks condition for %q", runner)
		}
	}
}

func assertRequiredFields(t *testing.T, schema map[string]any, want ...string) {
	t.Helper()
	raw, exists := schema["required"]
	if len(want) == 0 {
		if exists && len(raw.([]any)) != 0 {
			t.Fatalf("required=%v, want none", raw)
		}
		return
	}
	if !exists {
		t.Fatalf("required missing, want %v", want)
	}
	got := make([]string, len(raw.([]any)))
	for i, value := range raw.([]any) {
		got[i] = value.(string)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("required=%v, want %v", got, want)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertJSONConst(t *testing.T, value any, want any) {
	t.Helper()
	if got := value.(map[string]any)["const"]; got != want {
		t.Fatalf("const=%v, want %v", got, want)
	}
}

func assertJSONEnum(t *testing.T, value any, want []string) {
	t.Helper()
	raw := value.(map[string]any)["enum"].([]any)
	got := make([]string, len(raw))
	for i := range raw {
		got[i] = raw[i].(string)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enum=%v, want %v", got, want)
	}
}

func assertIssue(t *testing.T, issues []opsconfig.Issue, file, field string) {
	t.Helper()
	for _, issue := range issues {
		if issue.File == file && strings.Contains(issue.Field, field) {
			return
		}
	}
	t.Fatalf("missing issue file=%q field=%q in %+v", file, field, issues)
}

func assertIssueContains(t *testing.T, issues []opsconfig.Issue, file, field, message string) {
	t.Helper()
	for _, issue := range issues {
		if issue.File == file && strings.Contains(issue.Field, field) && strings.Contains(issue.Message, message) {
			return
		}
	}
	t.Fatalf("missing issue file=%q field=%q message=%q in %+v", file, field, message, issues)
}

func assertInvalidAbsentWithHealthySibling(t *testing.T, inv opsconfig.Inventory, invalidID, healthyID string) {
	t.Helper()
	if _, exists := inv.Services[invalidID]; exists {
		t.Fatalf("invalid service %q was loaded: %+v", invalidID, inv.Services[invalidID])
	}
	if _, exists := inv.Services[healthyID]; !exists {
		t.Fatalf("healthy sibling %q was excluded: %+v", healthyID, inv.Services)
	}
}

func copyValidInventory(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"hosts.yaml", "policies.yaml", filepath.Join("services", "demo-api.yaml")} {
		data, err := os.ReadFile(filepath.Join("testdata", "valid", name))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, name), string(data))
	}
	return root
}

func enableHostCapability(t *testing.T, root, capability string) {
	t.Helper()
	path := filepath.Join(root, "hosts.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "      - systemd\n", "      - systemd\n      - "+capability+"\n", 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func validService(id string) string {
	return `version: 1
id: ` + id + `
language: go
source:
  path: /Users/example/workspace/Demo
  repository: git@example.com:demo.git
build:
  adapter: command
  command: ./scripts/build.sh
  artifact: dist/demo.tar.gz
  manifest: dist/demo.manifest.json
environments:
  local:
    kind: local
    runner: process
    user: deploy
    command: /tmp/bin/demo
    pidfile: /tmp/demo.pid
    shutdownSignal: SIGTERM
    logs: /tmp/demo.log
  production:
    kind: ssh
    host: prod-demo
    root: /opt/apps/` + id + `
    runner: systemd
    unit: demo-api.service
    config:
      files:
        - shared/config/app.env
      requiredKeys:
        - DATABASE_URL
      secretKeys:
        - DATABASE_PASSWORD
futureResources:
  redis:
    status: planned
`
}
