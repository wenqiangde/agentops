package opscli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsrunner"
	"github.com/wenqiangde/agentops/internal/paths"
)

func executeRootCommand(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) (int, bool) {
	if len(args) == 0 || args[0] != "ops" {
		return 1, false
	}
	return RunWithPaths(p, args[1:], stdout, stderr), true
}

func TestOpsValidateReportsValidAndInvalidFiles(t *testing.T) {
	p := opsTestPaths(t, "partially-invalid")
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "validate", "all"}, &out, &errOut)
	if !handled {
		t.Fatal("ops command was not handled")
	}
	if code != 1 || !strings.Contains(out.String(), "healthy-api: valid") || !strings.Contains(errOut.String(), "services/broken-api.yaml") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestOpsListFiltersDeterministically(t *testing.T) {
	p := opsTestPaths(t, "valid")
	writeOpsService(t, p.OperationsRoot, "alpha-api", "java", "prod-other")
	writeOpsHost(t, p.OperationsRoot, "prod-other")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "language", args: []string{"ops", "list", "--language", "go"}, want: "demo-api\tgo\tlocal=process\tproduction=systemd\thost=prod-demo\n"},
		{name: "host", args: []string{"ops", "list", "--host", "prod-other"}, want: "alpha-api\tjava\tlocal=process\tproduction=systemd\thost=prod-other\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code, handled := executeRootCommand(p, tt.args, &out, &errOut)
			if !handled || code != 0 || errOut.Len() != 0 || out.String() != tt.want {
				t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
			}
		})
	}
}

func TestOpsInspectEnvironmentAndUnknownService(t *testing.T) {
	stubOpsRunner(t, &cliRunner{})
	p := opsTestPaths(t, "valid")
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "inspect", "demo-api", "--environment", "production"}, &out, &errOut)
	if !handled || code != 0 || errOut.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
	for _, want := range []string{"service: demo-api", "language: go", "repository: git@example.com:demo.git", "environment: production", "kind: ssh", "host: prod-demo", "runner: systemd", "root: /opt/apps/demo-api"} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Fatalf("inspect output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	errOut.Reset()
	code, handled = executeRootCommand(p, []string{"ops", "inspect", "missing"}, &out, &errOut)
	if !handled || code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "unknown service: missing") {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
}

func TestOpsInspectRunsDeclaredRunnerWithMappedSSHAlias(t *testing.T) {
	p := opsTestPaths(t, "valid")
	before := opsTree(t, p.OperationsRoot)
	original := opsRunnerNew
	defer func() { opsRunnerNew = original }()
	fake := &cliRunner{}
	opsRunnerNew = func(kind string, executor opsexec.Executor) opsrunner.Runner {
		fake.kind = kind
		fake.executor = executor
		return fake
	}
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "inspect", "demo-api", "--environment", "production"}, &out, &errOut)
	if code != 0 || fake.environment.Host != "prod-demo" || fake.kind != opsconfig.RunnerSystemd || !strings.Contains(out.String(), "state: running\n") {
		t.Fatalf("code=%d out=%q err=%q fake=%+v", code, out.String(), errOut.String(), fake)
	}
	if after := opsTree(t, p.OperationsRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("inspect wrote operations tree")
	}
}

func TestOpsInspectRejectsInvalidPoliciesAndRunnerTimeout(t *testing.T) {
	for _, value := range []string{"invalid", "0s"} {
		p := opsTestPaths(t, "valid")
		replacePolicyValue(t, p.OperationsRoot, "defaultTimeout: 30s", "defaultTimeout: "+value)
		fake := &cliRunner{}
		stubOpsRunner(t, fake)
		var out, errOut bytes.Buffer
		code, _ := executeRootCommand(p, []string{"ops", "inspect", "demo-api", "--environment", "production"}, &out, &errOut)
		if code != 1 || fake.calls != 0 || !strings.Contains(errOut.String(), "policies.yaml") {
			t.Fatalf("value=%q code=%d calls=%d out=%q err=%q", value, code, fake.calls, out.String(), errOut.String())
		}
	}
	p := opsTestPaths(t, "valid")
	fake := &cliRunner{check: opsrunner.Check{State: opsrunner.StateUnknown, Err: context.DeadlineExceeded}}
	stubOpsRunner(t, fake)
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "inspect", "demo-api", "--environment", "production"}, &out, &errOut)
	if code != 1 || fake.calls != 1 || !fake.hasDeadline {
		t.Fatalf("code=%d fake=%+v out=%q err=%q", code, fake, out.String(), errOut.String())
	}
}

func TestOpsInspectDoesNotPrintRunnerDetailPayload(t *testing.T) {
	p := opsTestPaths(t, "valid")
	fake := &cliRunner{check: opsrunner.Check{State: opsrunner.StateRunning, Detail: "credential-payload"}}
	stubOpsRunner(t, fake)
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "inspect", "demo-api", "--environment", "production"}, &out, &errOut)
	if code != 0 || strings.Contains(out.String(), "credential-payload") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

type cliRunner struct {
	kind        string
	executor    opsexec.Executor
	environment opsconfig.Environment
	check       opsrunner.Check
	calls       int
	hasDeadline bool
}

func stubOpsRunner(t *testing.T, runner opsrunner.Runner) {
	t.Helper()
	original := opsRunnerNew
	t.Cleanup(func() { opsRunnerNew = original })
	opsRunnerNew = func(string, opsexec.Executor) opsrunner.Runner { return runner }
}

func (r *cliRunner) Inspect(ctx context.Context, _ opsconfig.Service, e opsconfig.Environment) opsrunner.Check {
	r.environment = e
	r.calls++
	_, r.hasDeadline = ctx.Deadline()
	if r.check.State != "" || r.check.Err != nil {
		return r.check
	}
	return opsrunner.Check{State: opsrunner.StateRunning, Detail: "active"}
}
func (r *cliRunner) Start(context.Context, opsconfig.Service, opsconfig.Environment) opsrunner.Check {
	return opsrunner.Check{}
}
func (r *cliRunner) Stop(context.Context, opsconfig.Service, opsconfig.Environment) opsrunner.Check {
	return opsrunner.Check{}
}
func (r *cliRunner) Restart(context.Context, opsconfig.Service, opsconfig.Environment) opsrunner.Check {
	return opsrunner.Check{}
}
func (r *cliRunner) Logs(context.Context, opsconfig.Service, opsconfig.Environment, time.Duration) opsrunner.Check {
	return opsrunner.Check{}
}

func TestOpsInspectRedactsRepositoryCredentials(t *testing.T) {
	stubOpsRunner(t, &cliRunner{})
	p := opsTestPaths(t, "valid")
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "git@example.com:demo.git", "https://user:token@example.com/repo.git?token=x#fragment", 1))
	if err := os.WriteFile(servicePath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "inspect", "demo-api"}, &out, &errOut)
	if !handled || code != 0 || errOut.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "repository: https://example.com/repo.git\n") {
		t.Fatalf("sanitized repository missing: %q", out.String())
	}
	for _, secret := range []string{"user", "token", "?", "#", "fragment"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("inspect leaked %q: %q", secret, out.String())
		}
	}

	data = []byte(strings.Replace(string(data), "https://user:token@example.com/repo.git?token=x#fragment", "https:%zz", 1))
	if err := os.WriteFile(servicePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	code, handled = executeRootCommand(p, []string{"ops", "inspect", "demo-api"}, &out, &errOut)
	if !handled || code != 0 || !strings.Contains(out.String(), "repository: [invalid URL]\n") || strings.Contains(out.String(), "%zz") {
		t.Fatalf("invalid URL was not safely displayed: handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
}

func TestSafeOpsLocationFailClosedBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "scp-like", value: "git@example.com:team/repo.git", want: "git@example.com:team/repo.git"},
		{name: "network path", value: "//user:token@example.com/repo.git?token=x#fragment", want: "//example.com/repo.git"},
		{name: "opaque URL", value: "ssh:git@example.com/repo.git", want: "[invalid URL]"},
		{name: "parse failure without scheme", value: "%zz", want: "[invalid URL]"},
		{name: "suspicious at", value: "user@example.com/repo.git", want: "[invalid URL]"},
		{name: "suspicious query", value: "repo.git?token=x", want: "[invalid URL]"},
		{name: "suspicious fragment", value: "repo.git#token", want: "[invalid URL]"},
		{name: "scp-like whitespace", value: "git user@example.com:repo.git", want: "[invalid URL]"},
		{name: "scp-like slash in user", value: "team/git@example.com:repo.git", want: "[invalid URL]"},
		{name: "scp-like slash in host", value: "git@example.com/team:repo.git", want: "[invalid URL]"},
		{name: "scp-like empty path", value: "git@example.com:", want: "[invalid URL]"},
		{name: "plain path", value: "team/repo.git", want: "team/repo.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeOpsLocation(tt.value); got != tt.want {
				t.Fatalf("safeOpsLocation(%q)=%q want=%q", tt.value, got, tt.want)
			}
		})
	}
}

func TestSafeOpsLocationRejectsOutputControlCharacters(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "newline forged output", value: "team/repo.git\nservice: forged"},
		{name: "carriage return", value: "team/repo.git\rforged"},
		{name: "tab in scp path", value: "git@example.com:team/\trepo.git"},
		{name: "NUL in path", value: "team/repo\x00.git"},
		{name: "DEL in URL", value: "https://example.com/repo\x7f.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeOpsLocation(tt.value)
			if got != "[invalid URL]" {
				t.Fatalf("safeOpsLocation(%q)=%q want fail-closed placeholder", tt.value, got)
			}
			if strings.Contains(got, "forged") || strings.ContainsAny(got, "\r\n\t\x00\x7f") {
				t.Fatalf("safe output retained injected content: %q", got)
			}
		})
	}
}

func TestOpsValidateUsesFilenameAsServiceIdentity(t *testing.T) {
	p := opsTestPaths(t, "valid")
	writeOpsService(t, p.OperationsRoot, "declared-id", "go", "prod-demo")
	if err := os.Rename(filepath.Join(p.OperationsRoot, "services", "declared-id.yaml"), filepath.Join(p.OperationsRoot, "services", "wrong-name.yaml")); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "validate", "wrong-name"}, &out, &errOut)
	if !handled || code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "services/wrong-name.yaml:id:") || !strings.Contains(errOut.String(), "filename") {
		t.Fatalf("filename lookup handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	code, handled = executeRootCommand(p, []string{"ops", "validate", "declared-id"}, &out, &errOut)
	if !handled || code != 1 || out.Len() != 0 || errOut.String() != "agentops: unknown service: declared-id\n" {
		t.Fatalf("declared ID lookup handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
}

func TestOpsReadCommandsDoNotWrite(t *testing.T) {
	stubOpsRunner(t, &cliRunner{})
	p := opsTestPaths(t, "valid")
	before := opsTree(t, p.OperationsRoot)
	for _, args := range [][]string{
		{"ops", "validate", "all"},
		{"ops", "list"},
		{"ops", "inspect", "demo-api"},
	} {
		var out, errOut bytes.Buffer
		code, handled := executeRootCommand(p, args, &out, &errOut)
		if !handled || code != 0 {
			t.Fatalf("args=%v handled=%v code=%d stderr=%q", args, handled, code, errOut.String())
		}
	}
	after := opsTree(t, p.OperationsRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read commands changed operations tree:\nbefore=%v\nafter=%v", before, after)
	}

	missing := filepath.Join(t.TempDir(), "missing-operations")
	p.OperationsRoot = missing
	var out, errOut bytes.Buffer
	executeRootCommand(p, []string{"ops", "list"}, &out, &errOut)
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("ops list created missing operations root: %v", err)
	}
}

func TestOpsHealthAllContinuesAfterFailureInServiceOrderAndDoesNotWrite(t *testing.T) {
	p := opsTestPaths(t, "valid")
	writeOpsService(t, p.OperationsRoot, "alpha-api", "go", "prod-demo")
	before := opsTree(t, p.OperationsRoot)
	original := opsHealthProbe
	defer func() { opsHealthProbe = original }()
	var seen []string
	opsHealthProbe = func(_ context.Context, _ opsexec.Executor, _ opsconfig.Environment, h opsconfig.Health, _ time.Duration) opshealth.Result {
		seen = append(seen, h.URL)
		if strings.Contains(h.URL, "alpha-api") {
			return opshealth.Result{Healthy: false, Detail: "unhealthy"}
		}
		return opshealth.Result{Healthy: true, Detail: "healthy"}
	}
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "health", "all", "--environment", "production"}, &out, &errOut)
	if !handled || code != 1 || !strings.Contains(out.String(), "demo-api\thealthy") || !strings.Contains(out.String(), "alpha-api\tunhealthy") || strings.Index(out.String(), "alpha-api") > strings.Index(out.String(), "demo-api") {
		t.Fatalf("handled=%v code=%d out=%q err=%q seen=%v", handled, code, out.String(), errOut.String(), seen)
	}
	if after := opsTree(t, p.OperationsRoot); !reflect.DeepEqual(before, after) {
		t.Fatalf("health wrote files: before=%v after=%v", before, after)
	}
}

func TestOpsHealthAllReportsInvalidServiceAndContinuesValidServices(t *testing.T) {
	p := opsTestPaths(t, "partially-invalid")
	path := filepath.Join(p.OperationsRoot, "services", "healthy-api.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("    health:\n      type: command\n      command:\n        program: \"true\"\n")...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	original := opsHealthProbe
	defer func() { opsHealthProbe = original }()
	calls := 0
	opsHealthProbe = func(context.Context, opsexec.Executor, opsconfig.Environment, opsconfig.Health, time.Duration) opshealth.Result {
		calls++
		return opshealth.Result{Healthy: true, Detail: "checked"}
	}
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "health", "all", "--environment", "production"}, &out, &errOut)
	if code != 1 || calls != 1 || !strings.Contains(out.String(), "healthy-api\thealthy") || !strings.Contains(errOut.String(), "services/broken-api.yaml") {
		t.Fatalf("code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, []string{"ops", "health", "broken-api", "--environment", "production"}, &out, &errOut)
	if code != 1 || calls != 1 || !strings.Contains(errOut.String(), "services/broken-api.yaml") {
		t.Fatalf("single invalid code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
	}
}

func TestOpsHealthRequiresExplicitEnvironment(t *testing.T) {
	p := opsTestPaths(t, "valid")
	for _, args := range [][]string{{"ops", "health", "demo-api"}, {"ops", "health", "demo-api", "--environment", "staging"}} {
		var out, errOut bytes.Buffer
		code, _ := executeRootCommand(p, args, &out, &errOut)
		if code != 1 || !strings.Contains(errOut.String(), agentOpsUsage) {
			t.Fatalf("args=%v code=%d err=%q", args, code, errOut.String())
		}
	}
}

func TestOpsHealthRejectsInvalidPoliciesWithoutProbe(t *testing.T) {
	for _, value := range []string{"invalid", "0s"} {
		p := opsTestPaths(t, "valid")
		replacePolicyValue(t, p.OperationsRoot, "healthTimeout: 10s", "healthTimeout: "+value)
		original := opsHealthProbe
		calls := 0
		opsHealthProbe = func(context.Context, opsexec.Executor, opsconfig.Environment, opsconfig.Health, time.Duration) opshealth.Result {
			calls++
			return opshealth.Result{Healthy: true}
		}
		var out, errOut bytes.Buffer
		code, _ := executeRootCommand(p, []string{"ops", "health", "all", "--environment", "production"}, &out, &errOut)
		opsHealthProbe = original
		if code != 1 || calls != 0 || !strings.Contains(errOut.String(), "policies.yaml") {
			t.Fatalf("value=%q code=%d calls=%d out=%q err=%q", value, code, calls, out.String(), errOut.String())
		}
	}
}

func TestOpsHealthNeverPrintsProbeErrorPayload(t *testing.T) {
	p := opsTestPaths(t, "valid")
	original := opsHealthProbe
	defer func() { opsHealthProbe = original }()
	secret := "token=top-secret"
	opsHealthProbe = func(context.Context, opsexec.Executor, opsconfig.Environment, opsconfig.Health, time.Duration) opshealth.Result {
		return opshealth.Result{Type: "http", Err: fmt.Errorf("request failed: %s", secret)}
	}
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "health", "demo-api", "--environment", "production"}, &out, &errOut)
	if code != 1 || strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) || !strings.Contains(out.String(), "http probe failed") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestOpsUsageAndMetadata(t *testing.T) {
	p := opsTestPaths(t, "valid")
	const wantUsage = "Usage: agentops [validate <all|service>|list [--language <language>] [--host <host>]|inspect <service> [--environment <local|production>]|build <service>|health <service|all> --environment <local|production>|deploy <service> --environment production --version <version>|rollback <service> --environment production --version <version>|backup <service> --environment production]\n"
	for _, tt := range []struct {
		name   string
		args   []string
		stderr string
	}{
		{name: "missing command", args: []string{"ops"}, stderr: "agentops: missing command\n" + wantUsage},
		{name: "unknown list flag", args: []string{"ops", "list", "--unknown"}, stderr: "agentops: unknown list option: --unknown\n" + wantUsage},
		{name: "missing inspect argument", args: []string{"ops", "inspect"}, stderr: "agentops: inspect requires one service\n" + wantUsage},
		{name: "invalid environment", args: []string{"ops", "inspect", "demo-api", "--environment", "staging"}, stderr: "agentops: --environment must be local or production\n" + wantUsage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code, handled := executeRootCommand(p, tt.args, &out, &errOut)
			if !handled || code != 1 || out.Len() != 0 || errOut.String() != tt.stderr {
				t.Fatalf("args=%v handled=%v code=%d out=%q err=%q wantErr=%q", tt.args, handled, code, out.String(), errOut.String(), tt.stderr)
			}
		})
	}

}

func TestOpsBuildProducesVerifiedArtifactSummary(t *testing.T) {
	p := opsBuildTestPaths(t)
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &out, &errOut)
	if !handled || code != 0 || errOut.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
	for _, want := range []string{"service: demo-api", "version: 1.2.3", "commit: 0123456789abcdef", "target: linux/amd64", "archive: ", "size: ", "sha256: "} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestOpsBuildUsesDirectSourcePathWithoutProjectConfiguration(t *testing.T) {
	p := opsBuildTestPaths(t)
	projectPath := buildProjectPath(t, p)
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "  path: /Users/example/workspace/Demo\n", "  project: MissingProject\n  path: "+projectPath+"\n", 1))
	if err := os.WriteFile(servicePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := opsCommand(p, []string{"build", "demo-api"}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "version: 1.2.3") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestOpsBuildRejectsMissingSourceInvalidTimeoutAndCommandFailure(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*paths.Paths)
		want   string
	}{
		{name: "missing source", mutate: func(p *paths.Paths) {
			servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
			data, err := os.ReadFile(servicePath)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), "  path: "+buildProjectPath(t, *p)+"\n", "", 1))
			if err := os.WriteFile(servicePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "source.path"},
		{name: "invalid timeout", mutate: func(p *paths.Paths) {
			replacePolicyValue(t, p.OperationsRoot, "defaultTimeout: 30s", "defaultTimeout: invalid")
		}, want: "policies.yaml"},
		{name: "command failure", mutate: func(p *paths.Paths) {
			project := buildProjectPath(t, *p)
			if err := os.WriteFile(filepath.Join(project, "scripts", "build.sh"), []byte("#!/bin/sh\necho token=private\nexit 7\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, want: "build command failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := opsBuildTestPaths(t)
			tt.mutate(&p)
			var out, errOut bytes.Buffer
			code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &out, &errOut)
			if code != 1 || !strings.Contains(errOut.String(), tt.want) || strings.Contains(out.String()+errOut.String(), "private") || strings.Contains(out.String()+errOut.String(), "token=") {
				t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestOpsReadOnlyServiceRejectsManagedReleaseCommandsBeforeExecution(t *testing.T) {
	p := opsTestPaths(t, "valid")
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	service := string(data)
	start := strings.Index(service, "build:\n")
	end := strings.Index(service, "environments:\n")
	if start < 0 || end <= start {
		t.Fatal("fixture build block not found")
	}
	service = service[:start] + service[end:]
	localStart := strings.Index(service, "  local:\n")
	productionStart := strings.Index(service, "  production:\n")
	if localStart < 0 || productionStart <= localStart {
		t.Fatal("fixture local environment not found")
	}
	service = service[:localStart] + "  local:\n    kind: local\n    runner: manual\n" + service[productionStart:]
	if err := os.WriteFile(servicePath, []byte(service), 0o600); err != nil {
		t.Fatal(err)
	}

	deploy := &cliDeployExecutor{}
	rollback := &cliRollbackExecutor{}
	originalDeploy := opsDeployExecutor
	originalRollback := opsRollbackExecutor
	opsDeployExecutor = func() opsexec.Executor { return deploy }
	opsRollbackExecutor = func() opsexec.Executor { return rollback }
	t.Cleanup(func() {
		opsDeployExecutor = originalDeploy
		opsRollbackExecutor = originalRollback
	})

	for _, args := range [][]string{
		{"ops", "build", "demo-api"},
		{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"},
		{"ops", "rollback", "demo-api", "--environment", "production", "--version", "1.2.3"},
	} {
		var out, errOut bytes.Buffer
		code, _ := executeRootCommand(p, args, &out, &errOut)
		if code != 1 || !strings.Contains(errOut.String(), "managed build/deploy configuration") || out.Len() != 0 {
			t.Fatalf("args=%v code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
	if len(deploy.runs) != 0 || len(deploy.copies) != 0 || len(rollback.runs) != 0 || len(rollback.copies) != 0 {
		t.Fatalf("release rejection executed commands: deploy=%v/%v rollback=%v/%v", deploy.runs, deploy.copies, rollback.runs, rollback.copies)
	}

	for _, args := range [][]string{
		{"ops", "validate", "demo-api"},
		{"ops", "list"},
		{"ops", "inspect", "demo-api", "--environment", "local"},
	} {
		var out, errOut bytes.Buffer
		code, _ := executeRootCommand(p, args, &out, &errOut)
		if code != 0 || errOut.Len() != 0 {
			t.Fatalf("read args=%v code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

type cliDeployExecutor struct {
	runs         []opsexec.Request
	copies       []opsexec.CopyRequest
	trace        []string
	allowWrites  bool
	failCopy     bool
	remoteDigest string
}

func (e *cliDeployExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.runs = append(e.runs, request)
	e.trace = append(e.trace, request.Program+" "+strings.Join(request.Args, " "))
	switch request.Program {
	case "test":
		if len(request.Args) == 2 && strings.Contains(request.Args[1], "/releases/1.2.3") {
			return opsexec.Result{ExitCode: 1, Err: fmt.Errorf("exit status 1")}
		}
		return opsexec.Result{ExitCode: 0}
	case "readlink":
		return opsexec.Result{ExitCode: 0, Stdout: "/opt/apps/demo-api/releases/1.1.0\n"}
	case "id":
		return opsexec.Result{ExitCode: 0, Stdout: "deploy\n"}
	case "uname":
		return opsexec.Result{ExitCode: 0, Stdout: "Linux x86_64\n"}
	case "df":
		return opsexec.Result{ExitCode: 0, Stdout: "1048576\n"}
	case "which":
		if len(request.Args) != 1 {
			return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("invalid which argv")}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "/usr/bin/" + request.Args[0] + "\n"}
	case "systemctl":
		if len(request.Args) == 0 || (request.Args[0] != "show" && (!e.allowWrites || (request.Args[0] != "restart" && request.Args[0] != "reload"))) {
			return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("future systemctl write must not run")}
		}
		if request.Args[0] == "restart" || request.Args[0] == "reload" {
			return opsexec.Result{ExitCode: 0}
		}
		output := "ActiveState=active\nSubState=running\nMainPID=42\n"
		if strings.Contains(strings.Join(request.Args, " "), "FragmentPath") {
			output += "FragmentPath=/usr/lib/systemd/system/php8.5-fpm.service\n"
		}
		return opsexec.Result{ExitCode: 0, Stdout: output}
	case "stat":
		if len(request.Args) > 1 && request.Args[1] == "%F %U" {
			return opsexec.Result{ExitCode: 0, Stdout: "regular file root\n"}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "regular file\n"}
	case "sha256sum":
		if len(request.Args) == 2 && strings.Contains(request.Args[1], "/.agentsetup/1.2.3/") {
			return opsexec.Result{ExitCode: 0, Stdout: e.remoteDigest + "  " + request.Args[1] + "\n"}
		}
		return opsexec.Result{ExitCode: 0, Stdout: "c5ccf45ca6013ef990bf1b51465a00b62b55d29f0e89b73f59ec23ec7d510983  /opt/apps/demo-api/shared/config/app.env\n"}
	case "curl":
		return opsexec.Result{ExitCode: 0, Stdout: "200"}
	case "pm2":
		if len(request.Args) == 1 && request.Args[0] == "jlist" {
			return opsexec.Result{ExitCode: 0, Stdout: `[{"name":"demo-api","pid":42,"pm2_env":{"status":"online","username":"root"}}]`}
		}
		return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("future pm2 write must not run")}
	case "mkdir", "tar", "mv", "ln", "rm", "chmod":
		if !e.allowWrites {
			return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("future write command must not run")}
		}
		return opsexec.Result{ExitCode: 0}
	case "find":
		return opsexec.Result{ExitCode: 0, Stdout: "300 1.2.3\n200 1.1.0\n"}
	default:
		return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("unexpected write command")}
	}
}

func (e *cliDeployExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	e.copies = append(e.copies, request)
	e.trace = append(e.trace, "copy "+request.Source+" "+request.Destination)
	if !e.allowWrites || e.failCopy {
		return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("copy failed with token=private")}
	}
	data, err := os.ReadFile(request.Source)
	if err != nil {
		return opsexec.Result{ExitCode: 7, Err: err}
	}
	digest := sha256.Sum256(data)
	e.remoteDigest = hex.EncodeToString(digest[:])
	return opsexec.Result{ExitCode: 0}
}

func TestOpsDeployPreviewAndStaleRemainReadOnlyAndConfirmApplies(t *testing.T) {
	p := opsBuildTestPaths(t)
	projectPath := buildProjectPath(t, p)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	serviceData, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	serviceData = []byte(strings.Replace(string(serviceData), "  path: /Users/example/workspace/Demo\n", "  path: "+projectPath+"\n", 1))
	if err := os.WriteFile(servicePath, serviceData, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &cliDeployExecutor{}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsDeployExecutor = original })

	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}, &out, &errOut)
	if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), `"version": "1.2.3"`) || !strings.Contains(out.String(), "preview-digest: ") {
		t.Fatalf("preview code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	digest := strings.TrimSpace(out.String()[strings.LastIndex(out.String(), "preview-digest: ")+len("preview-digest: "):])
	if len(digest) != 64 || len(fake.runs) == 0 || len(fake.copies) != 0 || !onlyDeployReadRequests(fake.runs) {
		t.Fatalf("digest=%q runs=%d copies=%d", digest, len(fake.runs), len(fake.copies))
	}
	firstRunCount := len(fake.runs)

	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--confirm", "--preview-digest", strings.Repeat("0", 64)}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "stale") || len(fake.copies) != 0 || len(fake.runs) != firstRunCount*2 || !onlyDeployReadRequests(fake.runs) {
		t.Fatalf("stale code=%d out=%q err=%q runs=%d copies=%d", code, out.String(), errOut.String(), len(fake.runs), len(fake.copies))
	}

	fake.allowWrites = true
	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--confirm", "--preview-digest", digest}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "deployment: succeeded") || !strings.Contains(out.String(), "report-id: deploy-") || len(fake.copies) != 1 {
		t.Fatalf("confirm code=%d out=%q err=%q runs=%d copies=%d", code, out.String(), errOut.String(), len(fake.runs), len(fake.copies))
	}
	assertTraceSubsequence(t, fake.trace, []string{
		"mkdir -p /opt/apps/demo-api/.agentsetup/1.2.3",
		"copy ",
		"sha256sum -- /opt/apps/demo-api/.agentsetup/1.2.3/artifact.tar.gz",
		"mkdir /opt/apps/demo-api/releases/1.2.3",
		"tar --extract --gzip",
		"ln -sfn releases/1.1.0 /opt/apps/demo-api/.previous.tmp",
		"ln -sfn releases/1.2.3 /opt/apps/demo-api/.current.tmp",
		"mv -Tf /opt/apps/demo-api/.current.tmp /opt/apps/demo-api/current",
		"systemctl restart demo-api.service",
		"systemctl show demo-api.service",
		"curl ",
		"find /opt/apps/demo-api/releases",
	})
	reports, err := os.ReadDir(p.OpsReportRoot)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports=%v err=%v", reports, err)
	}
	reportPath := filepath.Join(p.OpsReportRoot, reports[0].Name())
	info, err := os.Stat(reportPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report info=%v err=%v", info, err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil || !strings.Contains(string(reportData), `"requested_version": "1.2.3"`) || !strings.Contains(string(reportData), `"actor": "deploy"`) {
		t.Fatalf("report=%q err=%v", reportData, err)
	}
}

func TestOpsDeployPHPFPMPreviewStaleAndConfirmUseExactContract(t *testing.T) {
	p := opsBuildTestPaths(t)
	setCLIServicePHPFPM(t, p)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	fake := &cliDeployExecutor{}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsDeployExecutor = original })

	var preview, previewErr bytes.Buffer
	args := []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 || previewErr.Len() != 0 {
		t.Fatalf("preview code=%d out=%q err=%q", code, preview.String(), previewErr.String())
	}
	for _, want := range []string{`"kind": "php-fpm"`, `"config_owner": "root"`, `"config_path": "/usr/lib/systemd/system/php8.5-fpm.service"`, `"kind": "activate-runner"`, `"kind": "process-health-config-owner"`} {
		if !strings.Contains(preview.String(), want) {
			t.Fatalf("preview missing %s: %s", want, preview.String())
		}
	}
	digest := previewDigest(t, preview.String())
	previewRuns := len(fake.runs)
	if previewRuns == 0 || len(fake.copies) != 0 || !onlyDeployReadRequests(fake.runs) {
		t.Fatalf("preview runs=%v copies=%v", fake.runs, fake.copies)
	}

	var staleOut, staleErr bytes.Buffer
	staleArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", strings.Repeat("0", 64))
	if code, _ := executeRootCommand(p, staleArgs, &staleOut, &staleErr); code != 1 || !strings.Contains(staleErr.String(), "stale") || len(fake.runs) != previewRuns*2 || !onlyDeployReadRequests(fake.runs) {
		t.Fatalf("stale code=%d runs=%v out=%q err=%q", code, fake.runs, staleOut.String(), staleErr.String())
	}

	fake.allowWrites = true
	var out, errOut bytes.Buffer
	confirmArgs := append(append([]string(nil), args...), "--confirm", "--preview-digest", digest)
	if code, _ := executeRootCommand(p, confirmArgs, &out, &errOut); code != 0 || !strings.Contains(out.String(), "deployment: succeeded") {
		t.Fatalf("confirm code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	assertTraceSubsequence(t, fake.trace, []string{
		"mv -Tf /opt/apps/demo-api/.current.tmp /opt/apps/demo-api/current",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
		"systemctl reload php8.5-fpm",
		"systemctl show php8.5-fpm --property=ActiveState,SubState,MainPID,FragmentPath --no-pager",
		"stat -c %F %U -- /usr/lib/systemd/system/php8.5-fpm.service",
	})
}

func TestOpsDeployUnsupportedRunnerFailsBeforeWrites(t *testing.T) {
	p := opsBuildTestPaths(t)
	setCLIServicePM2(t, p)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	fake := &cliDeployExecutor{}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsDeployExecutor = original })
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "preview blocked") || len(fake.copies) != 0 || !onlyDeployReadRequests(fake.runs) {
		t.Fatalf("code=%d runs=%v copies=%v out=%q err=%q", code, fake.runs, fake.copies, out.String(), errOut.String())
	}
}

func assertTraceSubsequence(t *testing.T, trace, prefixes []string) {
	t.Helper()
	index := 0
	for _, call := range trace {
		if index < len(prefixes) && strings.HasPrefix(call, prefixes[index]) {
			index++
		}
	}
	if index != len(prefixes) {
		t.Fatalf("trace missing ordered prefix %q after %v", prefixes[index], trace)
	}
}

func TestOpsDeployApplyFailureReturnsNonzeroAndWritesRedactedReport(t *testing.T) {
	p := opsBuildTestPaths(t)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	fake := &cliDeployExecutor{}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsDeployExecutor = original })
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d err=%q", code, previewErr.String())
	}
	digest := strings.TrimSpace(preview.String()[strings.LastIndex(preview.String(), "preview-digest: ")+len("preview-digest: "):])
	fake.allowWrites = true
	fake.failCopy = true
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--confirm", "--preview-digest", digest}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "deployment: failed") || strings.Contains(out.String()+errOut.String(), "private") || strings.Contains(out.String()+errOut.String(), "token=") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	reports, err := os.ReadDir(p.OpsReportRoot)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports=%v err=%v", reports, err)
	}
	data, err := os.ReadFile(filepath.Join(p.OpsReportRoot, reports[0].Name()))
	if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "token=") {
		t.Fatalf("unsafe report=%q err=%v", data, err)
	}
}

func onlyDeployReadRequests(requests []opsexec.Request) bool {
	for _, request := range requests {
		if !isDeployReadRequest(request) {
			return false
		}
	}
	return true
}

func isDeployReadRequest(request opsexec.Request) bool {
	switch request.Program {
	case "test", "readlink", "id", "uname", "df", "which", "sha256sum", "stat", "curl", "nc", "cat":
		return true
	case "systemctl":
		return len(request.Args) > 0 && request.Args[0] == "show"
	case "kill":
		return len(request.Args) > 0 && request.Args[0] == "-0"
	case "pm2":
		return len(request.Args) == 1 && request.Args[0] == "jlist"
	default:
		return false
	}
}

func TestOpsDeployRequiresExactManifestVersion(t *testing.T) {
	p := opsBuildTestPaths(t)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	fake := &cliDeployExecutor{}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsDeployExecutor = original })
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"ops", "deploy", "demo-api", "--environment", "production"}, want: "--version"},
		{name: "different", args: []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.4"}, want: "does not match"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code, _ := executeRootCommand(p, tt.args, &out, &errOut)
			if code != 1 || !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
			}
		})
	}
	if len(fake.runs) != 0 || len(fake.copies) != 0 {
		t.Fatalf("version rejection performed remote operations: runs=%v copies=%v", fake.runs, fake.copies)
	}
}

func TestOpsDeployRejectsInvalidConfirmationArguments(t *testing.T) {
	p := opsTestPaths(t, "valid")
	for _, args := range [][]string{
		{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--confirm"},
		{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--preview-digest", strings.Repeat("a", 64)},
		{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3", "--confirm", "--preview-digest", "ABC"},
	} {
		var out, errOut bytes.Buffer
		if code, _ := executeRootCommand(p, args, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "preview-digest") {
			t.Fatalf("args=%v code=%d out=%q err=%q", args, code, out.String(), errOut.String())
		}
	}
}

type fixedDeployExecutor struct{ result opsexec.Result }

func (e *fixedDeployExecutor) Run(context.Context, opsexec.Request) opsexec.Result { return e.result }
func (e *fixedDeployExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: 7, Err: fmt.Errorf("copy must not run")}
}

func TestOpsDeployFailsClosedWithoutLeakingRemoteOutput(t *testing.T) {
	p := opsBuildTestPaths(t)
	var buildOut, buildErr bytes.Buffer
	if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
		t.Fatalf("build code=%d err=%q", code, buildErr.String())
	}
	original := opsDeployExecutor
	opsDeployExecutor = func() opsexec.Executor {
		return &fixedDeployExecutor{result: opsexec.Result{ExitCode: 7, Stdout: "token=secret", Stderr: "password=secret", Err: fmt.Errorf("secret")}}
	}
	t.Cleanup(func() { opsDeployExecutor = original })
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "preview collection failed") || strings.Contains(out.String()+errOut.String(), "secret") {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestOpsDeployRejectsMissingSourceAndInvalidArtifact(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(paths.Paths)
		want string
	}{
		{name: "missing source", edit: func(p paths.Paths) {
			servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
			data, err := os.ReadFile(servicePath)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), "  path: "+buildProjectPath(t, p)+"\n", "", 1))
			if err := os.WriteFile(servicePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "source.path"},
		{name: "invalid artifact", edit: func(p paths.Paths) {
			manifest := filepath.Join(buildProjectPath(t, p), "dist", "demo-api.manifest.json")
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), `"version":"1.2.3"`, `"version":"bad/version"`, 1))
			if err := os.WriteFile(manifest, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}, want: "artifact or manifest validation failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := opsBuildTestPaths(t)
			var buildOut, buildErr bytes.Buffer
			if code, _ := executeRootCommand(p, []string{"ops", "build", "demo-api"}, &buildOut, &buildErr); code != 0 {
				t.Fatalf("build code=%d err=%q", code, buildErr.String())
			}
			tt.edit(p)
			var out, errOut bytes.Buffer
			code, _ := executeRootCommand(p, []string{"ops", "deploy", "demo-api", "--environment", "production", "--version", "1.2.3"}, &out, &errOut)
			if code != 1 || !strings.Contains(errOut.String(), tt.want) {
				t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func opsBuildTestPaths(t *testing.T) paths.Paths {
	t.Helper()
	p := opsTestPaths(t, "valid")
	project := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(filepath.Join(project, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(project, "fixture.tar.gz")
	writeCLITarFixture(t, fixture, "app", []byte("artifact"))
	archive, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	script := fmt.Sprintf(`#!/bin/sh
set -eu
mkdir -p dist
cp fixture.tar.gz dist/demo-api.tar.gz
printf '%%s' '{"service":"demo-api","version":"1.2.3","commit":"0123456789abcdef","built_at":"2026-09-12T01:02:03Z","platform":"linux","architecture":"amd64","sha256":"%s"}' > dist/demo-api.manifest.json
`, hex.EncodeToString(digest[:]))
	if err := os.WriteFile(filepath.Join(project, "scripts", "build.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "  path: /Users/example/workspace/Demo\n", "  path: "+project+"\n", 1))
	if err := os.WriteFile(servicePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setCLIServicePHPFPM(t *testing.T, p paths.Paths) {
	t.Helper()
	replaceCLIProductionRunner(t, p, "    runner: php-fpm\n    service: php8.5-fpm\n    configOwner: root\n    configPath: /usr/lib/systemd/system/php8.5-fpm.service")
}

func setCLIServicePM2(t *testing.T, p paths.Paths) {
	t.Helper()
	replaceCLIProductionRunner(t, p, "    runner: pm2\n    app: demo-api\n    configOwner: root\n    configPath: /opt/apps/demo-api/ecosystem.config.js")
}

func replaceCLIProductionRunner(t *testing.T, p paths.Paths, replacement string) {
	t.Helper()
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), "    runner: systemd\n    unit: demo-api.service", replacement, 1)
	if updated == string(data) {
		t.Fatal("systemd production runner fixture was not found")
	}
	if err := os.WriteFile(servicePath, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeCLITarFixture(t *testing.T, filename, name string, body []byte) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func buildProjectPath(t *testing.T, p paths.Paths) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(p.OperationsRoot, "services", "demo-api.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "  path: ") {
			return strings.TrimPrefix(line, "  path: ")
		}
	}
	t.Fatal("project path missing")
	return ""
}

func TestOpsListEmptyInventory(t *testing.T) {
	p := opsTestPaths(t, "valid")
	entries, err := os.ReadDir(filepath.Join(p.OperationsRoot, "services"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(p.OperationsRoot, "services", entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, []string{"ops", "list"}, &out, &errOut)
	if !handled || code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
}

func opsTestPaths(t *testing.T, fixture string) paths.Paths {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join("..", "opsconfig", "testdata", fixture)
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == "." {
			return err
		}
		destination := filepath.Join(root, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths.Paths{OperationsRoot: root, OpsReportRoot: filepath.Join(root, "reports"), OpsBackupRoot: filepath.Join(root, "backups")}
}

func writeOpsService(t *testing.T, root, id, language, host string) {
	t.Helper()
	content := "version: 1\nid: " + id + "\nlanguage: " + language + `
source:
  path: /Users/example/workspace/Demo
  repository: git@example.com:demo.git
build:
  adapter: command
  command: ./scripts/build.sh
  artifact: dist/app.tar.gz
  manifest: dist/app.manifest.json
environments:
  local:
    kind: local
    runner: process
    user: deploy
    command: /tmp/bin/app
    pidfile: /tmp/app.pid
    shutdownSignal: SIGTERM
    logs: /tmp/app.log
  production:
    kind: ssh
    host: ` + host + "\n    root: /opt/apps/" + id + `
    runner: systemd
    unit: app.service
    health:
      type: http
      url: http://127.0.0.1/` + id + `/health
      successStatuses: [200]
`
	if err := os.WriteFile(filepath.Join(root, "services", id+".yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeOpsHost(t *testing.T, root, host string) {
	t.Helper()
	path := filepath.Join(root, "hosts.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("  "+host+":\n    sshAlias: "+host+"\n    platform: ubuntu\n    architecture: amd64\n    capabilities:\n      - systemd\n")...)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func opsTree(t *testing.T, root string) []string {
	t.Helper()
	var entries []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel != "." {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			entries = append(entries, fmt.Sprintf("%s:%s:%d", filepath.ToSlash(rel), info.Mode(), info.Size()))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func replacePolicyValue(t *testing.T, root, old, new string) {
	t.Helper()
	path := filepath.Join(root, "policies.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), old, new, 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
