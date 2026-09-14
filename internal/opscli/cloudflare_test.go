package opscli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestOpsDeployRoutesCloudflareWorkerToReadOnlyPreview(t *testing.T) {
	p := opsTestPaths(t, "valid")
	repositoryRoot, sourcePath := newCLICloudflareRepository(t)
	writeCLICloudflareService(t, p.OperationsRoot, repositoryRoot, sourcePath)
	fake := &cliCloudflareExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
		{ExitCode: 0, Stdout: "private dry-run output"},
	}}
	original := opsCloudflareExecutor
	opsCloudflareExecutor = func() opsexec.Executor { return fake }
	t.Cleanup(func() { opsCloudflareExecutor = original })

	var stdout, stderr bytes.Buffer
	code, handled := executeRootCommand(p, []string{
		"ops", "deploy", "preveal-relay", "--environment", "production", "--version", "2026.09.14-1",
	}, &stdout, &stderr)
	if !handled || code != 0 || stderr.Len() != 0 {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, stdout.String(), stderr.String())
	}
	for _, wanted := range []string{`"service": "preveal-relay"`, `"worker": "example-worker"`, "preview-digest: "} {
		if !strings.Contains(stdout.String(), wanted) {
			t.Fatalf("preview missing %q: %s", wanted, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "private dry-run output") {
		t.Fatalf("preview exposed Wrangler output: %s", stdout.String())
	}
	want := []opsexec.Request{
		{Program: "node_modules/.bin/wrangler", Args: []string{"--version"}, Directory: sourcePath, Timeout: 30_000_000_000},
		{Program: "node_modules/.bin/wrangler", Args: []string{"whoami", "--account", "0123456789abcdef0123456789abcdef", "--json"}, Directory: sourcePath, Timeout: 30_000_000_000},
		{Program: "node_modules/.bin/wrangler", Args: []string{"deploy", "--dry-run", "--config", "wrangler.jsonc"}, Directory: sourcePath, Timeout: 30_000_000_000},
	}
	if !reflect.DeepEqual(fake.requests, want) {
		t.Fatalf("requests=%+v want=%+v", fake.requests, want)
	}
}

type cliCloudflareExecutor struct {
	requests []opsexec.Request
	results  []opsexec.Result
}

func (e *cliCloudflareExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, request)
	if len(e.results) == 0 {
		return opsexec.Result{ExitCode: -1}
	}
	result := e.results[0]
	e.results = e.results[1:]
	return result
}

func (e *cliCloudflareExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: -1}
}

func newCLICloudflareRepository(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "relay")
	writeCLIFile(t, filepath.Join(source, "package.json"), `{"devDependencies":{"wrangler":"~4.35.0"}}`, 0o644)
	writeCLIFile(t, filepath.Join(source, "package-lock.json"), `{}`, 0o644)
	writeCLIFile(t, filepath.Join(source, "node_modules", ".bin", "wrangler"), "#!/usr/bin/env node\n", 0o755)
	writeCLIFile(t, filepath.Join(source, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef"}`, 0o644)
	writeCLIFile(t, filepath.Join(root, "admin", "index.html"), "admin", 0o644)
	runCLIGit(t, root, "init", "--quiet")
	runCLIGit(t, root, "config", "user.name", "AgentOps Test")
	runCLIGit(t, root, "config", "user.email", "agentops@example.test")
	runCLIGit(t, root, "add", ".")
	runCLIGit(t, root, "commit", "--quiet", "-m", "baseline")
	return root, source
}

func writeCLICloudflareService(t *testing.T, operationsRoot, repositoryRoot, sourcePath string) {
	t.Helper()
	content := fmt.Sprintf(`version: 1
id: preveal-relay
language: typescript
source:
  path: %s
  repository: git@example.com:preveal.git
  repositoryRoot: %s
  deploymentScope: [relay, admin]
deployment:
  requireCommittedScope: false
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: example-worker
    accountId: 0123456789abcdef0123456789abcdef
    wranglerConfig: wrangler.jsonc
`, sourcePath, repositoryRoot)
	writeCLIFile(t, filepath.Join(operationsRoot, "services", "preveal-relay.yaml"), content, 0o644)
}

func writeCLIFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func runCLIGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
}
