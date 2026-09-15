package opscloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestInspectUsesProjectLocalWranglerFromSourcePath(t *testing.T) {
	sourcePath := newCloudflareProject(t)
	accountID := "0123456789abcdef0123456789abcdef"
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef","name":"Example"}]}`},
	}}

	_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
		SourcePath:     sourcePath,
		Worker:         "example-worker",
		AccountID:      accountID,
		WranglerConfig: "wrangler.jsonc",
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []opsexec.Request{
		{
			Program:   "node_modules/.bin/wrangler",
			Args:      []string{"--version"},
			Directory: sourcePath,
			Timeout:   5 * time.Second,
		},
		{
			Program:   "node_modules/.bin/wrangler",
			Args:      []string{"whoami", "--account", accountID, "--json"},
			Directory: sourcePath,
			Timeout:   5 * time.Second,
		},
	}
	if !reflect.DeepEqual(executor.requests, want) {
		t.Fatalf("requests=%+v want=%+v", executor.requests, want)
	}
}

func TestInspectAcceptsInternalWranglerSymlink(t *testing.T) {
	root := newCloudflareProject(t)
	wrangler := filepath.Join(root, "node_modules", ".bin", "wrangler")
	if err := os.Remove(wrangler); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "node_modules", "wrangler", "bin", "wrangler.js"), "#!/usr/bin/env node\n", 0o755)
	if err := os.Symlink(filepath.Join("..", "wrangler", "bin", "wrangler.js"), wrangler); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
	}}
	_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
		SourcePath: root, Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInspectRejectsWranglerConfigPathsOutsideSource(t *testing.T) {
	for _, config := range []string{
		`{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","main":"/tmp/worker.js"}`,
		`{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","assets":{"directory":"../public"}}`,
	} {
		root := newCloudflareProject(t)
		writeFile(t, filepath.Join(root, "wrangler.jsonc"), config, 0o644)
		executor := &recordingExecutor{}
		_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
			SourcePath: root, Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
			WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
		})
		if err == nil {
			t.Fatalf("unsafe config was accepted: %s", config)
		}
		if len(executor.requests) != 0 {
			t.Fatalf("unsafe config executed commands: %+v", executor.requests)
		}
	}
}

func TestInspectAcceptsWranglerInputInDeclaredSiblingScope(t *testing.T) {
	repositoryRoot := t.TempDir()
	sourcePath := filepath.Join(repositoryRoot, "relay")
	writeFile(t, filepath.Join(sourcePath, "package.json"), `{"devDependencies":{"wrangler":"~4.35.0"}}`, 0o644)
	writeFile(t, filepath.Join(sourcePath, "package-lock.json"), `{}`, 0o644)
	writeFile(t, filepath.Join(sourcePath, "node_modules", ".bin", "wrangler"), "#!/usr/bin/env node\n", 0o755)
	writeFile(t, filepath.Join(sourcePath, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","assets":{"directory":"../admin/dist"}}`, 0o644)
	writeFile(t, filepath.Join(repositoryRoot, "admin", "dist", "index.html"), "admin\n", 0o644)
	executor := &recordingExecutor{results: []opsexec.Result{
		{ExitCode: 0, Stdout: "4.35.0\n"},
		{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`},
	}}

	_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
		SourcePath: sourcePath, RepositoryRoot: repositoryRoot, DeploymentScope: []string{"relay", "admin"},
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInspectRejectsWranglerInputInUndeclaredSiblingScope(t *testing.T) {
	repositoryRoot := t.TempDir()
	sourcePath := filepath.Join(repositoryRoot, "relay")
	writeFile(t, filepath.Join(sourcePath, "package.json"), `{"devDependencies":{"wrangler":"~4.35.0"}}`, 0o644)
	writeFile(t, filepath.Join(sourcePath, "package-lock.json"), `{}`, 0o644)
	writeFile(t, filepath.Join(sourcePath, "node_modules", ".bin", "wrangler"), "#!/usr/bin/env node\n", 0o755)
	writeFile(t, filepath.Join(sourcePath, "wrangler.jsonc"), `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef","assets":{"directory":"../admin/dist"}}`, 0o644)
	writeFile(t, filepath.Join(repositoryRoot, "admin", "dist", "index.html"), "admin\n", 0o644)
	executor := &recordingExecutor{}

	_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
		SourcePath: sourcePath, RepositoryRoot: repositoryRoot, DeploymentScope: []string{"relay"},
		Worker: "example-worker", AccountID: "0123456789abcdef0123456789abcdef",
		WranglerConfig: "wrangler.jsonc", Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("undeclared sibling Wrangler input was accepted")
	}
	if len(executor.requests) != 0 {
		t.Fatalf("unsafe config executed commands: %+v", executor.requests)
	}
}

func TestInspectRejectsWrongAccountAndConfigIdentity(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		whoami    string
		wantError string
	}{
		{
			name:      "wrong account",
			config:    `{"name":"example-worker","account_id":"0123456789abcdef0123456789abcdef"}`,
			whoami:    `{"accounts":[{"id":"ffffffffffffffffffffffffffffffff"}]}`,
			wantError: "not authenticated for configured Cloudflare account",
		},
		{
			name:      "worker mismatch",
			config:    `{"name":"other-worker","account_id":"0123456789abcdef0123456789abcdef"}`,
			whoami:    `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`,
			wantError: "Worker name does not match Wrangler config",
		},
		{
			name:      "account mismatch",
			config:    `{"name":"example-worker","account_id":"ffffffffffffffffffffffffffffffff"}`,
			whoami:    `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`,
			wantError: "account ID does not match Wrangler config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourcePath := newCloudflareProject(t)
			writeFile(t, filepath.Join(sourcePath, "wrangler.jsonc"), tt.config, 0o644)
			executor := &recordingExecutor{results: []opsexec.Result{
				{ExitCode: 0, Stdout: "4.35.0\n"},
				{ExitCode: 0, Stdout: tt.whoami},
			}}
			_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
				SourcePath: sourcePath, Worker: "example-worker",
				AccountID: "0123456789abcdef0123456789abcdef", WranglerConfig: "wrangler.jsonc",
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("err=%v want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestInspectMissingWranglerOnlyRecommendsNPMCI(t *testing.T) {
	sourcePath := newCloudflareProject(t)
	if err := os.Remove(filepath.Join(sourcePath, "node_modules", ".bin", "wrangler")); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}

	_, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
		SourcePath: sourcePath, Worker: "example-worker",
		AccountID: "0123456789abcdef0123456789abcdef", WranglerConfig: "wrangler.jsonc",
	})
	if err == nil || err.Error() != "project-local Wrangler executable is unavailable; run npm ci" {
		t.Fatalf("err=%v", err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("preflight executed commands while Wrangler was missing: %+v", executor.requests)
	}
}

func TestInspectDoesNotExposeWranglerOutputOrSecrets(t *testing.T) {
	const (
		token          = "cf_api_token_super_secret"
		environmentKey = "CLOUDFLARE_API_TOKEN=environment-secret"
		credentialPath = "/Users/example/.wrangler/config/default.toml"
	)
	tests := []struct {
		name    string
		results []opsexec.Result
	}{
		{
			name: "version failure",
			results: []opsexec.Result{{
				ExitCode: 1, Stdout: token, Stderr: environmentKey,
				Err: errors.New(credentialPath),
			}},
		},
		{
			name: "authentication failure",
			results: []opsexec.Result{
				{ExitCode: 0, Stdout: "4.35.0\n"},
				{ExitCode: 1, Stdout: token, Stderr: environmentKey, Err: errors.New(credentialPath)},
			},
		},
		{
			name: "successful authentication",
			results: []opsexec.Result{
				{ExitCode: 0, Stdout: "4.35.0\n"},
				{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef","name":"` + token + `","credential":"` + credentialPath + `"}]}`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &recordingExecutor{results: tt.results}
			evidence, err := opscloudflare.Inspect(context.Background(), executor, opscloudflare.Request{
				SourcePath: newCloudflareProject(t), Worker: "example-worker",
				AccountID: "0123456789abcdef0123456789abcdef", WranglerConfig: "wrangler.jsonc",
			})
			encoded, marshalErr := json.Marshal(evidence)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			visible := string(encoded)
			if err != nil {
				visible += err.Error()
			}
			for _, secret := range []string{token, environmentKey, credentialPath, "environment-secret"} {
				if strings.Contains(visible, secret) {
					t.Fatalf("preflight exposed sensitive command output %q in %q", secret, visible)
				}
			}
		})
	}
}

type recordingExecutor struct {
	requests []opsexec.Request
	results  []opsexec.Result
}

func (e *recordingExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, request)
	if len(e.results) == 0 {
		return opsexec.Result{ExitCode: -1}
	}
	result := e.results[0]
	e.results = e.results[1:]
	return result
}

func (e *recordingExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: -1}
}

func newCloudflareProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"devDependencies":{"wrangler":"~4.35.0"}}`, 0o644)
	writeFile(t, filepath.Join(root, "package-lock.json"), `{}`, 0o644)
	writeFile(t, filepath.Join(root, "node_modules", ".bin", "wrangler"), "#!/usr/bin/env node\n", 0o755)
	writeFile(t, filepath.Join(root, "wrangler.jsonc"), "{\n// fixture\n\"name\": \"example-worker\",\n\"account_id\": \"0123456789abcdef0123456789abcdef\",\n}\n", 0o644)
	return root
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
