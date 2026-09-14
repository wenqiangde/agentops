package opsgit_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/opsgit"
)

func TestInspectDeploymentScopeIgnoresChangesOutsideRelayAndAdmin(t *testing.T) {
	repository := newScopeRepository(t)
	clean := inspectScope(t, repository)
	if clean.State != opsgit.StateClean || len(clean.Entries) != 0 {
		t.Fatalf("clean evidence=%+v", clean)
	}

	writeScopeFile(t, repository, "App/Feature.swift", "changed outside deployment scope\n")
	outOfScope := inspectScope(t, repository)
	if outOfScope.State != opsgit.StateClean || len(outOfScope.Entries) != 0 {
		t.Fatalf("outside-scope evidence=%+v", outOfScope)
	}
	if outOfScope.ContentSHA256 != clean.ContentSHA256 {
		t.Fatalf("outside-scope change altered digest: clean=%s changed=%s", clean.ContentSHA256, outOfScope.ContentSHA256)
	}

	writeScopeFile(t, repository, "relay/.cache/ignored.txt", "ignored\n")
	ignored := inspectScope(t, repository)
	if ignored.State != opsgit.StateClean || ignored.ContentSHA256 != clean.ContentSHA256 {
		t.Fatalf("ignored evidence=%+v clean_digest=%s", ignored, clean.ContentSHA256)
	}
}

func TestInspectDeploymentScopeReportsTrackedAndUntrackedChanges(t *testing.T) {
	repository := newScopeRepository(t)
	writeScopeFile(t, repository, "relay/src/index.ts", "modified relay\n")
	writeScopeFile(t, repository, "admin/src/app.ts", "staged admin\n")
	runGit(t, repository, "add", "--", "admin/src/app.ts")
	writeScopeFile(t, repository, "relay/src/new.ts", "untracked relay\n")

	evidence := inspectScope(t, repository)
	if evidence.State != opsgit.StateDirty {
		t.Fatalf("state=%q evidence=%+v", evidence.State, evidence)
	}
	want := []opsgit.Entry{
		{Path: "admin/src/app.ts", IndexStatus: "M", WorktreeStatus: " "},
		{Path: "relay/src/index.ts", IndexStatus: " ", WorktreeStatus: "M"},
		{Path: "relay/src/new.ts", IndexStatus: "?", WorktreeStatus: "?"},
	}
	if got := statusEntries(evidence.Entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%+v want=%+v", got, want)
	}
	if evidence.ContentSHA256 == inspectCommittedScope(t, repository).ContentSHA256 {
		t.Fatal("scoped changes did not alter content digest")
	}
}

func TestInspectDeploymentScopeReportsRenameAndDeletion(t *testing.T) {
	repository := newScopeRepository(t)
	runGit(t, repository, "mv", "admin/src/app.ts", "admin/src/dashboard.ts")
	if err := os.Remove(filepath.Join(repository, "relay", "src", "index.ts")); err != nil {
		t.Fatal(err)
	}

	evidence := inspectScope(t, repository)
	if evidence.State != opsgit.StateDirty {
		t.Fatalf("state=%q evidence=%+v", evidence.State, evidence)
	}
	want := []opsgit.Entry{
		{Path: "admin/src/dashboard.ts", OriginalPath: "admin/src/app.ts", IndexStatus: "R", WorktreeStatus: " "},
		{Path: "relay/src/index.ts", IndexStatus: " ", WorktreeStatus: "D"},
	}
	if got := statusEntries(evidence.Entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries=%+v want=%+v", got, want)
	}
}

func TestInspectDeploymentScopeDigestChangesWithScopedBytesAndBaseCommit(t *testing.T) {
	repository := newScopeRepository(t)
	baseline := inspectScope(t, repository)

	writeScopeFile(t, repository, "relay/src/index.ts", "working tree revision\n")
	workingTree := inspectScope(t, repository)
	if workingTree.ContentSHA256 == baseline.ContentSHA256 {
		t.Fatal("working-tree bytes did not change digest")
	}

	runGit(t, repository, "add", "--", "relay/src/index.ts")
	runGit(t, repository, "commit", "-m", "update relay")
	committed := inspectScope(t, repository)
	if committed.BaseCommit == baseline.BaseCommit {
		t.Fatal("base commit did not change")
	}
	if committed.ContentSHA256 == baseline.ContentSHA256 {
		t.Fatal("new committed bytes did not change digest")
	}
}

func TestInspectDeploymentScopeRejectsUnsafeRequests(t *testing.T) {
	repository := newScopeRepository(t)
	tests := []struct {
		name   string
		root   string
		scopes []string
	}{
		{name: "duplicate", root: repository, scopes: []string{"relay", "relay"}},
		{name: "overlapping", root: repository, scopes: []string{"relay", "relay/src"}},
		{name: "traversal", root: repository, scopes: []string{"../relay"}},
		{name: "control character", root: repository, scopes: []string{"relay\nadmin"}},
		{name: "invalid UTF-8", root: repository, scopes: []string{string([]byte{'r', 0xff})}},
		{name: "nested root", root: filepath.Join(repository, "relay"), scopes: []string{"src"}},
		{name: "not a repository", root: t.TempDir(), scopes: []string{"relay"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := opsgit.Inspect(context.Background(), opsgit.Request{RepositoryRoot: tt.root, Scopes: tt.scopes})
			if err == nil {
				t.Fatal("unsafe request was accepted")
			}
		})
	}
}

func TestInspectDeploymentScopeRejectsCancelledContext(t *testing.T) {
	repository := newScopeRepository(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := opsgit.Inspect(ctx, opsgit.Request{RepositoryRoot: repository, Scopes: []string{"relay", "admin"}})
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("err=%v", err)
	}
}

func TestInspectDeploymentScopeRejectsSymlinkedFile(t *testing.T) {
	repository := newScopeRepository(t)
	external := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(external, []byte("outside scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repository, "relay", "src", "external.txt")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}

	_, err := opsgit.Inspect(context.Background(), opsgit.Request{RepositoryRoot: repository, Scopes: []string{"relay", "admin"}})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("err=%v", err)
	}
}

func inspectScope(t *testing.T, repository string) opsgit.Evidence {
	t.Helper()
	evidence, err := opsgit.Inspect(context.Background(), opsgit.Request{
		RepositoryRoot: repository,
		Scopes:         []string{"relay", "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func inspectCommittedScope(t *testing.T, repository string) opsgit.Evidence {
	t.Helper()
	clone := filepath.Join(t.TempDir(), "repository")
	runCommand(t, "", "git", "clone", "--quiet", repository, clone)
	return inspectScope(t, clone)
}

func statusEntries(entries []opsgit.Entry) []opsgit.Entry {
	result := make([]opsgit.Entry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, opsgit.Entry{
			Path:           entry.Path,
			OriginalPath:   entry.OriginalPath,
			IndexStatus:    entry.IndexStatus,
			WorktreeStatus: entry.WorktreeStatus,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

func newScopeRepository(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "AgentOps Test")
	runGit(t, repository, "config", "user.email", "agentops@example.test")
	writeScopeFile(t, repository, ".gitignore", "relay/.cache/\n")
	writeScopeFile(t, repository, "relay/src/index.ts", "relay baseline\n")
	writeScopeFile(t, repository, "admin/src/app.ts", "admin baseline\n")
	writeScopeFile(t, repository, "App/Feature.swift", "app baseline\n")
	runGit(t, repository, "add", ".")
	runGit(t, repository, "commit", "--quiet", "-m", "baseline")
	return repository
}

func writeScopeFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runGit(t *testing.T, directory string, args ...string) {
	t.Helper()
	runCommand(t, directory, "git", args...)
}

func runCommand(t *testing.T, directory, program string, args ...string) {
	t.Helper()
	command := exec.Command(program, args...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", program, args, err, output)
	}
}
