package opscloudflare_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
)

func TestCreateSourceSnapshotCopiesIgnoredInputsAndInternalSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "dist", "worker.js"), "bundle\n", 0o644)
	writeFile(t, filepath.Join(root, "node_modules", "wrangler", "bin", "wrangler.js"), "cli\n", 0o755)
	if err := os.MkdirAll(filepath.Join(root, "node_modules", ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "wrangler", "bin", "wrangler.js"), filepath.Join(root, "node_modules", ".bin", "wrangler")); err != nil {
		t.Fatal(err)
	}

	snapshot, err := opscloudflare.CreateSourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.Cleanup)
	if snapshot.Path == root || len(snapshot.SHA256) != 64 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	data, err := os.ReadFile(filepath.Join(snapshot.Path, "dist", "worker.js"))
	if err != nil || string(data) != "bundle\n" {
		t.Fatalf("ignored input=%q err=%v", data, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(snapshot.Path, "node_modules", ".bin", "wrangler"))
	resolvedSnapshot, snapshotErr := filepath.EvalSymlinks(snapshot.Path)
	if err != nil || snapshotErr != nil || filepath.Dir(filepath.Dir(resolved)) != filepath.Join(resolvedSnapshot, "node_modules", "wrangler") {
		t.Fatalf("resolved=%q err=%v", resolved, err)
	}
}

func TestCreateSourceSnapshotRejectsExternalSymlink(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "secret")
	writeFile(t, external, "secret\n", 0o600)
	if err := os.Symlink(external, filepath.Join(root, "escaped")); err != nil {
		t.Fatal(err)
	}
	if _, err := opscloudflare.CreateSourceSnapshot(root); err == nil {
		t.Fatal("external symlink was accepted")
	}
}

func TestSourceSnapshotDigestIncludesIgnoredBytes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "dist", "worker.js")
	writeFile(t, path, "first\n", 0o644)
	first, err := opscloudflare.CreateSourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	first.Cleanup()
	writeFile(t, path, "second\n", 0o644)
	second, err := opscloudflare.CreateSourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Cleanup)
	if first.SHA256 == second.SHA256 {
		t.Fatal("ignored byte change did not change snapshot digest")
	}
}

func TestSealSourceSnapshotMakesFilesReadOnlyAndRejectsDigestDrift(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "index.ts"), "first\n", 0o644)
	snapshot, err := opscloudflare.CreateSourceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.Cleanup)
	writeFile(t, filepath.Join(snapshot.Path, "src", "index.ts"), "changed\n", 0o644)
	if err := opscloudflare.SealSourceSnapshot(snapshot.Path, snapshot.SHA256); err == nil {
		t.Fatal("changed snapshot was sealed")
	}
	writeFile(t, filepath.Join(snapshot.Path, "src", "index.ts"), "first\n", 0o644)
	if err := opscloudflare.SealSourceSnapshot(snapshot.Path, snapshot.SHA256); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(snapshot.Path, "src", "index.ts"))
	if err != nil || info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
}
