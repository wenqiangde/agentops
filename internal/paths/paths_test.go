package paths_test

import (
	"path/filepath"
	"testing"

	"github.com/wenqiangde/agentops/internal/paths"
)

func TestResolveUsesAgentOpsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AGENTOPS_HOME", home)
	t.Setenv("AGENTOPS_OPERATIONS", "")

	got := paths.Resolve()
	want := filepath.Join(home, ".agentops", "operations")
	if got.OperationsRoot != want || got.OpsReportRoot != filepath.Join(want, "reports") || got.OpsBackupRoot != filepath.Join(want, "backups") {
		t.Fatalf("paths=%+v", got)
	}
}

func TestResolveUsesOperationsOverride(t *testing.T) {
	root := filepath.Join(t.TempDir(), "operations")
	t.Setenv("AGENTOPS_OPERATIONS", root)

	got := paths.Resolve()
	if got.OperationsRoot != root || got.OpsReportRoot != filepath.Join(root, "reports") || got.OpsBackupRoot != filepath.Join(root, "backups") {
		t.Fatalf("paths=%+v", got)
	}
}
