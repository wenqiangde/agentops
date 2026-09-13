package opscli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type cliBackupExecutor struct {
	runs, pipelines, copies int
	data                    []byte
}

func (e *cliBackupExecutor) Run(_ context.Context, request opsexec.Request) opsexec.Result {
	e.runs++
	if request.Program == "sha256sum" {
		sum := sha256.Sum256(e.data)
		return opsexec.Result{ExitCode: 0, Stdout: hex.EncodeToString(sum[:]) + "  remote\n"}
	}
	if request.Program == "mysql" && request.HostAlias != "" {
		return opsexec.Result{ExitCode: 0, Stdout: "prod-db\t3306\t8.4.3\n"}
	}
	if request.Program == "mysql" && request.HostAlias == "" && strings.Contains(strings.Join(request.Args, " "), "SELECT @@hostname, @@port") {
		return opsexec.Result{ExitCode: 0, Stdout: "restore-db\t3307\n"}
	}
	if request.Program == "stat" {
		return opsexec.Result{ExitCode: 0, Stdout: "17\n"}
	}
	return opsexec.Result{ExitCode: 0}
}
func (e *cliBackupExecutor) Pipeline(context.Context, opsexec.PipelineRequest) opsexec.Result {
	e.pipelines++
	return opsexec.Result{ExitCode: 0}
}
func (e *cliBackupExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	e.copies++
	if err := os.WriteFile(request.Destination, e.data, 0o600); err != nil {
		return opsexec.Result{ExitCode: -1, Err: err}
	}
	return opsexec.Result{ExitCode: 0}
}

func TestOpsBackupPreviewIsReadOnlyAndStable(t *testing.T) {
	p := opsTestPaths(t, "valid")
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("data:\n  mysql:\n    resource: app_db\n    migrationCommand: ./migrate\n    backupPolicy: before-migration\n")...)
	if err := os.WriteFile(servicePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &cliBackupExecutor{}
	original := opsBackupExecutor
	opsBackupExecutor = func() opsBackupExecution { return fake }
	t.Cleanup(func() { opsBackupExecutor = original })
	args := backupCLIArgs()
	var out, errOut bytes.Buffer
	code, handled := executeRootCommand(p, args, &out, &errOut)
	if !handled || code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), `"resource": "app_db"`) || !strings.Contains(out.String(), "preview-digest: ") {
		t.Fatalf("handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
	if fake.runs+fake.pipelines+fake.copies != 0 {
		t.Fatalf("preview performed writes: %+v", fake)
	}
	first := out.String()
	out.Reset()
	errOut.Reset()
	code, _ = executeRootCommand(p, args, &out, &errOut)
	if code != 0 || out.String() != first {
		t.Fatalf("preview is not stable: first=%q second=%q err=%q", first, out.String(), errOut.String())
	}
}

func TestOpsBackupConfirmAppliesAndWritesPrivateEvidence(t *testing.T) {
	p := opsTestPaths(t, "valid")
	servicePath := filepath.Join(p.OperationsRoot, "services", "demo-api.yaml")
	data, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("data:\n  mysql:\n    resource: app_db\n    migrationCommand: ./migrate\n    backupPolicy: before-migration\n")...)
	if err := os.WriteFile(servicePath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &cliBackupExecutor{data: []byte("encrypted archive")}
	original := opsBackupExecutor
	opsBackupExecutor = func() opsBackupExecution { return fake }
	t.Cleanup(func() { opsBackupExecutor = original })
	args := backupCLIArgs()
	var preview, previewErr bytes.Buffer
	if code, _ := executeRootCommand(p, args, &preview, &previewErr); code != 0 {
		t.Fatalf("preview code=%d err=%q", code, previewErr.String())
	}
	digest := strings.TrimSpace(preview.String()[strings.LastIndex(preview.String(), "preview-digest: ")+len("preview-digest: "):])
	args = append(args, "--confirm", "--preview-digest", digest)
	var out, errOut bytes.Buffer
	code, _ := executeRootCommand(p, args, &out, &errOut)
	if code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "backup: verified") || fake.pipelines != 2 || fake.copies != 1 {
		t.Fatalf("code=%d out=%q err=%q fake=%+v", code, out.String(), errOut.String(), fake)
	}
	report := filepath.Join(p.OpsReportRoot, "backup-20260912T120000Z.json")
	info, err := os.Stat(report)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report=%v err=%v", info, err)
	}
}

func backupCLIArgs() []string {
	return []string{"ops", "backup", "demo-api", "--environment", "production", "--archive-id", "20260912T120000Z", "--age-recipient", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "--mysql-option-file", "/run/secrets/mysql.cnf", "--restore-age-identity", "/tmp/age-key.txt", "--restore-option-file", "/tmp/restore.cnf", "--restore-socket", "/tmp/mysql.sock", "--restore-hostname", "restore-db", "--restore-port", "3307", "--restore-database", "agentsetup_restore_20260912_a1b2", "--integrity-query", "SELECT COUNT(*) FROM migrations"}
}
