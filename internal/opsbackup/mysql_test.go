package opsbackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type fakeExecutor struct {
	runs      []opsexec.Request
	runCtxErr []error
	pipelines []opsexec.PipelineRequest
	copies    []opsexec.CopyRequest
	results   []opsexec.Result
	pipeline  opsexec.Result
	data      []byte
}

func (f *fakeExecutor) Run(ctx context.Context, request opsexec.Request) opsexec.Result {
	f.runs = append(f.runs, request)
	f.runCtxErr = append(f.runCtxErr, ctx.Err())
	if len(f.results) == 0 {
		return opsexec.Result{ExitCode: 0}
	}
	result := f.results[0]
	f.results = f.results[1:]
	return result
}

func (f *fakeExecutor) Pipeline(_ context.Context, request opsexec.PipelineRequest) opsexec.Result {
	f.pipelines = append(f.pipelines, request)
	if f.pipeline.Err != nil || f.pipeline.ExitCode != 0 || f.pipeline.TimedOut {
		return f.pipeline
	}
	return opsexec.Result{ExitCode: 0}
}

func (f *fakeExecutor) Copy(_ context.Context, request opsexec.CopyRequest) opsexec.Result {
	f.copies = append(f.copies, request)
	if err := os.WriteFile(request.Destination, f.data, 0o600); err != nil {
		return opsexec.Result{ExitCode: -1, Err: err}
	}
	return opsexec.Result{ExitCode: 0}
}

func testPlan(t *testing.T) BackupPlan {
	t.Helper()
	dir := t.TempDir()
	return BackupPlan{
		Service: "demo-api", Resource: "app_db", Host: "prod-demo",
		ServerArchive: "/opt/apps/demo-api/backups/app_db-20260912T120000Z.sql.age",
		LocalArchive:  filepath.Join(dir, "app_db-20260912T120000Z.sql.age"),
		AgeRecipient:  "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		ServerCopies:  1, LocalCopies: 7,
		MySQLOptionFile: "/run/secrets/demo-mysql.cnf",
		Restore: RestorePlan{
			AgeIdentity: filepath.Join(dir, "age-key.txt"), MySQLOptionFile: filepath.Join(dir, "restore.cnf"), Socket: filepath.Join(dir, "mysql.sock"),
			ExpectedHostname: "restore-db", ExpectedPort: "3307", TemporaryDatabase: "agentsetup_restore_20260912_a1b2", IntegrityQueries: []string{"SELECT COUNT(*) FROM migrations"},
		},
	}
}

func TestMySQLPreviewAndDigestPerformNoWritesAndCoverIdentity(t *testing.T) {
	plan := testPlan(t)
	executor := &fakeExecutor{}
	preview, err := Preview(context.Background(), executor, plan)
	if err != nil || len(executor.runs)+len(executor.pipelines)+len(executor.copies) != 0 || preview.Plan.Service != plan.Service {
		t.Fatalf("preview=%+v err=%v executor=%+v", preview, err, executor)
	}
	first, err := Digest(preview)
	if err != nil {
		t.Fatal(err)
	}
	changed := preview
	changed.Plan.Resource = "other_db"
	second, _ := Digest(changed)
	changed = preview
	changed.Plan.AgeRecipient = strings.Replace(plan.AgeRecipient, "age1q", "age1p", 1)
	third, _ := Digest(changed)
	if first == second || first == third {
		t.Fatalf("digest did not cover resource and recipient: %q %q %q", first, second, third)
	}
	if err := Confirm(preview, first); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLBackupEncryptsBeforeTransferAndVerifiesIsolatedRestoreBeforeRetention(t *testing.T) {
	plan := testPlan(t)
	data := []byte("encrypted archive")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	executor := &fakeExecutor{data: data, results: []opsexec.Result{
		{ExitCode: 0},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: "prod-db\t3306\t8.4.3\n"},
		{ExitCode: 0, Stdout: digest + "  " + plan.ServerArchive + ".partial\n"},
		{ExitCode: 0, Stdout: "17\n"},
		{ExitCode: 0},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: "restore-db\t3307\n"},
		{ExitCode: 0},
		{ExitCode: 0, Stdout: ""},
	}}
	preview, _ := Preview(context.Background(), executor, plan)
	confirmed, _ := Digest(preview)
	result, err := Apply(context.Background(), executor, preview, confirmed, time.Second)
	if err != nil || !result.Verified || result.ServerVersion != "8.4.3" || result.ArchiveSize != 17 || result.ServerSHA256 != digest || result.LocalSHA256 != digest {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(executor.pipelines) != 2 || executor.pipelines[0].HostAlias != plan.Host || executor.pipelines[1].HostAlias != "" {
		t.Fatalf("pipelines=%+v", executor.pipelines)
	}
	wantDump := []opsexec.PipelineStage{{Program: "mysqldump", Args: []string{"--defaults-extra-file=" + plan.MySQLOptionFile, "--single-transaction", "--quick", plan.Resource}}, {Program: "age", Args: []string{"-r", plan.AgeRecipient}}}
	if !reflect.DeepEqual(executor.pipelines[0].Stages, wantDump) {
		t.Fatalf("dump stages=%+v want=%+v", executor.pipelines[0].Stages, wantDump)
	}
	if _, err := os.Stat(plan.LocalArchive); err != nil {
		t.Fatalf("final local archive missing: %v", err)
	}
	for _, request := range executor.runs {
		joined := request.Program + " " + strings.Join(request.Args, " ")
		if strings.Contains(joined, "password") || strings.Contains(joined, "secret-value") {
			t.Fatalf("credential leaked into argv: %q", joined)
		}
	}
	if executor.runs[0].Program != "age" || executor.runs[len(executor.runs)-1].Program != "find" {
		t.Fatalf("run order=%+v", executor.runs)
	}
}

func TestMySQLTransferMismatchRemovesOnlyIncompleteLocalFileAndSkipsRestoreAndRetention(t *testing.T) {
	plan := testPlan(t)
	executor := &fakeExecutor{data: []byte("different"), results: []opsexec.Result{{ExitCode: 0}, {ExitCode: 0}, {ExitCode: 0, Stdout: "prod-db\t3306\t8.4.3\n"}, {ExitCode: 0, Stdout: strings.Repeat("0", 64) + "  remote\n"}, {ExitCode: 0, Stdout: "9\n"}, {ExitCode: 0}, {ExitCode: 0}}}
	preview, _ := Preview(context.Background(), executor, plan)
	digest, _ := Digest(preview)
	result, err := Apply(context.Background(), executor, preview, digest, time.Second)
	if err == nil || result.Verified || len(executor.pipelines) != 1 || len(executor.runs) != 7 {
		t.Fatalf("result=%+v err=%v runs=%+v pipelines=%+v", result, err, executor.runs, executor.pipelines)
	}
	if _, statErr := os.Stat(plan.LocalArchive + ".partial"); !os.IsNotExist(statErr) {
		t.Fatalf("incomplete local file remains: %v", statErr)
	}
}

func TestMySQLPipelineFailureCleansRemotePartialWithIndependentContext(t *testing.T) {
	plan := testPlan(t)
	executor := &fakeExecutor{
		pipeline: opsexec.Result{ExitCode: 1, Err: context.DeadlineExceeded, TimedOut: true},
		results: []opsexec.Result{
			{ExitCode: 0},
			{ExitCode: 0},
			{ExitCode: 0, Stdout: "prod-db\t3306\t8.4.3\n"},
			{ExitCode: 0},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	preview, _ := Preview(ctx, executor, plan)
	digest, _ := Digest(preview)
	cancel()
	if _, err := Apply(ctx, executor, preview, digest, time.Second); err == nil {
		t.Fatal("expected pipeline failure")
	}
	last := len(executor.runs) - 1
	if last < 0 || executor.runs[last].Program != "rm" || executor.runCtxErr[last] != nil {
		t.Fatalf("cleanup did not use an independent context: runs=%+v contextErrors=%+v", executor.runs, executor.runCtxErr)
	}
}

func TestRetentionRejectsUntrustedRemoteListingBeforeDelete(t *testing.T) {
	for _, output := range []string{
		"malformed",
		"NaN /opt/apps/demo-api/backups/app_db-20260912T120000Z.sql.age\n",
		"+Inf /opt/apps/demo-api/backups/app_db-20260912T120000Z.sql.age\n",
		"1 /opt/apps/demo-api/backups/../outside.age\n",
		"1 /tmp/outside.age\n",
		"1 /opt/apps/demo-api/backups/not-an-archive.txt\n",
		"1 /opt/apps/demo-api/backups/other_db-20260912T120000Z.sql.age\n",
	} {
		plan := testPlan(t)
		executor := &fakeExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: output}}}
		if err := retainVerified(context.Background(), executor, plan, time.Second); err == nil {
			t.Fatalf("output %q was accepted", output)
		}
		if len(executor.runs) != 1 || executor.runs[0].Program != "find" {
			t.Fatalf("output %q triggered an unsafe command: %+v", output, executor.runs)
		}
	}
}

func TestRestoreRejectsProductionDatabaseIdentityBeforeExecution(t *testing.T) {
	plan := testPlan(t)
	plan.Restore.TemporaryDatabase = plan.Resource
	executor := &fakeExecutor{}
	if _, err := VerifyRestore(context.Background(), executor, plan, DatabaseIdentity{Hostname: "prod-db", Port: "3306"}, time.Second); err == nil || len(executor.runs)+len(executor.pipelines) != 0 {
		t.Fatalf("err=%v executor=%+v", err, executor)
	}
}

func TestRestoreRejectsProductionInstanceIdentity(t *testing.T) {
	plan := testPlan(t)
	executor := &fakeExecutor{results: []opsexec.Result{{ExitCode: 0, Stdout: "prod-db\t3306\n"}}}
	if _, err := VerifyRestore(context.Background(), executor, plan, DatabaseIdentity{Hostname: "prod-db", Port: "3306"}, time.Second); err == nil || len(executor.runs) != 1 || len(executor.pipelines) != 0 {
		t.Fatalf("err=%v executor=%+v", err, executor)
	}
}

func TestRestoreRejectsIntegrityQueriesOutsideCountTemplate(t *testing.T) {
	for _, query := range []string{"SELECT * FROM users INTO OUTFILE '/tmp/users'", "SELECT * FROM users INTO\tOUTFILE '/tmp/users'", "SELECT SLEEP(10)", "SELECT GET_LOCK('x', 1)", "SELECT 1 # comment"} {
		plan := testPlan(t)
		plan.Restore.IntegrityQueries = []string{query}
		executor := &fakeExecutor{}
		if _, err := VerifyRestore(context.Background(), executor, plan, DatabaseIdentity{Hostname: "prod-db", Port: "3306"}, time.Second); err == nil || len(executor.runs) != 0 {
			t.Fatalf("query=%q err=%v executor=%+v", query, err, executor)
		}
	}
}

func TestWriteReportPersistsOnlyRedactedRecoveryEvidence(t *testing.T) {
	root := t.TempDir()
	report := Report{
		OperationID: "backup-20260912T120000Z", Service: "demo-api", Resource: "app_db", Host: "prod-demo",
		PlanDigest: strings.Repeat("a", 64), ServerSHA256: strings.Repeat("b", 64), LocalSHA256: strings.Repeat("b", 64),
		RestoreEvidence: RestoreEvidence{TemporaryDatabase: "agentsetup_restore_20260912_a1b2", IntegrityChecks: 1, Verified: true},
		StartedAt:       time.Now().UTC(), FinishedAt: time.Now().UTC(), Status: "verified",
	}
	path, err := WriteReport(root, report)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	info, statErr := os.Stat(path)
	if err != nil || statErr != nil || info.Mode().Perm() != 0o600 || strings.Contains(string(data), "option-file") || strings.Contains(string(data), "age-key") || strings.Contains(string(data), "SELECT") {
		t.Fatalf("data=%s info=%v readErr=%v statErr=%v", data, info, err, statErr)
	}
	if _, err := WriteReport(root, report); err == nil {
		t.Fatal("existing recovery report was overwritten")
	}
}
