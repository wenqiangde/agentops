package opsexec

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLocalPipelineConnectsStagesWithoutShell(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("encrypted-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := NewLocalExecutor().Pipeline(context.Background(), PipelineRequest{
		Stages:     []PipelineStage{{Program: "cat"}, {Program: "cat"}},
		InputPath:  input,
		OutputPath: output,
	})
	data, err := os.ReadFile(output)
	if result.Err != nil || err != nil || string(data) != "encrypted-bytes" {
		t.Fatalf("result=%+v data=%q err=%v", result, data, err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestSSHPipelineBuildsQuotedStructuredStages(t *testing.T) {
	var program string
	var args []string
	executor := NewSSHExecutorWithCommand(func(ctx context.Context, name string, argv ...string) *exec.Cmd {
		program = name
		args = append([]string(nil), argv...)
		return helperCommand(ctx, "success")
	})
	result := executor.Pipeline(context.Background(), PipelineRequest{
		HostAlias: "prod-a",
		Stages: []PipelineStage{
			{Program: "mysqldump", Args: []string{"--defaults-extra-file=/run/secrets/mysql.cnf", "--single-transaction", "--quick", "app_db"}},
			{Program: "age", Args: []string{"-r", "age1recipient"}},
		},
		OutputPath: "/opt/apps/demo/backups/app.sql.age.partial",
	})
	if result.Err != nil || program != "ssh" {
		t.Fatalf("program=%q result=%+v", program, result)
	}
	if len(args) != 7 || !reflect.DeepEqual(args[:6], []string{"-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "--", "prod-a"}) || !strings.Contains(args[6], "'bash' '-o' 'pipefail'") || !strings.Contains(args[6], "set -o noclobber; umask 077") || !strings.Contains(args[6], "'mysqldump'") || !strings.Contains(args[6], "'age'") {
		t.Fatalf("unsafe or incomplete pipeline args=%#v", args)
	}
}

func TestPipelineRejectsUnsafeShapeBeforeExecution(t *testing.T) {
	tests := []PipelineRequest{
		{HostAlias: "prod-a", Stages: nil, OutputPath: "/tmp/out"},
		{HostAlias: "prod-a", Stages: []PipelineStage{{Program: "age\nrm"}}, OutputPath: "/tmp/out"},
		{HostAlias: "prod-a", Stages: []PipelineStage{{Program: "age"}}, OutputPath: "/tmp/../out"},
		{HostAlias: "prod-a", Stages: []PipelineStage{{Program: "age"}}, InputPath: "/tmp/in", OutputPath: "/tmp/out"},
	}
	for i, request := range tests {
		called := false
		executor := NewSSHExecutorWithCommand(func(context.Context, string, ...string) *exec.Cmd {
			called = true
			return nil
		})
		result := executor.Pipeline(context.Background(), request)
		if called || result.Err == nil {
			t.Fatalf("case=%d called=%v result=%+v", i, called, result)
		}
	}
}
