package opscli

import (
	"bytes"
	"strings"
	"testing"
)

func TestOpsMainWithPathsShowsDedicatedHelp(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := opsMainWithPaths(p, []string{"--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("opsMainWithPaths() code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:\n  agentops") {
		t.Fatalf("help = %q, want standard agentops usage", stdout.String())
	}
	if strings.Contains(stdout.String(), "Usage: agentsetup ops") {
		t.Fatalf("help = %q, contains legacy command name", stdout.String())
	}
	for _, want := range []string{"Operate application services", "Available Commands:", "validate", "deploy", "completion", "version"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help = %q, missing %q", stdout.String(), want)
		}
	}
}

func TestOpsMainWithPathsShowsCommandHelpWithoutRunningCommand(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := opsMainWithPaths(p, []string{"help", "deploy"}, &stdout, &stderr)

	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("help deploy = (%d, %q, %q), want success", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"Deploy a service release", "agentops deploy <service>", "--environment production", "--version <version>"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("help deploy = %q, missing %q", stdout.String(), want)
		}
	}
}

func TestOpsMainWithPathsShowsVersionMetadata(t *testing.T) {
	p := opsTestPaths(t, "valid")
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := opsMainWithPaths(p, args, &stdout, &stderr)

		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("%v = (%d, %q, %q), want success", args, code, stdout.String(), stderr.String())
		}
		for _, want := range []string{"AgentOps Version", "Version:", "Commit:", "Build date:", "Channel:"} {
			if !strings.Contains(stdout.String(), want) {
				t.Fatalf("%v output = %q, missing %q", args, stdout.String(), want)
			}
		}
	}
}

func TestOpsMainWithPathsGeneratesZshCompletion(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := opsMainWithPaths(p, []string{"completion", "zsh"}, &stdout, &stderr)

	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("completion zsh = (%d, %q, %q), want success", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "#compdef agentops") {
		t.Fatalf("completion zsh = %q, want agentops completion", stdout.String())
	}
}

func TestOpsMainWithPathsUsesDedicatedUsageForErrors(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := opsMainWithPaths(p, []string{"registry"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("opsMainWithPaths() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "registry" for "agentops"`) || !strings.Contains(stderr.String(), agentOpsUsage) {
		t.Fatalf("stderr = %q, want isolated command error and dedicated usage", stderr.String())
	}
	if strings.Contains(stderr.String(), "Usage: agentsetup ops") {
		t.Fatalf("stderr = %q, contains legacy command name", stderr.String())
	}
}

func TestOpsMainWithPathsSharesOperationsBehavior(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var dedicatedOut bytes.Buffer
	var dedicatedErr bytes.Buffer
	var legacyOut bytes.Buffer
	var legacyErr bytes.Buffer

	dedicatedCode := opsMainWithPaths(p, []string{"list"}, &dedicatedOut, &dedicatedErr)
	legacyCode := opsCommand(p, []string{"list"}, &legacyOut, &legacyErr)

	if dedicatedCode != legacyCode || dedicatedOut.String() != legacyOut.String() || dedicatedErr.String() != legacyErr.String() {
		t.Fatalf("dedicated result (%d, %q, %q) differs from legacy (%d, %q, %q)", dedicatedCode, dedicatedOut.String(), dedicatedErr.String(), legacyCode, legacyOut.String(), legacyErr.String())
	}
}

func TestOpsCommandUsesDedicatedUsage(t *testing.T) {
	p := opsTestPaths(t, "valid")
	var stderr bytes.Buffer

	code := opsCommand(p, []string{"unknown"}, &bytes.Buffer{}, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), agentOpsUsage) {
		t.Fatalf("result = (%d, %q), want dedicated usage", code, stderr.String())
	}
}
