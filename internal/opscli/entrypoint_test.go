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
	if !strings.Contains(stdout.String(), agentOpsUsage) {
		t.Fatalf("help = %q, want dedicated usage", stdout.String())
	}
	if strings.Contains(stdout.String(), "Usage: agentsetup ops") {
		t.Fatalf("help = %q, contains legacy command name", stdout.String())
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
	if !strings.Contains(stderr.String(), "unknown command: registry") || !strings.Contains(stderr.String(), agentOpsUsage) {
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
