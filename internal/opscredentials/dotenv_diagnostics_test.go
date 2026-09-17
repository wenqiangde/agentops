package opscredentials

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

// A test harness, not the production CLI: exercise real error/report serializers.
func TestDotenvDiagnosticSubprocess(t *testing.T) {
	if os.Getenv("AGENTOPS_TEST_DOTENV_HELPER") != "1" {
		return
	}
	_, loadErr := readDotenv(os.Getenv("AGENTOPS_TEST_DOTENV_PATH"), os.Getuid(), nil)
	if loadErr == nil {
		t.Fatal("failure fixture accepted")
	}
	assertSafeDotenvError(t, loadErr)
	fmt.Fprintln(os.Stderr, loadErr)
	stage, err := opscloudflare.NewStageResult(opscloudflare.StageProductionAction,
		opscloudflare.StageCode(loadErr.Error()), 0, opscloudflare.TimeoutNone, "test-credential-diagnostic")
	if err != nil {
		t.Fatal("safe stage construction failed")
	}
	now := time.Now().UTC()
	_, err = opsreport.WriteCloudflare(os.Getenv("AGENTOPS_TEST_REPORT_ROOT"), opsreport.CloudflareReportInput{
		OperationID: "test-credential-report", Operation: "deploy", Actor: "test",
		Service: "example-service", Environment: "production", Worker: "example-worker",
		PlanDigest: strings.Repeat("a", 64), PayloadDigest: strings.Repeat("b", 64),
		RequestedVersion: "test-version", Outcome: opsreport.CloudflareKnownFailure,
		Health:    opsreport.HealthEvidence{Type: "http", State: "not-checked"},
		ErrorCode: loadErr.Error(), Stages: []opscloudflare.StageResult{stage},
		StartedAt: now, FinishedAt: now,
	})
	if err != nil {
		t.Fatal("private diagnostic report failed")
	}
}

func TestDotenvFailureOutputsDoNotLeak(t *testing.T) {
	fixtures := []struct {
		name, content string
		mode          os.FileMode
		link          bool
	}{
		{"syntax", "TOKEN=\"" + dotenvSentinel + "\n", 0600, false},
		{"duplicate", "TOKEN=" + dotenvSentinel + "\nTOKEN=other\n", 0600, false},
		{"permission", "TOKEN=" + dotenvSentinel + "\n", 0644, false},
		{"symlink", "TOKEN=" + dotenvSentinel + "\n", 0600, true},
		{"oversize", "TOKEN=" + dotenvSentinel + strings.Repeat("x", maxDotenvSize) + "\n", 0600, false},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			path := dotenvFixture(t, fixture.content, fixture.mode)
			if fixture.link {
				link := filepath.Join(t.TempDir(), ".env")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			reportRoot := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestDotenvDiagnosticSubprocess$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "AGENTOPS_TEST_DOTENV_HELPER=1", "AGENTOPS_TEST_DOTENV_PATH="+path, "AGENTOPS_TEST_REPORT_ROOT="+reportRoot)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatal("diagnostic subprocess failed")
			}
			for _, output := range [][]byte{stdout.Bytes(), stderr.Bytes()} {
				if bytes.Contains(output, []byte(dotenvSentinel)) || bytes.Contains(output, []byte(path)) {
					t.Fatal("diagnostic output leaked secret or private input path")
				}
			}
			if !strings.Contains(stderr.String(), "CF_CREDENTIAL_FILE_") {
				t.Fatal("safe diagnostic missing")
			}
			reports, err := filepath.Glob(filepath.Join(reportRoot, "*.json"))
			if err != nil || len(reports) != 1 {
				t.Fatal("expected one private report")
			}
			data, err := os.ReadFile(reports[0])
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(dotenvSentinel)) || bytes.Contains(data, []byte(path)) {
				t.Fatal("persisted report leaked secret or input path")
			}
			info, err := os.Stat(reports[0])
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("report permissions not private")
			}
		})
	}
}
