package opsreport_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsreport"
)

func TestWritePersistsCompleteAtomicPrivateReport(t *testing.T) {
	root := t.TempDir()
	report := validReport()
	path, err := opsreport.Write(root, report, nil)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "op-20260912-001.json") {
		t.Fatalf("path=%q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got opsreport.Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.OperationID != report.OperationID || got.ArtifactDigest != report.ArtifactDigest || got.Health.State != "healthy" || len(got.Steps) != 1 || got.ManualWork != "none" {
		t.Fatalf("report=%+v", got)
	}

	// A second write must atomically replace the same operation report and keep
	// the requested private mode even if the old file was less restrictive.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	report.Recovery = "restored previous release"
	if _, err := opsreport.Write(root, report, nil); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement info=%v err=%v", info, err)
	}
	leftovers, err := filepath.Glob(filepath.Join(root, ".op-20260912-001.json.tmp-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary files=%v err=%v", leftovers, err)
	}
}

func TestWriteRedactsExplicitAndCommonCredentialPatterns(t *testing.T) {
	report := validReport()
	report.Actor = "https://user:password@example.com/operator"
	report.Steps[0].Error = "password=hunter2 token: abc123 Authorization: Bearer bearer-secret api_key=key-secret --token spaced-secret explicit-value"
	report.Health.Detail = "https://admin:private@example.com/health?token=query-secret"
	report.ManualWork = "export SECRET=manual-secret and use explicit-value"
	path, err := opsreport.Write(t.TempDir(), report, []string{"explicit-value"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"password", "hunter2", "abc123", "bearer-secret", "key-secret", "spaced-secret", "admin:private", "query-secret", "manual-secret", "explicit-value"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(secret)) {
			t.Fatalf("report leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "[redacted]") {
		t.Fatalf("missing redaction marker: %s", text)
	}
}

func TestWriteRejectsInvalidIdentityAndTimeWithoutCreatingReport(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*opsreport.Report)
	}{
		{name: "unsafe operation ID", mutate: func(r *opsreport.Report) { r.OperationID = "../escape" }},
		{name: "missing service", mutate: func(r *opsreport.Report) { r.Service = "" }},
		{name: "invalid plan digest", mutate: func(r *opsreport.Report) { r.PlanDigest = "short" }},
		{name: "zero start", mutate: func(r *opsreport.Report) { r.StartedAt = time.Time{} }},
		{name: "finish before start", mutate: func(r *opsreport.Report) { r.FinishedAt = r.StartedAt.Add(-time.Second) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			report := validReport()
			tt.mutate(&report)
			if _, err := opsreport.Write(root, report, nil); err == nil {
				t.Fatal("invalid report was accepted")
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("entries=%v err=%v", entries, err)
			}
		})
	}
}

func validReport() opsreport.Report {
	started := time.Date(2026, 9, 12, 1, 2, 3, 0, time.UTC)
	return opsreport.Report{
		OperationID:      "op-20260912-001",
		Actor:            "deploy",
		Service:          "demo-api",
		Environment:      "production",
		Host:             "prod-api",
		PlanDigest:       strings.Repeat("a", 64),
		PreviousVersion:  "1.1.0",
		RequestedVersion: "1.2.0",
		ArtifactDigest:   strings.Repeat("b", 64),
		Steps: []opsreport.StepResult{{
			Order: 1, Kind: "upload-artifact", Status: "succeeded", StartedAt: started, FinishedAt: started.Add(time.Second),
		}},
		Health:     opsreport.HealthEvidence{Type: "http", State: "healthy", Healthy: true, StatusCode: 200},
		Recovery:   "not-required",
		StartedAt:  started,
		FinishedAt: started.Add(2 * time.Second),
		ManualWork: "none",
	}
}
