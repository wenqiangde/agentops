package opsreport_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

func TestNewCloudflareReportClassifiesProductionOutcomes(t *testing.T) {
	tests := []struct {
		name       string
		outcome    opsreport.CloudflareOutcome
		health     opsreport.HealthEvidence
		errorCode  string
		terminal   bool
		manualWork string
	}{
		{name: "success", outcome: opsreport.CloudflareSucceeded, health: opsreport.HealthEvidence{Type: "http", State: "healthy", Healthy: true, StatusCode: 200}, terminal: true, manualWork: "none"},
		{name: "known failure before production write", outcome: opsreport.CloudflareKnownFailure, health: opsreport.HealthEvidence{Type: "http", State: "not-checked"}, errorCode: "CF_PRODUCTION_ACTION_REJECTED", terminal: true, manualWork: "retry-after-correction"},
		{name: "unknown production state", outcome: opsreport.CloudflareUnknownState, health: opsreport.HealthEvidence{Type: "http", State: "not-checked"}, errorCode: "CF_IDENTITY_UNAVAILABLE", terminal: false, manualWork: "inspect-remote-state-before-retry"},
		{name: "health failure after verified write", outcome: opsreport.CloudflareHealthFailure, health: opsreport.HealthEvidence{Type: "http", State: "failed", Healthy: false, StatusCode: 503}, errorCode: "CF_HEALTH_FAILED", terminal: true, manualWork: "decide-explicit-rollback"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validCloudflareReportInput(t)
			input.Outcome = test.outcome
			input.Health = test.health
			input.ErrorCode = test.errorCode
			report, err := opsreport.NewCloudflareReport(input)
			if err != nil {
				t.Fatal(err)
			}
			if report.Cloudflare == nil || report.Cloudflare.Outcome != test.outcome || report.Terminal != test.terminal || report.ManualWork != test.manualWork {
				t.Fatalf("report=%+v", report)
			}
			if report.Cloudflare.DeploymentID != input.DeploymentID || len(report.Cloudflare.VersionIDs) != 1 || report.Cloudflare.VersionIDs[0] != input.VersionIDs[0] {
				t.Fatalf("durable Cloudflare identity missing: %+v", report.Cloudflare)
			}
			if len(report.Cloudflare.Stages) != len(input.Stages) || report.Cloudflare.Stages[0].Code != input.Stages[0].Code {
				t.Fatalf("safe stage evidence missing: %+v", report.Cloudflare.Stages)
			}
		})
	}
}

func TestNewCloudflareRollbackIdentityMismatchIsUnknownState(t *testing.T) {
	input := validCloudflareReportInput(t)
	input.Operation = "rollback"
	input.Outcome = opsreport.CloudflareUnknownState
	input.ErrorCode = "CF_ROLLBACK_IDENTITY_MISMATCH"
	input.DeploymentID = "33333333-3333-4333-8333-333333333333"
	input.PreviousDeploymentID = "22222222-2222-4222-8222-222222222222"

	report, err := opsreport.NewCloudflareReport(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Cloudflare == nil || report.Cloudflare.Outcome != opsreport.CloudflareUnknownState || report.Terminal || report.Recovery != "manual-review-required" || report.ManualWork != "inspect-remote-state-before-retry" {
		t.Fatalf("rollback identity mismatch was not preserved as unknown state: %+v", report)
	}
}

func TestWriteCloudflareReportReturnsPersistenceFailureWithoutSuccessArtifact(t *testing.T) {
	root := t.TempDir()
	blockedRoot := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blockedRoot, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := validCloudflareReportInput(t)
	input.Outcome = opsreport.CloudflareUnknownState
	input.ErrorCode = "CF_IDENTITY_UNAVAILABLE"

	path, err := opsreport.WriteCloudflare(blockedRoot, input)
	if err == nil || path != "" {
		t.Fatalf("persistence failure was accepted: path=%q err=%v", path, err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil || len(entries) != 1 || entries[0].Name() != "not-a-directory" {
		t.Fatalf("unexpected report artifact after failure: entries=%v err=%v", entries, readErr)
	}
}

func TestWriteCloudflareReportPersistsPrivateCredentialFreeEvidence(t *testing.T) {
	root := t.TempDir()
	input := validCloudflareReportInput(t)
	path, err := opsreport.WriteCloudflare(root, input)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || strings.Contains(string(data), "token") || strings.Contains(string(data), ".dev.vars") || strings.Contains(string(data), "approved module") {
		t.Fatalf("report contains unsafe production material: %s", data)
	}
	typeOfEvidence := reflect.TypeOf(opsreport.CloudflareEvidence{})
	for index := 0; index < typeOfEvidence.NumField(); index++ {
		name := strings.ToLower(typeOfEvidence.Field(index).Name)
		for _, forbidden := range []string{"stdout", "stderr", "token", "secret", "credential", "source", "content", "module", "asset"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("Cloudflare report evidence exposes %q field", typeOfEvidence.Field(index).Name)
			}
		}
	}
}

func validCloudflareReportInput(t *testing.T) opsreport.CloudflareReportInput {
	t.Helper()
	started := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	stage, err := opscloudflare.NewSuccessfulStageResult(opscloudflare.StageProductionAction, "CF_PRODUCTION_ACTION_OK", time.Second, "correlation-001")
	if err != nil {
		t.Fatal(err)
	}
	return opsreport.CloudflareReportInput{
		OperationID:          "cloudflare-deploy-20260915-001",
		Operation:            "deploy",
		Actor:                "environment",
		Service:              "example-relay",
		Environment:          "production",
		Worker:               "example-worker",
		PlanDigest:           strings.Repeat("a", 64),
		PayloadDigest:        strings.Repeat("b", 64),
		RequestedVersion:     "2026.09.15-1",
		PreviousDeploymentID: "11111111-1111-4111-8111-111111111111",
		DeploymentID:         "22222222-2222-4222-8222-222222222222",
		VersionIDs:           []string{"33333333-3333-4333-8333-333333333333"},
		Stages:               []opscloudflare.StageResult{stage},
		Outcome:              opsreport.CloudflareSucceeded,
		Health:               opsreport.HealthEvidence{Type: "http", State: "healthy", Healthy: true, StatusCode: 200},
		StartedAt:            started,
		FinishedAt:           started.Add(2 * time.Second),
	}
}
