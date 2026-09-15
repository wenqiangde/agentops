package opsreport

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
)

type CloudflareOutcome string

const (
	CloudflareSucceeded     CloudflareOutcome = "succeeded"
	CloudflareKnownFailure  CloudflareOutcome = "known-failure"
	CloudflareUnknownState  CloudflareOutcome = "unknown-state"
	CloudflareHealthFailure CloudflareOutcome = "health-failure"
)

type CloudflareEvidence struct {
	Operation            string                      `json:"operation"`
	Outcome              CloudflareOutcome           `json:"outcome"`
	ErrorCode            string                      `json:"error_code,omitempty"`
	PreviousDeploymentID string                      `json:"previous_deployment_id,omitempty"`
	DeploymentID         string                      `json:"deployment_id,omitempty"`
	VersionIDs           []string                    `json:"version_ids,omitempty"`
	Stages               []opscloudflare.StageResult `json:"stages"`
}

type CloudflareReportInput struct {
	OperationID          string
	Operation            string
	Actor                string
	Service              string
	Environment          string
	Worker               string
	PlanDigest           string
	PayloadDigest        string
	RequestedVersion     string
	PreviousDeploymentID string
	DeploymentID         string
	VersionIDs           []string
	Stages               []opscloudflare.StageResult
	Outcome              CloudflareOutcome
	Health               HealthEvidence
	ErrorCode            string
	StartedAt            time.Time
	FinishedAt           time.Time
}

var cloudflareUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var cloudflareErrorCode = regexp.MustCompile(`^CF_[A-Z0-9_]+$`)

func NewCloudflareReport(input CloudflareReportInput) (Report, error) {
	terminal, recovery, manualWork, err := cloudflareDisposition(input.Outcome)
	if err != nil {
		return Report{}, err
	}
	evidence := &CloudflareEvidence{
		Operation: input.Operation, Outcome: input.Outcome, ErrorCode: input.ErrorCode,
		PreviousDeploymentID: input.PreviousDeploymentID, DeploymentID: input.DeploymentID,
		VersionIDs: append([]string(nil), input.VersionIDs...), Stages: append([]opscloudflare.StageResult(nil), input.Stages...),
	}
	report := Report{
		OperationID: input.OperationID, Actor: input.Actor, Service: input.Service, Environment: input.Environment,
		Host: input.Worker, PlanDigest: input.PlanDigest, RequestedVersion: input.RequestedVersion,
		ArtifactDigest: input.PayloadDigest, Health: input.Health, Recovery: recovery, Terminal: terminal,
		StartedAt: input.StartedAt, FinishedAt: input.FinishedAt, ManualWork: manualWork, Cloudflare: evidence,
	}
	status := string(input.Outcome)
	if input.Outcome == CloudflareSucceeded {
		status = "succeeded"
	}
	report.Steps = []StepResult{{Order: 1, Kind: "cloudflare-" + input.Operation, Status: status, StartedAt: input.StartedAt, FinishedAt: input.FinishedAt, Error: input.ErrorCode}}
	if input.ErrorCode != "" {
		report.Error = input.ErrorCode
	}
	if err := validate(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func WriteCloudflare(root string, input CloudflareReportInput) (string, error) {
	report, err := NewCloudflareReport(input)
	if err != nil {
		return "", err
	}
	return Write(root, report, nil)
}

func cloudflareDisposition(outcome CloudflareOutcome) (bool, string, string, error) {
	switch outcome {
	case CloudflareSucceeded:
		return true, "not-applicable", "none", nil
	case CloudflareKnownFailure:
		return true, "correct-input-and-retry", "retry-after-correction", nil
	case CloudflareUnknownState:
		return false, "manual-review-required", "inspect-remote-state-before-retry", nil
	case CloudflareHealthFailure:
		return true, "explicit-rollback-decision-required", "decide-explicit-rollback", nil
	default:
		return false, "", "", errors.New("Cloudflare report outcome is invalid")
	}
}

func validateCloudflareEvidence(evidence CloudflareEvidence) error {
	if evidence.Operation != "deploy" && evidence.Operation != "rollback" {
		return errors.New("Cloudflare report operation is invalid")
	}
	if _, _, _, err := cloudflareDisposition(evidence.Outcome); err != nil {
		return err
	}
	if evidence.ErrorCode != "" && !cloudflareErrorCode.MatchString(evidence.ErrorCode) {
		return errors.New("Cloudflare report error code is invalid")
	}
	for _, identifier := range append(append([]string(nil), evidence.PreviousDeploymentID, evidence.DeploymentID), evidence.VersionIDs...) {
		if identifier != "" && !cloudflareUUID.MatchString(identifier) {
			return errors.New("Cloudflare report durable identity is invalid")
		}
	}
	if len(evidence.Stages) == 0 {
		return errors.New("Cloudflare report stage evidence is incomplete")
	}
	for _, stage := range evidence.Stages {
		if !stage.Stage.Valid() || stage.Code == "" || stage.Elapsed < 0 || stage.CorrelationID == "" || strings.TrimSpace(stage.Remediation) == "" {
			return errors.New("Cloudflare report stage evidence is invalid")
		}
	}
	return nil
}
