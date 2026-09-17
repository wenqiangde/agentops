package opsreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/atomicfile"
)

var safeIdentity = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)
var sha256Digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var credentialAssignment = regexp.MustCompile(`(?i)\b(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+`)
var bearerCredential = regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+[^\s,;]+`)
var spacedCredential = regexp.MustCompile(`(?i)(?:--)?(?:password|passwd|token|secret|api[_-]?key)\s+[^\s,;]+`)
var URLUserInfo = regexp.MustCompile(`(?i)(https?://)[^/@\s]+:[^/@\s]+@`)

type Report struct {
	OperationID      string         `json:"operation_id"`
	Actor            string         `json:"actor"`
	Service          string         `json:"service"`
	Environment      string         `json:"environment"`
	Host             string         `json:"host"`
	PlanDigest       string         `json:"plan_digest"`
	PreviousVersion  string         `json:"previous_version,omitempty"`
	RequestedVersion string         `json:"requested_version"`
	ArtifactDigest   string         `json:"artifact_digest"`
	Steps            []StepResult   `json:"steps"`
	Health           HealthEvidence `json:"health"`
	Recovery         string         `json:"recovery"`
	Terminal         bool           `json:"terminal"`
	StartedAt        time.Time      `json:"started_at"`
	FinishedAt       time.Time      `json:"finished_at"`
	Error            string         `json:"error,omitempty"`
	ManualWork       string         `json:"manual_work,omitempty"`
}

type StepResult struct {
	Order      int       `json:"order"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Error      string    `json:"error,omitempty"`
}

type HealthEvidence struct {
	Type       string `json:"type"`
	State      string `json:"state"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

func Write(root string, report Report, redactValues []string) (string, error) {
	if err := validate(report); err != nil {
		return "", err
	}
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("report root must be a clean absolute path")
	}
	report = redactReport(report, redactValues)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode operation report: %w", err)
	}
	target := filepath.Join(root, report.OperationID+".json")
	if err := atomicfile.WriteFile(target, append(data, '\n'), 0o600); err != nil {
		return "", fmt.Errorf("write operation report: %w", err)
	}
	return target, nil
}

func validate(report Report) error {
	for name, value := range map[string]string{
		"operation ID": report.OperationID,
		"service":      report.Service,
		"environment":  report.Environment,
		"host":         report.Host,
	} {
		if !safeIdentity.MatchString(value) {
			return fmt.Errorf("report %s is invalid", name)
		}
	}
	if strings.TrimSpace(report.Actor) == "" {
		return errors.New("report actor is required")
	}
	if !safeIdentity.MatchString(report.RequestedVersion) {
		return errors.New("report requested version is invalid")
	}
	if report.PreviousVersion != "" && !safeIdentity.MatchString(report.PreviousVersion) {
		return errors.New("report previous version is invalid")
	}
	if !sha256Digest.MatchString(report.PlanDigest) || !sha256Digest.MatchString(report.ArtifactDigest) {
		return errors.New("report digest is invalid")
	}
	if report.StartedAt.IsZero() || report.FinishedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) {
		return errors.New("report time range is invalid")
	}
	for _, step := range report.Steps {
		if step.Order <= 0 || strings.TrimSpace(step.Kind) == "" || strings.TrimSpace(step.Status) == "" {
			return errors.New("report step identity is invalid")
		}
		if step.StartedAt.IsZero() || step.FinishedAt.IsZero() || step.FinishedAt.Before(step.StartedAt) || step.StartedAt.Before(report.StartedAt) || step.FinishedAt.After(report.FinishedAt) {
			return errors.New("report step time range is invalid")
		}
	}
	return nil
}

func redactReport(report Report, values []string) Report {
	report.Actor = redact(report.Actor, values)
	report.Recovery = redact(report.Recovery, values)
	report.Error = redact(report.Error, values)
	report.ManualWork = redact(report.ManualWork, values)
	report.Health.Detail = redact(report.Health.Detail, values)
	for index := range report.Steps {
		report.Steps[index].Error = redact(report.Steps[index].Error, values)
	}
	return report
}

func redact(value string, explicit []string) string {
	values := append([]string(nil), explicit...)
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, secret := range values {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	value = URLUserInfo.ReplaceAllString(value, `${1}[redacted]@`)
	value = bearerCredential.ReplaceAllString(value, "[redacted]")
	value = spacedCredential.ReplaceAllString(value, "[redacted]")
	return credentialAssignment.ReplaceAllString(value, "[redacted]")
}
