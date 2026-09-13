package opsbackup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type Report struct {
	OperationID     string          `json:"operation_id"`
	Service         string          `json:"service"`
	Resource        string          `json:"resource"`
	Host            string          `json:"host"`
	PlanDigest      string          `json:"plan_digest"`
	ServerVersion   string          `json:"server_version,omitempty"`
	ArchiveSize     int64           `json:"archive_size,omitempty"`
	ServerSHA256    string          `json:"server_sha256,omitempty"`
	LocalSHA256     string          `json:"local_sha256,omitempty"`
	RestoreEvidence RestoreEvidence `json:"restore_evidence"`
	StartedAt       time.Time       `json:"started_at"`
	FinishedAt      time.Time       `json:"finished_at"`
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
}

func WriteReport(root string, report Report) (string, error) {
	if !safeIdentity.MatchString(report.OperationID) || !safeIdentity.MatchString(report.Service) || !safeIdentity.MatchString(report.Resource) || !safeHost.MatchString(report.Host) || !sha256Pattern.MatchString(report.PlanDigest) {
		return "", errors.New("backup report identity is invalid")
	}
	for _, digest := range []string{report.ServerSHA256, report.LocalSHA256} {
		if digest != "" && !sha256Pattern.MatchString(digest) {
			return "", errors.New("backup report digest is invalid")
		}
	}
	if report.Status != "verified" && report.Status != "failed" {
		return "", errors.New("backup report status is invalid")
	}
	if report.StartedAt.IsZero() || report.FinishedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) {
		return "", errors.New("backup report time range is invalid")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("backup report root must be a clean absolute path")
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, report.OperationID+".json")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(root, ".backup-report-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}
