package opscli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/wenqiangde/agentops/internal/opsreport"
)

func writeCloudflareReport(reportRoot string, report opsreport.Report) (string, error) {
	path, primaryErr := opsreport.Write(reportRoot, report, nil)
	if primaryErr == nil {
		return path, nil
	}
	fallbackRoot := filepath.Join(filepath.Dir(reportRoot), "emergency-reports")
	if err := os.MkdirAll(fallbackRoot, 0o700); err != nil {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	if err := os.Chmod(fallbackRoot, 0o700); err != nil {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	path, fallbackErr := opsreport.Write(fallbackRoot, report, nil)
	if fallbackErr != nil {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	return path, nil
}
