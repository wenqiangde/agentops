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
	parent := filepath.Dir(reportRoot)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	fallbackRoot, err := os.MkdirTemp(parent, "emergency-reports-")
	if err != nil {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(fallbackRoot)
		}
	}()
	path, fallbackErr := opsreport.Write(fallbackRoot, report, nil)
	if fallbackErr != nil {
		return "", errors.New("primary and emergency operation reports could not be persisted")
	}
	cleanup = false
	return path, nil
}
