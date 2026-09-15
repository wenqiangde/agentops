package opscloudflare

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type Stage string

const (
	StageGitInspect           Stage = "git-inspect"
	StageSnapshot             Stage = "snapshot"
	StageWranglerVersion      Stage = "wrangler-version"
	StageAccountMembership    Stage = "account-membership"
	StageDryRun               Stage = "dry-run"
	StageConfirmation         Stage = "confirmation"
	StageProductionAction     Stage = "production-action"
	StageIdentityVerification Stage = "identity-verification"
	StageHealth               Stage = "health"
)

var cloudflareStages = []Stage{
	StageGitInspect,
	StageSnapshot,
	StageWranglerVersion,
	StageAccountMembership,
	StageDryRun,
	StageConfirmation,
	StageProductionAction,
	StageIdentityVerification,
	StageHealth,
}

func Stages() []Stage {
	return append([]Stage(nil), cloudflareStages...)
}

func (s Stage) String() string { return string(s) }

func (s Stage) Valid() bool {
	for _, candidate := range cloudflareStages {
		if s == candidate {
			return true
		}
	}
	return false
}

type StageCode string

const (
	CodeGitInspectOK            StageCode = "CF_GIT_INSPECT_OK"
	CodeSnapshotOK              StageCode = "CF_SNAPSHOT_OK"
	CodeWranglerVersionOK       StageCode = "CF_WRANGLER_VERSION_OK"
	CodeAccountMembershipOK     StageCode = "CF_ACCOUNT_MEMBERSHIP_OK"
	CodeDryRunOK                StageCode = "CF_DRY_RUN_OK"
	CodeWranglerVersionFailed   StageCode = "CF_WRANGLER_VERSION_FAILED"
	CodeAccountMembershipFailed StageCode = "CF_ACCOUNT_MEMBERSHIP_FAILED"
	CodeDryRunFailed            StageCode = "CF_DRY_RUN_FAILED"
)

type TimeoutClassification string

const (
	TimeoutNone      TimeoutClassification = "none"
	TimeoutExceeded  TimeoutClassification = "deadline-exceeded"
	TimeoutCancelled TimeoutClassification = "cancelled"
)

func (c TimeoutClassification) valid() bool {
	return c == TimeoutNone || c == TimeoutExceeded || c == TimeoutCancelled
}

type StageResult struct {
	Stage         Stage                 `json:"stage"`
	Code          StageCode             `json:"code"`
	Elapsed       time.Duration         `json:"elapsed"`
	Timeout       TimeoutClassification `json:"timeout_classification"`
	CorrelationID string                `json:"correlation_id"`
	Remediation   string                `json:"remediation"`
}

var stageCodePattern = regexp.MustCompile(`^CF_[A-Z0-9_]+$`)

func NewStageResult(stage Stage, code StageCode, elapsed time.Duration, classification TimeoutClassification, correlationID string) (StageResult, error) {
	remediation, ok := stageRemediation[stage]
	if !stage.Valid() || !ok || !stageCodePattern.MatchString(string(code)) || elapsed < 0 || !classification.valid() || correlationID == "" {
		return StageResult{}, errors.New("Cloudflare stage result is invalid")
	}
	if strings.HasSuffix(string(code), "_OK") {
		remediation = "No action required."
	}
	return StageResult{
		Stage: stage, Code: code, Elapsed: elapsed, Timeout: classification,
		CorrelationID: correlationID, Remediation: remediation,
	}, nil
}

var stageRemediation = map[Stage]string{
	StageGitInspect:           "Inspect the private operation report, correct the Git scope, and rerun the preview.",
	StageSnapshot:             "Inspect the private operation report, correct the deployment scope, and rerun the preview.",
	StageWranglerVersion:      "Inspect the private operation report, install the supported project-local Wrangler version, and rerun the preview.",
	StageAccountMembership:    "Inspect the private operation report, authenticate the configured Cloudflare account, and rerun the preview.",
	StageDryRun:               "Inspect the private operation report, correct the dry-run input, and rerun the preview.",
	StageConfirmation:         "Inspect the private operation report, regenerate the preview digest, and confirm again.",
	StageProductionAction:     "Inspect the private operation report and verify the remote production state before retrying.",
	StageIdentityVerification: "Inspect the private operation report and verify the remote deployment identity before retrying.",
	StageHealth:               "Inspect the private operation report and verify service health before deciding whether to roll back.",
}

type StageError struct {
	Result  StageResult
	message string
}

func (e *StageError) Error() string { return e.message }

func AsStageError(err error) (*StageError, bool) {
	var stageError *StageError
	ok := errors.As(err, &stageError)
	return stageError, ok
}

func runExternalStage(ctx context.Context, executor opsexec.Executor, request opsexec.Request, stage Stage, successCode, failureCode StageCode, correlationID, message string) (opsexec.Result, StageResult, error) {
	started := time.Now()
	stageContext, cancel := context.WithCancel(ctx)
	if request.Timeout > 0 {
		stageContext, cancel = context.WithTimeout(ctx, request.Timeout)
	}
	defer cancel()
	result := executor.Run(stageContext, request)
	elapsed := result.Duration
	if elapsed <= 0 {
		elapsed = time.Since(started)
	}
	classification := TimeoutNone
	if result.TimedOut || errors.Is(stageContext.Err(), context.DeadlineExceeded) {
		classification = TimeoutExceeded
	} else if errors.Is(stageContext.Err(), context.Canceled) || errors.Is(result.Err, context.Canceled) {
		classification = TimeoutCancelled
	}
	if result.Err == nil && !result.TimedOut && result.ExitCode == 0 && classification == TimeoutNone {
		stageResult, err := NewStageResult(stage, successCode, elapsed, classification, correlationID)
		return result, stageResult, err
	}
	return result, StageResult{}, newStageError(stage, failureCode, elapsed, classification, correlationID, message)
}

func NewSuccessfulStageResult(stage Stage, code StageCode, elapsed time.Duration, correlationID string) (StageResult, error) {
	return NewStageResult(stage, code, elapsed, TimeoutNone, correlationID)
}

func NewCorrelationID() string { return stageCorrelationID("") }

func newStageError(stage Stage, code StageCode, elapsed time.Duration, classification TimeoutClassification, correlationID, message string) error {
	result, err := NewStageResult(stage, code, elapsed, classification, correlationID)
	if err != nil {
		return err
	}
	return &StageError{Result: result, message: message}
}

func stageCorrelationID(existing string) string {
	if existing != "" {
		return existing
	}
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
