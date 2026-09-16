package opscloudflare_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

func TestCloudflareStagesAreStableAndOrdered(t *testing.T) {
	want := []struct {
		stage opscloudflare.Stage
		code  string
	}{
		{opscloudflare.StageGitInspect, "git-inspect"},
		{opscloudflare.StageSnapshot, "snapshot"},
		{opscloudflare.StageWranglerVersion, "wrangler-version"},
		{opscloudflare.StageAccountMembership, "account-membership"},
		{opscloudflare.StageDryRun, "dry-run"},
		{opscloudflare.StageConfirmation, "confirmation"},
		{opscloudflare.StageProductionAction, "production-action"},
		{opscloudflare.StageIdentityVerification, "identity-verification"},
		{opscloudflare.StageHealth, "health"},
	}

	got := opscloudflare.Stages()
	if len(got) != len(want) {
		t.Fatalf("stage count=%d want=%d: %#v", len(got), len(want), got)
	}
	seen := make(map[opscloudflare.Stage]bool, len(got))
	for index, expected := range want {
		if got[index] != expected.stage || got[index].String() != expected.code {
			t.Fatalf("stage[%d]=%q want=%q", index, got[index], expected.code)
		}
		if seen[got[index]] {
			t.Fatalf("duplicate stage %q", got[index])
		}
		seen[got[index]] = true
	}
}

func TestCloudflareStageResultRequiresSafeDiagnosticFields(t *testing.T) {
	result, err := opscloudflare.NewStageResult(
		opscloudflare.StageDryRun,
		opscloudflare.StageCode("CF_DRY_RUN_FAILED"),
		250*time.Millisecond,
		opscloudflare.TimeoutNone,
		"018f4f2d-4e90-7a2f-9e51-4ef0f0c09991",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Stage != opscloudflare.StageDryRun || result.Code != "CF_DRY_RUN_FAILED" {
		t.Fatalf("stage identity missing: %#v", result)
	}
	if result.Elapsed != 250*time.Millisecond || result.Timeout != opscloudflare.TimeoutNone {
		t.Fatalf("stage timing classification missing: %#v", result)
	}
	if result.CorrelationID != "018f4f2d-4e90-7a2f-9e51-4ef0f0c09991" {
		t.Fatalf("correlation ID missing: %#v", result)
	}
	if result.Remediation != "Inspect the private operation report, correct the dry-run input, and rerun the preview." {
		t.Fatalf("remediation is not the fixed stage message: %q", result.Remediation)
	}
}

func TestCloudflareStageResultRejectsInvalidDiagnostics(t *testing.T) {
	tests := []struct {
		name           string
		stage          opscloudflare.Stage
		code           opscloudflare.StageCode
		elapsed        time.Duration
		classification opscloudflare.TimeoutClassification
		correlationID  string
	}{
		{name: "unknown stage", stage: "unknown", code: "CF_UNKNOWN", elapsed: time.Millisecond, classification: opscloudflare.TimeoutNone, correlationID: "correlation-1"},
		{name: "missing code", stage: opscloudflare.StageDryRun, elapsed: time.Millisecond, classification: opscloudflare.TimeoutNone, correlationID: "correlation-1"},
		{name: "negative elapsed", stage: opscloudflare.StageDryRun, code: "CF_DRY_RUN_FAILED", elapsed: -time.Millisecond, classification: opscloudflare.TimeoutNone, correlationID: "correlation-1"},
		{name: "unknown timeout", stage: opscloudflare.StageDryRun, code: "CF_DRY_RUN_FAILED", elapsed: time.Millisecond, classification: "unknown", correlationID: "correlation-1"},
		{name: "missing correlation", stage: opscloudflare.StageDryRun, code: "CF_DRY_RUN_FAILED", elapsed: time.Millisecond, classification: opscloudflare.TimeoutNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := opscloudflare.NewStageResult(test.stage, test.code, test.elapsed, test.classification, test.correlationID); err == nil {
				t.Fatal("invalid stage diagnostics were accepted")
			}
		})
	}
}

func TestCloudflareStageResultCannotCarrySensitiveOutput(t *testing.T) {
	typeOfResult := reflect.TypeOf(opscloudflare.StageResult{})
	for index := 0; index < typeOfResult.NumField(); index++ {
		field := typeOfResult.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"stdout", "stderr", "account", "token", "secret", "source", "content", "detail"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("stage result exposes forbidden field %q", field.Name)
			}
		}
	}
	result, err := opscloudflare.NewStageResult(opscloudflare.StageSnapshot, "CF_SNAPSHOT_FAILED", time.Millisecond, opscloudflare.TimeoutNone, "correlation-1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"stdout", "stderr", "account_id", "token", "secret", "source", "content", "detail"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("stage result JSON exposes %q: %s", forbidden, encoded)
		}
	}
}

func TestCloudflareStageRejectsUnknownValue(t *testing.T) {
	if opscloudflare.Stage("unknown").Valid() {
		t.Fatal("unknown stage is valid")
	}
	for _, stage := range opscloudflare.Stages() {
		if !stage.Valid() {
			t.Fatalf("declared stage is invalid: %q", stage)
		}
	}
}

func TestCloudflareSlowExecutorClassifiesEachTimedOutStage(t *testing.T) {
	privateValues := []string{"private-token", "0123456789abcdef0123456789abcdef", "private-source"}
	tests := []struct {
		name      string
		responses []timedStageResponse
		wantStage opscloudflare.Stage
		wantCode  opscloudflare.StageCode
	}{
		{
			name:      "Wrangler version",
			responses: []timedStageResponse{{delay: 100 * time.Millisecond}},
			wantStage: opscloudflare.StageWranglerVersion, wantCode: opscloudflare.CodeWranglerVersionFailed,
		},
		{
			name: "account membership",
			responses: []timedStageResponse{
				{result: opsexec.Result{ExitCode: 0, Stdout: "4.107.0\n"}},
				{delay: 100 * time.Millisecond},
			},
			wantStage: opscloudflare.StageAccountMembership, wantCode: opscloudflare.CodeAccountMembershipFailed,
		},
		{
			name: "dry-run",
			responses: []timedStageResponse{
				{result: opsexec.Result{ExitCode: 0, Stdout: "4.107.0\n"}},
				{result: opsexec.Result{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`}},
				{result: opsexec.Result{ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}`}},
				{delay: 100 * time.Millisecond},
			},
			wantStage: opscloudflare.StageDryRun, wantCode: opscloudflare.CodeDryRunFailed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := samplePlanRequest(newCloudflareProject(t))
			request.Preflight.Timeout = 20 * time.Millisecond
			executor := &timedStageExecutor{responses: test.responses, privateValues: privateValues}
			_, err := opscloudflare.CreatePlan(context.Background(), executor, request)
			stageError, ok := opscloudflare.AsStageError(err)
			if !ok {
				t.Fatalf("expected stage error, got %v", err)
			}
			if stageError.Result.Stage != test.wantStage || stageError.Result.Code != test.wantCode || stageError.Result.Timeout != opscloudflare.TimeoutExceeded {
				t.Fatalf("misclassified timeout: %#v", stageError.Result)
			}
			visible, marshalErr := json.Marshal(stageError.Result)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			visible = append(visible, stageError.Error()...)
			for _, private := range privateValues {
				if strings.Contains(string(visible), private) {
					t.Fatalf("private executor output leaked: %s", visible)
				}
			}
		})
	}
}

func TestCloudflareStagesReceiveIndependentTimeoutBudgets(t *testing.T) {
	request := samplePlanRequest(newCloudflareProject(t))
	request.Preflight.Timeout = 200 * time.Millisecond
	executor := &timedStageExecutor{responses: []timedStageResponse{
		{delay: 80 * time.Millisecond, result: opsexec.Result{ExitCode: 0, Stdout: "4.107.0\n"}},
		{delay: 80 * time.Millisecond, result: opsexec.Result{ExitCode: 0, Stdout: `{"accounts":[{"id":"0123456789abcdef0123456789abcdef"}]}`}},
		{delay: 80 * time.Millisecond, result: opsexec.Result{ExitCode: 0, Stdout: `{"id":"11111111-1111-4111-8111-111111111111","versions":[{"version_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","percentage":100}]}`}},
		{delay: 80 * time.Millisecond, result: opsexec.Result{ExitCode: 0}},
	}}
	started := time.Now()
	if _, err := opscloudflare.CreatePlan(context.Background(), executor, request); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed <= request.Preflight.Timeout {
		t.Fatalf("test did not exceed one stage budget: elapsed=%s budget=%s", elapsed, request.Preflight.Timeout)
	}
}

func TestCloudflareParentCancellationCancelsActiveStage(t *testing.T) {
	request := samplePlanRequest(newCloudflareProject(t))
	request.Preflight.Timeout = time.Second
	executor := &timedStageExecutor{responses: []timedStageResponse{{delay: time.Second}}}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	_, err := opscloudflare.CreatePlan(ctx, executor, request)
	stageError, ok := opscloudflare.AsStageError(err)
	if !ok {
		t.Fatalf("expected stage error, got %v", err)
	}
	if stageError.Result.Stage != opscloudflare.StageWranglerVersion || stageError.Result.Timeout != opscloudflare.TimeoutCancelled || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("parent cancellation was misclassified: %#v parent=%v", stageError.Result, ctx.Err())
	}
}

type timedStageResponse struct {
	delay  time.Duration
	result opsexec.Result
}

type timedStageExecutor struct {
	responses     []timedStageResponse
	privateValues []string
}

func (e *timedStageExecutor) Run(ctx context.Context, _ opsexec.Request) opsexec.Result {
	if len(e.responses) == 0 {
		return opsexec.Result{ExitCode: -1, Err: errors.New("unexpected executor call")}
	}
	response := e.responses[0]
	e.responses = e.responses[1:]
	started := time.Now()
	if response.delay > 0 {
		timer := time.NewTimer(response.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return opsexec.Result{
				ExitCode: -1, Err: ctx.Err(), TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
				Duration: time.Since(started), Stdout: strings.Join(e.privateValues, " "), Stderr: strings.Join(e.privateValues, " "),
			}
		case <-timer.C:
		}
	}
	response.result.Duration = time.Since(started)
	return response.result
}

func (*timedStageExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{ExitCode: -1}
}
