package opscli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

var opsCloudflareExecutor = func() opsexec.Executor { return opsexec.NewLocalExecutor() }
var opsCloudflareSnapshot = opscloudflare.CreateDeploymentSnapshot

// Cloudflare production writes remain closed until execution isolation passes
// the elevated-risk review gate. Preview and validation stay available.
var cloudflareProductionWritesEnabled = false

const cloudflareProductionWritesDisabledMessage = "agentops: Cloudflare production writes are temporarily disabled pending security review; use preview mode only"

func opsCloudflareDeploy(reportRoot string, service opsconfig.Service, production opsconfig.Environment, requestedVersion string, confirm bool, previewDigest string, timeout time.Duration, stdout, stderr io.Writer) int {
	correlationID := opscloudflare.NewCorrelationID()
	gitStarted := time.Now()
	gitCtx, gitCancel := context.WithTimeout(context.Background(), timeout)
	gitEvidence, err := opsgit.Inspect(gitCtx, opsgit.Request{
		RepositoryRoot: service.Source.RepositoryRoot,
		Scopes:         service.Source.DeploymentScope,
	})
	gitCancel()
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare Git scope inspection failed")
		return 1
	}
	gitStage, err := opscloudflare.NewSuccessfulStageResult(opscloudflare.StageGitInspect, opscloudflare.CodeGitInspectOK, time.Since(gitStarted), correlationID)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare Git stage diagnostic failed")
		return 1
	}
	snapshotStarted := time.Now()
	snapshot, err := opsCloudflareSnapshot(service.Source.RepositoryRoot, service.Source.Path, service.Source.DeploymentScope)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare source snapshot failed")
		return 1
	}
	snapshotStage, err := opscloudflare.NewSuccessfulStageResult(opscloudflare.StageSnapshot, opscloudflare.CodeSnapshotOK, time.Since(snapshotStarted), correlationID)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare snapshot stage diagnostic failed")
		return 1
	}
	defer snapshot.Cleanup()
	plan, err := opscloudflare.CreatePlan(context.Background(), opsCloudflareExecutor(), opscloudflare.PlanRequest{
		Service: service.ID, RequestedVersion: requestedVersion,
		Git: gitEvidence,
		Preflight: opscloudflare.Request{
			SourcePath: snapshot.Path, RepositoryRoot: snapshot.Root, DeploymentScope: service.Source.DeploymentScope, Worker: production.Worker,
			AccountID: production.AccountID, WranglerConfig: production.WranglerConfig,
			Timeout: timeout, CorrelationID: correlationID,
		},
		RepositorySourcePath: service.Source.Path, DeploymentInputSHA256: snapshot.SHA256,
		RequireCommittedScope: service.Deployment.RequireCommittedScope,
	})
	if err != nil {
		if !writeCloudflareStageDiagnostic(stderr, err) {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview failed")
		}
		return 1
	}
	plan.Diagnostics = append([]opscloudflare.StageResult{gitStage, snapshotStage}, plan.Diagnostics...)
	displayPlan := plan
	displayPlan.AccountID = maskedCloudflareAccountID(plan.AccountID)
	encoded, err := json.MarshalIndent(displayPlan, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	if plan.Blocked {
		fmt.Fprintf(stderr, "agentops: Cloudflare deployment preview blocked: %s\n", plan.BlockReason)
		return 1
	}
	digest, err := opscloudflare.Digest(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if confirm {
		if !cloudflareProductionWritesEnabled {
			fmt.Fprintln(stderr, cloudflareProductionWritesDisabledMessage)
			return 1
		}
		_, err := opscloudflare.Confirm(plan, previewDigest)
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest is stale")
			return 1
		}
		applyCtx, applyCancel := context.WithTimeout(context.Background(), timeout)
		defer applyCancel()
		if err := revalidateCloudflareGitEvidence(applyCtx, service, gitEvidence); err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest is stale")
			return 1
		}
		if err := opscloudflare.SealSourceSnapshot(snapshot.Root, snapshot.SHA256); err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest is stale")
			return 1
		}
		started := time.Now().UTC()
		// Task 5 binds the confirmed owned payload and token-backed client here.
		// Until then, the closed production gate and nil writer both fail closed.
		result, err := opscloudflare.Apply(applyCtx, nil, opscloudflare.ConfirmedProductionPlan{})
		if err != nil || !result.Success {
			if result.ProductionWriteSucceeded {
				if reportErr := writeCloudflareApplyFailureReport(reportRoot, "cloudflare-deploy", digest, plan, started, time.Now().UTC(), stdout); reportErr != nil {
					fmt.Fprintln(stderr, "agentops: production state unknown; audit persistence failed")
				}
			}
			fmt.Fprintln(stdout, "deployment: failed")
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment apply failed")
			return 1
		}
		health := opsHealthProbe(applyCtx, opsCloudflareExecutor(), production, production.Health, timeout)
		finished := time.Now().UTC()
		operationID, err := newOpsOperationID("cloudflare-deploy")
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment report identity failed")
			return 1
		}
		report := cloudflareOperationReport(operationID, digest, plan, health, started, finished)
		reportPath, err := writeCloudflareReport(reportRoot, report)
		if err != nil {
			fmt.Fprintln(stderr, "agentops: production state unknown; audit persistence failed")
			return 1
		}
		fmt.Fprintf(stdout, "deployment-id: %s\n", result.DeploymentID)
		for _, versionID := range result.VersionIDs {
			fmt.Fprintf(stdout, "version-id: %s\n", versionID)
		}
		fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
		if !health.Healthy {
			fmt.Fprintln(stdout, "deployment: failed")
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment HTTP health check failed; inspect the operation report")
			return 1
		}
		fmt.Fprintln(stdout, "deployment: succeeded")
	}
	return 0
}

func writeCloudflareStageDiagnostic(output io.Writer, err error) bool {
	stageError, ok := opscloudflare.AsStageError(err)
	if !ok {
		return false
	}
	result := stageError.Result
	fmt.Fprintf(output, "agentops: stage=%s code=%s elapsed=%s timeout=%s correlation-id=%s remediation=%s\n",
		result.Stage, result.Code, result.Elapsed, result.Timeout, result.CorrelationID, result.Remediation)
	return true
}

func maskedCloudflareAccountID(accountID string) string {
	if len(accountID) < 10 {
		return "[redacted]"
	}
	return accountID[:6] + "..." + accountID[len(accountID)-4:]
}

func revalidateCloudflareGitEvidence(ctx context.Context, service opsconfig.Service, expected opsgit.Evidence) error {
	actual, err := opsgit.Inspect(ctx, opsgit.Request{RepositoryRoot: service.Source.RepositoryRoot, Scopes: service.Source.DeploymentScope})
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("Cloudflare Git deployment evidence changed")
	}
	return nil
}

func writeCloudflareApplyFailureReport(reportRoot, operationKind, digest string, plan opscloudflare.CloudflareDeployPlan, started, finished time.Time, stdout io.Writer) error {
	operationID, err := newOpsOperationID(operationKind)
	if err != nil {
		return err
	}
	report := opsreport.Report{
		OperationID: operationID, Actor: plan.AccountID, Service: plan.Service, Environment: plan.Environment, Host: plan.Worker,
		PlanDigest: digest, RequestedVersion: plan.RequestedVersion, ArtifactDigest: plan.ScopeContentSHA256,
		Steps:    []opsreport.StepResult{{Order: 1, Kind: "cloudflare-deploy", Status: "failed", StartedAt: started, FinishedAt: finished, Error: "post-deploy identity verification failed"}},
		Health:   opsreport.HealthEvidence{Type: "http", State: "not-checked", Healthy: false},
		Recovery: "manual-review-required", Terminal: true, StartedAt: started, FinishedAt: finished,
		Error: "post-deploy identity verification failed", ManualWork: "inspect Cloudflare deployment state before retrying",
	}
	reportPath, err := writeCloudflareReport(reportRoot, report)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	return nil
}

func cloudflareOperationReport(operationID, digest string, plan opscloudflare.CloudflareDeployPlan, health opshealth.Result, started, finished time.Time) opsreport.Report {
	state := "healthy"
	errorSummary := ""
	if !health.Healthy {
		state = "failed"
		errorSummary = "HTTP health check failed"
	}
	return opsreport.Report{
		OperationID:      operationID,
		Actor:            plan.AccountID,
		Service:          plan.Service,
		Environment:      plan.Environment,
		Host:             plan.Worker,
		PlanDigest:       digest,
		RequestedVersion: plan.RequestedVersion,
		ArtifactDigest:   plan.ScopeContentSHA256,
		Steps: []opsreport.StepResult{
			{Order: 1, Kind: "cloudflare-deploy", Status: "succeeded", StartedAt: started, FinishedAt: finished},
			{Order: 2, Kind: "http-health", Status: state, StartedAt: started, FinishedAt: finished, Error: errorSummary},
		},
		Health:     opsreport.HealthEvidence{Type: health.Type, State: state, Healthy: health.Healthy, StatusCode: health.StatusCode, Detail: health.Detail},
		Recovery:   "not-applicable",
		Terminal:   true,
		StartedAt:  started,
		FinishedAt: finished,
		Error:      errorSummary,
		ManualWork: "none",
	}
}
