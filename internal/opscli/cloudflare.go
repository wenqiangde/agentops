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

func opsCloudflareDeploy(reportRoot string, service opsconfig.Service, production opsconfig.Environment, requestedVersion string, confirm bool, previewDigest string, timeout time.Duration, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	gitEvidence, err := opsgit.Inspect(ctx, opsgit.Request{
		RepositoryRoot: service.Source.RepositoryRoot,
		Scopes:         service.Source.DeploymentScope,
	})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare Git scope inspection failed")
		return 1
	}
	plan, err := opscloudflare.CreatePlan(ctx, opsCloudflareExecutor(), opscloudflare.PlanRequest{
		Service: service.ID, RequestedVersion: requestedVersion,
		Git: gitEvidence,
		Preflight: opscloudflare.Request{
			SourcePath: service.Source.Path, Worker: production.Worker,
			AccountID: production.AccountID, WranglerConfig: production.WranglerConfig,
			Timeout: timeout,
		},
		RequireCommittedScope: service.Deployment.RequireCommittedScope,
	})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview failed")
		return 1
	}
	encoded, err := json.MarshalIndent(plan, "", "  ")
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
		confirmed, err := opscloudflare.Confirm(plan, previewDigest)
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest is stale")
			return 1
		}
		if err := revalidateCloudflareGitEvidence(ctx, service, gitEvidence); err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest is stale")
			return 1
		}
		started := time.Now().UTC()
		result, err := opscloudflare.Apply(ctx, opsCloudflareExecutor(), confirmed)
		if err != nil || !result.Success {
			if result.ProductionWriteSucceeded {
				writeCloudflareApplyFailureReport(reportRoot, "cloudflare-deploy", digest, plan, started, time.Now().UTC(), stdout)
			}
			fmt.Fprintln(stdout, "deployment: failed")
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment apply failed")
			return 1
		}
		health := opsHealthProbe(ctx, opsCloudflareExecutor(), production, production.Health, timeout)
		finished := time.Now().UTC()
		operationID, err := newOpsOperationID("cloudflare-deploy")
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment report identity failed")
			return 1
		}
		report := cloudflareOperationReport(operationID, digest, plan, health, started, finished)
		reportPath, err := opsreport.Write(reportRoot, report, nil)
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment report failed")
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

func revalidateCloudflareGitEvidence(ctx context.Context, service opsconfig.Service, expected opsgit.Evidence) error {
	actual, err := opsgit.Inspect(ctx, opsgit.Request{RepositoryRoot: service.Source.RepositoryRoot, Scopes: service.Source.DeploymentScope})
	if err != nil || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("Cloudflare Git deployment evidence changed")
	}
	return nil
}

func writeCloudflareApplyFailureReport(reportRoot, operationKind, digest string, plan opscloudflare.CloudflareDeployPlan, started, finished time.Time, stdout io.Writer) {
	operationID, err := newOpsOperationID(operationKind)
	if err != nil {
		return
	}
	report := opsreport.Report{
		OperationID: operationID, Actor: plan.AccountID, Service: plan.Service, Environment: plan.Environment, Host: plan.Worker,
		PlanDigest: digest, RequestedVersion: plan.RequestedVersion, ArtifactDigest: plan.ScopeContentSHA256,
		Steps:    []opsreport.StepResult{{Order: 1, Kind: "cloudflare-deploy", Status: "failed", StartedAt: started, FinishedAt: finished, Error: "post-deploy identity verification failed"}},
		Health:   opsreport.HealthEvidence{Type: "http", State: "not-checked", Healthy: false},
		Recovery: "manual-review-required", Terminal: true, StartedAt: started, FinishedAt: finished,
		Error: "post-deploy identity verification failed", ManualWork: "inspect Cloudflare deployment state before retrying",
	}
	reportPath, err := opsreport.Write(reportRoot, report, nil)
	if err == nil {
		fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	}
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
