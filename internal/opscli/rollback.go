package opscli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsdeploy"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsreport"
	"github.com/wenqiangde/agentops/internal/paths"
)

var opsRollbackExecutor = func() opsexec.Executor { return opsexec.NewSSHExecutor() }

func opsRollback(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	serviceID, targetVersion, confirm, previewDigest, ok := parseOpsRollbackArgs(args, stderr)
	if !ok {
		return 1
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	if hasGlobalOpsIssue(issues) {
		printOpsIssues(stderr, issues)
		return 1
	}
	service, found := inv.Services[serviceID]
	if !found {
		selected := issuesForService(issues, serviceID)
		if len(selected) != 0 {
			printOpsIssues(stderr, selected)
		} else {
			fmt.Fprintf(stderr, "agentops: unknown service: %s\n", serviceID)
		}
		return 1
	}
	cloudflareProduction, cloudflareFound := service.Environments[opsconfig.EnvironmentProduction]
	if cloudflareFound && cloudflareProduction.Kind == opsconfig.EnvironmentKindCloudflareWorkers {
		timeout, err := time.ParseDuration(inv.Policies.Execution.DefaultTimeout)
		if err != nil || timeout <= 0 {
			fmt.Fprintln(stderr, "agentops: invalid default operation timeout")
			return 1
		}
		return opsCloudflareRollback(p.OpsReportRoot, service, cloudflareProduction, targetVersion, confirm, previewDigest, timeout, stdout, stderr)
	}
	if !service.BuildConfigured() {
		fmt.Fprintln(stderr, "agentops: service has no managed build/deploy configuration")
		return 1
	}
	production := service.Environments[opsconfig.EnvironmentProduction]
	host, found := inv.Hosts[production.Host]
	if !found || production.Kind != opsconfig.EnvironmentKindSSH {
		fmt.Fprintln(stderr, "agentops: service has no unambiguous production target")
		return 1
	}
	timeout, err := time.ParseDuration(inv.Policies.Execution.DefaultTimeout)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "agentops: invalid default operation timeout")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	executor := opsRollbackExecutor()
	plan, err := opsdeploy.CreateRollback(ctx, executor, service, host, inv.Policies, targetVersion, timeout)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: rollback preview collection failed")
		return 1
	}
	encoded, err := opsdeploy.MarshalRollbackIndented(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: rollback preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	if plan.Blocked {
		fmt.Fprintf(stderr, "agentops: rollback preview blocked: %s\n", plan.BlockReason)
		return 1
	}
	digest, err := opsdeploy.RollbackDigest(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: rollback preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if !confirm {
		return 0
	}
	if err := opsdeploy.ConfirmRollback(plan, previewDigest); err != nil {
		if strings.Contains(err.Error(), "stale") {
			fmt.Fprintln(stderr, "agentops: rollback preview digest is stale")
		} else {
			fmt.Fprintln(stderr, "agentops: rollback preview cannot be confirmed")
		}
		return 1
	}
	operationID, err := newOpsOperationID("rollback")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: cannot create rollback operation identity")
		return 1
	}
	started := time.Now().UTC()
	reportPath := ""
	sink := func(_ context.Context, result opsdeploy.RollbackResult) error {
		written, writeErr := opsreport.Write(p.OpsReportRoot, rollbackOperationReport(operationID, digest, plan, result, started, time.Now().UTC()), nil)
		if writeErr == nil {
			reportPath = written
		}
		return writeErr
	}
	result, applyErr := opsdeploy.ApplyRollback(ctx, executor, opsdeploy.ConfirmedRollbackPlan{Plan: plan, Digest: digest}, timeout, sink)
	if applyErr != nil && reportPath == "" {
		_ = sink(context.Background(), result)
	}
	if applyErr != nil {
		fmt.Fprintln(stdout, "rollback: failed")
		if result.Recovered {
			fmt.Fprintln(stdout, "recovery: restored-original-release")
		}
		if reportPath != "" {
			fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
		}
		fmt.Fprintln(stderr, "agentops: rollback apply failed; inspect the operation report")
		return 1
	}
	fmt.Fprintln(stdout, "rollback: succeeded")
	fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	return 0
}

func opsCloudflareRollback(reportRoot string, service opsconfig.Service, production opsconfig.Environment, targetID string, confirm bool, previewDigest string, timeout time.Duration, stdout, stderr io.Writer) int {
	gitCtx, gitCancel := context.WithTimeout(context.Background(), timeout)
	gitEvidence, err := opsgit.Inspect(gitCtx, opsgit.Request{RepositoryRoot: service.Source.RepositoryRoot, Scopes: service.Source.DeploymentScope})
	gitCancel()
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback Git scope inspection failed")
		return 1
	}
	snapshot, err := opsCloudflareSnapshot(service.Source.RepositoryRoot, service.Source.Path, service.Source.DeploymentScope)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare source snapshot failed")
		return 1
	}
	defer snapshot.Cleanup()
	plan, err := opscloudflare.CreateRollbackPlan(context.Background(), opsCloudflareExecutor(), opscloudflare.RollbackPlanRequest{
		Service: service.ID, TargetID: targetID, Git: gitEvidence,
		Preflight: opscloudflare.Request{
			SourcePath: snapshot.Path, RepositoryRoot: snapshot.Root, DeploymentScope: service.Source.DeploymentScope, Worker: production.Worker, AccountID: production.AccountID,
			WranglerConfig: production.WranglerConfig, Timeout: timeout,
		},
		RepositorySourcePath: service.Source.Path, DeploymentInputSHA256: snapshot.SHA256,
		RequireCommittedScope: service.Deployment.RequireCommittedScope,
	})
	if err != nil {
		if !writeCloudflareStageDiagnostic(stderr, err) {
			fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview failed")
		}
		return 1
	}
	if err := opscloudflarepayload.ValidateWranglerVersion(production.APIProfile, plan.WranglerVersion); err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production capability validation failed")
		return 1
	}
	configBytes, err := os.ReadFile(filepath.Join(snapshot.Path, production.WranglerConfig))
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production capability validation failed")
		return 1
	}
	config, err := opscloudflarepayload.ParseWranglerConfig(production.APIProfile, configBytes)
	if err != nil || config.Name != production.Worker || config.AccountID != production.AccountID {
		fmt.Fprintln(stderr, "agentops: Cloudflare production capability validation failed")
		return 1
	}
	request, err := opscloudflarepayload.NewRollbackRequest(plan.AccountID, plan.Worker, plan.TargetVersionID, plan.CurrentDeploymentID, plan.DeploymentInputSHA256, timeout)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production rollback request construction failed")
		return 1
	}
	identity := opscloudflare.ProductionConfirmationIdentity{
		APIProfile: production.APIProfile, ClientVersion: opscloudflarepayload.ProductionClientVersion,
		EndpointSequence: opscloudflarepayload.RollbackEndpointSequence(request), TokenProviderIdentity: cloudflareEnvironmentTokenProvider{}.Identity(),
	}
	displayPlan := plan
	displayPlan.AccountID = maskedCloudflareAccountID(plan.AccountID)
	encoded, err := json.MarshalIndent(displayPlan, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	if plan.Blocked {
		fmt.Fprintf(stderr, "agentops: Cloudflare rollback preview blocked: %s\n", plan.BlockReason)
		return 1
	}
	digest, err := opscloudflare.RollbackProductionDigest(plan, request, identity)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if !confirm {
		return 0
	}
	confirmed, err := opscloudflare.ConfirmProductionRollback(plan, request, identity, previewDigest)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview digest is stale")
		return 1
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), timeout)
	defer applyCancel()
	if err := revalidateCloudflareGitEvidence(applyCtx, service, gitEvidence); err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview digest is stale")
		return 1
	}
	if err := opscloudflare.SealSourceSnapshot(snapshot.Root, snapshot.SHA256); err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback preview digest is stale")
		return 1
	}
	started := time.Now().UTC()
	client, err := opsCloudflareProductionClient()
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare trusted production client is unavailable")
		return 1
	}
	result, err := opscloudflare.ApplyRollback(applyCtx, client, confirmed)
	if err != nil || !result.Success {
		if result.ProductionWriteSucceeded {
			if reportErr := writeCloudflareRollbackFailureReport(reportRoot, digest, plan, result, started, time.Now().UTC(), stdout); reportErr != nil {
				fmt.Fprintln(stderr, "agentops: production state unknown; audit persistence failed")
			}
		}
		fmt.Fprintln(stdout, "rollback: failed")
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback apply failed")
		return 1
	}
	health := opsHealthProbe(applyCtx, opsCloudflareExecutor(), production, production.Health, timeout)
	finished := time.Now().UTC()
	operationID, err := newOpsOperationID("cloudflare-rollback")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback report identity failed")
		return 1
	}
	reportPath, err := writeCloudflareReport(reportRoot, cloudflareRollbackOperationReport(operationID, digest, plan, health, started, finished))
	if err != nil {
		fmt.Fprintln(stderr, "agentops: production state unknown; audit persistence failed")
		return 1
	}
	fmt.Fprintf(stdout, "deployment-id: %s\nversion-id: %s\n", result.DeploymentID, result.VersionID)
	fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	if !health.Healthy {
		fmt.Fprintln(stdout, "rollback: failed")
		fmt.Fprintln(stderr, "agentops: Cloudflare rollback HTTP health check failed; inspect the operation report")
		return 1
	}
	fmt.Fprintln(stdout, "rollback: succeeded")
	return 0
}

func writeCloudflareRollbackFailureReport(reportRoot, digest string, plan opscloudflare.CloudflareRollbackPlan, result opscloudflare.RollbackResult, started, finished time.Time, stdout io.Writer) error {
	operationID, err := newOpsOperationID("cloudflare-rollback")
	if err != nil {
		return err
	}
	stage, err := opscloudflare.NewStageResult(opscloudflare.StageIdentityVerification, "CF_ROLLBACK_IDENTITY_MISMATCH", finished.Sub(started), opscloudflare.TimeoutNone, opscloudflare.NewCorrelationID())
	if err != nil {
		return err
	}
	versionIDs := []string(nil)
	if result.VersionID != "" {
		versionIDs = []string{result.VersionID}
	}
	report, err := opsreport.NewCloudflareReport(opsreport.CloudflareReportInput{
		OperationID: operationID, Operation: "rollback", Actor: "environment", Service: plan.Service, Environment: plan.Environment, Worker: plan.Worker,
		PlanDigest: digest, PayloadDigest: plan.DeploymentInputSHA256, RequestedVersion: plan.TargetVersionID,
		PreviousDeploymentID: plan.CurrentDeploymentID, DeploymentID: result.DeploymentID, VersionIDs: versionIDs, Stages: []opscloudflare.StageResult{stage},
		Outcome: opsreport.CloudflareUnknownState, Health: opsreport.HealthEvidence{Type: "http", State: "not-checked"}, ErrorCode: "CF_ROLLBACK_IDENTITY_MISMATCH",
		StartedAt: started, FinishedAt: finished,
	})
	if err != nil {
		return err
	}
	reportPath, err := writeCloudflareReport(reportRoot, report)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	return nil
}

func cloudflareRollbackOperationReport(operationID, digest string, plan opscloudflare.CloudflareRollbackPlan, health opshealth.Result, started, finished time.Time) opsreport.Report {
	state := "healthy"
	errorSummary := ""
	if !health.Healthy {
		state = "failed"
		errorSummary = "HTTP health check failed"
	}
	previous := "multiple"
	if len(plan.CurrentVersionIDs) == 1 {
		previous = plan.CurrentVersionIDs[0]
	}
	return opsreport.Report{
		OperationID: operationID, Actor: plan.AccountID, Service: plan.Service, Environment: plan.Environment, Host: plan.Worker,
		PlanDigest: digest, PreviousVersion: previous, RequestedVersion: plan.TargetVersionID, ArtifactDigest: plan.ScopeContentSHA256,
		Steps: []opsreport.StepResult{
			{Order: 1, Kind: "cloudflare-rollback", Status: "succeeded", StartedAt: started, FinishedAt: finished},
			{Order: 2, Kind: "active-deployment-verification", Status: "succeeded", StartedAt: started, FinishedAt: finished},
			{Order: 3, Kind: "http-health", Status: state, StartedAt: started, FinishedAt: finished, Error: errorSummary},
		},
		Health:   opsreport.HealthEvidence{Type: health.Type, State: state, Healthy: health.Healthy, StatusCode: health.StatusCode, Detail: health.Detail},
		Recovery: "not-applicable", Terminal: true, StartedAt: started, FinishedAt: finished, Error: errorSummary, ManualWork: "none",
	}
}

func parseOpsRollbackArgs(args []string, stderr io.Writer) (string, string, bool, string, bool) {
	if len(args) < 5 || strings.HasPrefix(args[0], "-") || args[1] != "--environment" || args[2] != opsconfig.EnvironmentProduction || args[3] != "--version" || strings.HasPrefix(args[4], "-") {
		opsUsageError(stderr, "rollback requires one service, --environment production, and --version <version>")
		return "", "", false, "", false
	}
	service, version := args[0], args[4]
	confirm := false
	digest := ""
	for index := 5; index < len(args); index++ {
		switch args[index] {
		case "--confirm":
			if confirm {
				opsUsageError(stderr, "duplicate --confirm")
				return "", "", false, "", false
			}
			confirm = true
		case "--preview-digest":
			if digest != "" || index+1 >= len(args) {
				opsUsageError(stderr, "--preview-digest requires one value")
				return "", "", false, "", false
			}
			index++
			digest = args[index]
		default:
			opsUsageError(stderr, "unknown rollback option: "+args[index])
			return "", "", false, "", false
		}
	}
	if confirm != (digest != "") || (digest != "" && !opsdeploy.IsDigest(digest)) {
		opsUsageError(stderr, "--confirm and --preview-digest <64lowerhex> must be used together")
		return "", "", false, "", false
	}
	return service, version, confirm, digest, true
}

func rollbackOperationReport(operationID, digest string, plan opsdeploy.RollbackPlan, result opsdeploy.RollbackResult, started, finished time.Time) opsreport.Report {
	steps := make([]opsreport.StepResult, 0, len(result.Steps))
	for index, step := range result.Steps {
		stepError := ""
		if step.State != "succeeded" {
			stepError = "step failed"
		}
		steps = append(steps, opsreport.StepResult{Order: index + 1, Kind: step.Kind, Status: step.State, StartedAt: step.StartedAt, FinishedAt: step.FinishedAt, Error: stepError})
	}
	healthState := "failed"
	if result.Success {
		healthState = "healthy"
	}
	recovery := "not-required"
	manualWork := "none"
	if result.Recovered {
		recovery = "restored-original-release"
	} else if result.Activated && !result.Success {
		recovery = "automatic-recovery-not-completed"
		manualWork = "inspect rollback and recovery state"
	}
	errorSummary := ""
	if !result.Success {
		errorSummary = "application rollback failed"
	}
	return opsreport.Report{
		OperationID: operationID, Actor: plan.RemoteUser, Service: plan.Service, Environment: plan.Environment, Host: plan.Host,
		PlanDigest: digest, PreviousVersion: plan.CurrentVersion, RequestedVersion: plan.TargetVersion, ArtifactDigest: plan.TargetArtifactSHA256,
		Steps: steps, Health: opsreport.HealthEvidence{Type: plan.Health.Type, State: healthState, Healthy: result.Success}, Recovery: recovery, Terminal: true,
		StartedAt: started, FinishedAt: finished, Error: errorSummary, ManualWork: manualWork,
	}
}
