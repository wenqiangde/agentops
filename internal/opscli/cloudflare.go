package opscli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsreport"
)

var opsCloudflareExecutor = func() opsexec.Executor { return opsexec.NewLocalExecutor() }
var opsCloudflareSnapshot = opscloudflare.CreateDeploymentSnapshot

type cloudflareProductionWriter interface {
	opscloudflare.DeploymentWriter
	opscloudflare.RollbackWriter
}

var opsCloudflareProductionClient = func() (cloudflareProductionWriter, error) {
	return opscloudflarepayload.NewCloudflareClient(cloudflareEnvironmentTokenProvider{})
}

type cloudflareEnvironmentTokenProvider struct{}

func (cloudflareEnvironmentTokenProvider) Token(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, found := os.LookupEnv("AGENTOPS_CLOUDFLARE_API_TOKEN")
	if !found || value == "" {
		return nil, fmt.Errorf("Cloudflare production token is unavailable")
	}
	return []byte(value), nil
}

func (cloudflareEnvironmentTokenProvider) Identity() string { return "environment" }

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
		APIProfile:            production.APIProfile,
		RequireCommittedScope: service.Deployment.RequireCommittedScope,
	})
	if err != nil {
		if errors.Is(err, opscloudflarepayload.ErrUnsupportedWranglerProfile) {
			fmt.Fprintln(stderr, "agentops: Cloudflare production capability validation failed")
			return 1
		}
		if !writeCloudflareStageDiagnostic(stderr, err) {
			fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview failed")
		}
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
	sourceRelative, err := filepath.Rel(snapshot.Root, snapshot.Path)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production payload boundary failed")
		return 1
	}
	bundleRelative := filepath.Join(sourceRelative, plan.BundleDirectory)
	payload, _, err := opscloudflarepayload.BuildPayload(snapshot.Root, filepath.Join(sourceRelative, production.WranglerConfig), bundleRelative, production.APIProfile)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production payload capture failed")
		return 1
	}
	if err := os.RemoveAll(filepath.Join(snapshot.Root, bundleRelative)); err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production bundle cleanup failed")
		return 1
	}
	request, err := opscloudflarepayload.NewRequest(plan.AccountID, plan.Worker, plan.CurrentDeploymentID, plan.CurrentVersionIDs, payload.SHA256, payload, timeout)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production request construction failed")
		return 1
	}
	plan.DeploymentInputSHA256 = payload.SHA256
	endpointSequence, err := opscloudflarepayload.EndpointSequence(request)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare production endpoint validation failed")
		return 1
	}
	identity := opscloudflare.ProductionConfirmationIdentity{
		APIProfile: production.APIProfile, ClientVersion: opscloudflarepayload.ProductionClientVersion,
		EndpointSequence: endpointSequence, TokenProviderIdentity: cloudflareEnvironmentTokenProvider{}.Identity(),
		MigrationDerivationAlgorithm: opscloudflarepayload.MigrationDerivationAlgorithm,
		AllowedMigrationRemoteStates: opscloudflarepayload.AllowedMigrationRemoteStates(),
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
	digest, err := opscloudflare.ProductionDigest(plan, request, identity)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if confirm {
		confirmed, err := opscloudflare.ConfirmProduction(plan, request, identity, previewDigest)
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
		client, err := opsCloudflareProductionClient()
		if err != nil {
			fmt.Fprintln(stderr, "agentops: Cloudflare trusted production client is unavailable")
			return 1
		}
		result, err := opscloudflare.Apply(applyCtx, client, confirmed)
		if err != nil || !result.Success {
			if reportErr := writeCloudflareApplyFailureReport(reportRoot, "cloudflare-deploy", digest, plan, result, started, time.Now().UTC(), stdout); reportErr != nil {
				fmt.Fprintln(stderr, "agentops: Cloudflare audit persistence failed")
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
		report, err := cloudflareOperationReport(operationID, digest, plan, result, health, started, finished)
		if err != nil {
			fmt.Fprintln(stderr, "agentops: production state unknown; audit report construction failed")
			return 1
		}
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

func writeCloudflareApplyFailureReport(reportRoot, operationKind, digest string, plan opscloudflare.CloudflareDeployPlan, result opscloudflare.ApplyResult, started, finished time.Time, stdout io.Writer) error {
	operationID, err := newOpsOperationID(operationKind)
	if err != nil {
		return err
	}
	stageName := opscloudflare.StageIdentityVerification
	stageCode := "CF_IDENTITY_UNAVAILABLE"
	outcome := opsreport.CloudflareUnknownState
	if !result.ProductionWriteSucceeded {
		stageName = opscloudflare.StageProductionAction
		stageCode = "CF_PRODUCTION_ACTION_REJECTED"
		outcome = opsreport.CloudflareKnownFailure
	}
	stage, err := opscloudflare.NewStageResult(stageName, opscloudflare.StageCode(stageCode), finished.Sub(started), opscloudflare.TimeoutNone, opscloudflare.NewCorrelationID())
	if err != nil {
		return err
	}
	report, err := opsreport.NewCloudflareReport(opsreport.CloudflareReportInput{
		OperationID: operationID, Operation: "deploy", Actor: "environment", Service: plan.Service, Environment: plan.Environment, Worker: plan.Worker,
		PlanDigest: digest, PayloadDigest: plan.DeploymentInputSHA256, RequestedVersion: plan.RequestedVersion,
		DeploymentID: opsreport.ReportSafeCloudflareFailureIdentifier(result.DeploymentID), VersionIDs: reportSafeCloudflareFailureIdentifiers(result.VersionIDs), Stages: []opscloudflare.StageResult{stage},
		ObservedMigrations:   append([]opscloudflarepayload.MigrationObservationEvidence(nil), result.ObservedMigrations...),
		PendingMigrationTags: append([]string(nil), result.PendingMigrationTags...), MigrationOmitted: result.MigrationOmitted,
		Outcome: outcome, Health: opsreport.HealthEvidence{Type: "http", State: "not-checked"}, ErrorCode: stageCode,
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

func reportSafeCloudflareFailureIdentifiers(identifiers []string) []string {
	result := make([]string, len(identifiers))
	for index, identifier := range identifiers {
		result[index] = opsreport.ReportSafeCloudflareFailureIdentifier(identifier)
	}
	return result
}

func cloudflareOperationReport(operationID, digest string, plan opscloudflare.CloudflareDeployPlan, result opscloudflare.ApplyResult, health opshealth.Result, started, finished time.Time) (opsreport.Report, error) {
	state := "healthy"
	if !health.Healthy {
		state = "failed"
	}
	outcome := opsreport.CloudflareSucceeded
	errorCode := ""
	if !health.Healthy {
		outcome = opsreport.CloudflareHealthFailure
		errorCode = "CF_HEALTH_FAILED"
	}
	stage, err := opscloudflare.NewSuccessfulStageResult(opscloudflare.StageProductionAction, "CF_PRODUCTION_ACTION_OK", finished.Sub(started), opscloudflare.NewCorrelationID())
	if err != nil {
		return opsreport.Report{}, err
	}
	return opsreport.NewCloudflareReport(opsreport.CloudflareReportInput{
		OperationID: operationID, Operation: "deploy", Actor: plan.AccountID, Service: plan.Service, Environment: plan.Environment, Worker: plan.Worker,
		PlanDigest: digest, PayloadDigest: plan.DeploymentInputSHA256, RequestedVersion: plan.RequestedVersion,
		DeploymentID: result.DeploymentID, VersionIDs: append([]string(nil), result.VersionIDs...),
		ObservedMigrations:   append([]opscloudflarepayload.MigrationObservationEvidence(nil), result.ObservedMigrations...),
		PendingMigrationTags: append([]string(nil), result.PendingMigrationTags...), MigrationOmitted: result.MigrationOmitted,
		Stages: []opscloudflare.StageResult{stage}, Outcome: outcome,
		Health:    opsreport.HealthEvidence{Type: health.Type, State: state, Healthy: health.Healthy, StatusCode: health.StatusCode, Detail: health.Detail},
		ErrorCode: errorCode, StartedAt: started, FinishedAt: finished,
	})
}
