package opscli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsdeploy"
	"github.com/wenqiangde/agentops/internal/opsexec"
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
