package opscli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsartifact"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsdeploy"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsreport"
	"github.com/wenqiangde/agentops/internal/opsrunner"
	"github.com/wenqiangde/agentops/internal/paths"
)

var opsHealthProbe = opshealth.Probe
var opsRunnerNew = opsrunner.New
var opsDeployExecutor = func() opsexec.Executor { return opsexec.NewSSHExecutor() }

const agentOpsUsage = "Usage: agentops [validate <all|service>|list [--language <language>] [--host <host>]|inspect <service> [--environment <local|production>]|build <service>|health <service|all> --environment <local|production>|deploy <service> --environment production --version <version>|rollback <service> --environment production --version <version>|backup <service> --environment production]"

type opsUsageWriter struct {
	io.Writer
	usage string
}

func Main(args []string, stdout io.Writer, stderr io.Writer) int {
	return opsMainWithPaths(paths.Resolve(), args, stdout, stderr)
}

func RunWithPaths(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	return opsMainWithPaths(p, args, stdout, stderr)
}

func opsMainWithPaths(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	return executeAgentOpsCommand(p, args, stdout, stderr)
}

func opsCommand(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return opsUsageError(stderr, "missing command")
	}
	switch args[0] {
	case "validate":
		return opsValidate(p, args[1:], stdout, stderr)
	case "list":
		return opsList(p, args[1:], stdout, stderr)
	case "inspect":
		return opsInspect(p, args[1:], stdout, stderr)
	case "build":
		return opsBuild(p, args[1:], stdout, stderr)
	case "health":
		return opsHealth(p, args[1:], stdout, stderr)
	case "deploy":
		return opsDeploy(p, args[1:], stdout, stderr)
	case "rollback":
		return opsRollback(p, args[1:], stdout, stderr)
	case "backup":
		return opsBackup(p, args[1:], stdout, stderr)
	default:
		return opsUsageError(stderr, "unknown command: "+args[0])
	}
}

func opsDeploy(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	serviceID, requestedVersion, confirm, previewDigest, ok := parseOpsDeployArgs(args, stderr)
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
	projectRoot, err := resolveOpsSourceRoot(p, service)
	if err != nil {
		fmt.Fprintf(stderr, "agentops: %v\n", err)
		return 1
	}
	platform := host.Platform
	if platform == "ubuntu" {
		platform = "linux"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	artifact, err := opsartifact.ValidateContext(ctx, projectRoot, service, opsartifact.Target{Platform: platform, Architecture: host.Architecture})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: existing artifact or manifest validation failed")
		return 1
	}
	if requestedVersion != artifact.Manifest.Version {
		fmt.Fprintln(stderr, "agentops: requested version does not match verified manifest version")
		return 1
	}
	executor := opsDeployExecutor()
	plan, err := opsdeploy.Create(ctx, executor, service, host, inv.Policies, artifact, timeout)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: deployment preview collection failed")
		return 1
	}
	encoded, err := opsdeploy.MarshalIndented(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: deployment preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	if plan.Blocked {
		fmt.Fprintf(stderr, "agentops: deployment preview blocked: %s\n", plan.BlockReason)
		return 1
	}
	digest, err := opsdeploy.Digest(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: deployment preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if confirm {
		if err := opsdeploy.Confirm(plan, previewDigest); err != nil {
			if strings.Contains(err.Error(), "stale") {
				fmt.Fprintln(stderr, "agentops: preview digest is stale")
			} else {
				fmt.Fprintln(stderr, "agentops: deployment preview cannot be confirmed")
			}
			return 1
		}
		operationID, err := newOpsOperationID("deploy")
		if err != nil {
			fmt.Fprintln(stderr, "agentops: cannot create deployment operation identity")
			return 1
		}
		started := time.Now().UTC()
		reportPath := ""
		sink := func(_ context.Context, result opsdeploy.ApplyResult) error {
			finished := time.Now().UTC()
			report := deployOperationReport(operationID, digest, plan, result, started, finished)
			written, writeErr := opsreport.Write(p.OpsReportRoot, report, []string{plan.Migration.Command})
			if writeErr == nil {
				reportPath = written
			}
			return writeErr
		}
		result, applyErr := opsdeploy.Apply(ctx, executor, opsdeploy.ConfirmedPlan{Plan: plan, Digest: digest}, artifact.ArchivePath, timeout, sink)
		if applyErr != nil && reportPath == "" {
			_ = sink(context.Background(), result)
		}
		if applyErr != nil {
			fmt.Fprintln(stdout, "deployment: failed")
			if reportPath != "" {
				fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
			}
			fmt.Fprintln(stderr, "agentops: deployment apply failed; inspect the operation report")
			return 1
		}
		fmt.Fprintln(stdout, "deployment: succeeded")
		fmt.Fprintf(stdout, "report-id: %s\nreport: %s\n", operationID, reportPath)
	}
	return 0
}

func newOpsOperationID(kind string) (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s-%s", kind, time.Now().UTC().Format("20060102T150405.000000000Z"), hex.EncodeToString(random[:])), nil
}

func deployOperationReport(operationID, digest string, plan opsdeploy.Plan, result opsdeploy.ApplyResult, started, finished time.Time) opsreport.Report {
	steps := make([]opsreport.StepResult, 0, len(result.Steps))
	for index, step := range result.Steps {
		stepStarted := step.StartedAt
		stepFinished := step.FinishedAt
		if stepStarted.IsZero() {
			stepStarted = started
		}
		if stepFinished.IsZero() {
			stepFinished = finished
		}
		stepError := ""
		if step.State != "succeeded" {
			stepError = "step failed"
		}
		steps = append(steps, opsreport.StepResult{Order: index + 1, Kind: step.Kind, Status: step.State, StartedAt: stepStarted, FinishedAt: stepFinished, Error: stepError})
	}
	recovery := "not-required"
	manualWork := "none"
	if result.Recovered {
		recovery = "restored-previous-release"
	} else if result.Activated && !result.Success {
		recovery = "automatic-recovery-not-completed"
		manualWork = "inspect deployment and recovery state"
	}
	errorSummary := ""
	if !result.Success {
		errorSummary = "deployment failed"
	}
	healthState := "failed"
	if result.Success {
		healthState = "healthy"
	}
	return opsreport.Report{
		OperationID: operationID, Actor: plan.Preflight.RemoteUser, Service: plan.Service, Environment: plan.Environment, Host: plan.Host,
		PlanDigest: digest, PreviousVersion: plan.CurrentVersion, RequestedVersion: plan.Version, ArtifactDigest: plan.ArtifactSHA256,
		Steps: steps, Health: opsreport.HealthEvidence{Type: plan.Health.Type, State: healthState, Healthy: result.Success}, Recovery: recovery, Terminal: result.Terminal,
		StartedAt: started, FinishedAt: finished, Error: errorSummary, ManualWork: manualWork,
	}
}

func parseOpsDeployArgs(args []string, stderr io.Writer) (string, string, bool, string, bool) {
	if len(args) < 3 || strings.HasPrefix(args[0], "-") || args[1] != "--environment" || args[2] != opsconfig.EnvironmentProduction {
		opsUsageError(stderr, "deploy requires one service, --environment production, and --version <version>")
		return "", "", false, "", false
	}
	confirm := false
	digest := ""
	version := ""
	for index := 3; index < len(args); index++ {
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
		case "--version":
			if version != "" || index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				opsUsageError(stderr, "--version requires one value")
				return "", "", false, "", false
			}
			index++
			version = args[index]
		default:
			opsUsageError(stderr, "unknown deploy option: "+args[index])
			return "", "", false, "", false
		}
	}
	if version == "" {
		opsUsageError(stderr, "deploy requires --version <version>")
		return "", "", false, "", false
	}
	if confirm != (digest != "") || (digest != "" && !opsdeploy.IsDigest(digest)) {
		opsUsageError(stderr, "--confirm and --preview-digest <64lowerhex> must be used together")
		return "", "", false, "", false
	}
	return args[0], version, confirm, digest, true
}

func opsBuild(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return opsUsageError(stderr, "build requires one service")
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	if hasGlobalOpsIssue(issues) {
		printOpsIssues(stderr, issues)
		return 1
	}
	service, ok := inv.Services[args[0]]
	if !ok {
		selected := issuesForService(issues, args[0])
		if len(selected) != 0 {
			printOpsIssues(stderr, selected)
		} else {
			fmt.Fprintf(stderr, "agentops: unknown service: %s\n", args[0])
		}
		return 1
	}
	if !service.BuildConfigured() {
		fmt.Fprintln(stderr, "agentops: service has no managed build/deploy configuration")
		return 1
	}
	production := service.Environments[opsconfig.EnvironmentProduction]
	host, ok := inv.Hosts[production.Host]
	if !ok || production.Kind != opsconfig.EnvironmentKindSSH {
		fmt.Fprintln(stderr, "agentops: service has no unambiguous production target")
		return 1
	}
	targetPlatform := host.Platform
	if targetPlatform == "ubuntu" {
		targetPlatform = "linux"
	}
	if targetPlatform == "" || host.Architecture == "" {
		fmt.Fprintln(stderr, "agentops: production target is incomplete")
		return 1
	}
	timeout, err := time.ParseDuration(inv.Policies.Execution.DefaultTimeout)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "agentops: invalid default operation timeout")
		return 1
	}
	projectRoot, err := resolveOpsSourceRoot(p, service)
	if err != nil {
		fmt.Fprintf(stderr, "agentops: %v\n", err)
		return 1
	}
	verified, err := opsartifact.Build(context.Background(), opsexec.NewLocalExecutor(), projectRoot, service, opsartifact.Target{Platform: targetPlatform, Architecture: host.Architecture}, timeout)
	if err != nil {
		fmt.Fprintf(stderr, "agentops: %s\n", safeOpsBuildError(err))
		return 1
	}
	fmt.Fprintf(stdout, "service: %s\nversion: %s\ncommit: %s\ntarget: %s/%s\narchive: %s\nsize: %d\nsha256: %s\n", service.ID, verified.Manifest.Version, verified.Manifest.Commit, verified.Manifest.Platform, verified.Manifest.Architecture, verified.ArchivePath, verified.Size, verified.SHA256)
	return 0
}

func resolveOpsSourceRoot(_ paths.Paths, service opsconfig.Service) (string, error) {
	return service.Source.Path, nil
}

func safeOpsBuildError(err error) string {
	message := err.Error()
	for _, safe := range []string{"build command failed", "build command timed out", "build operation timed out", "build outputs are stale", "manifest service does not match", "manifest target does not match production host", "artifact SHA-256 does not match manifest"} {
		if strings.Contains(message, safe) {
			return safe
		}
	}
	return "artifact build or validation failed"
}

func opsHealth(p paths.Paths, args []string, stdout, stderr io.Writer) int {
	if len(args) != 3 || strings.HasPrefix(args[0], "-") || args[1] != "--environment" {
		return opsUsageError(stderr, "health requires one service or all and --environment")
	}
	environmentName := args[2]
	if environmentName != opsconfig.EnvironmentLocal && environmentName != opsconfig.EnvironmentProduction {
		return opsUsageError(stderr, "--environment must be local or production")
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	names := sortedServiceNames(inv.Services)
	exit := 0
	if args[0] == "all" {
		if len(issues) != 0 {
			printOpsIssues(stderr, issues)
			exit = 1
		}
		if hasGlobalOpsIssue(issues) {
			return 1
		}
	}
	if args[0] != "all" {
		if hasGlobalOpsIssue(issues) {
			printOpsIssues(stderr, issues)
			return 1
		}
		if _, ok := inv.Services[args[0]]; !ok {
			selected := issuesForService(issues, args[0])
			if len(selected) != 0 {
				printOpsIssues(stderr, selected)
			} else {
				fmt.Fprintf(stderr, "agentops: unknown service: %s\n", args[0])
			}
			return 1
		}
		names = []string{args[0]}
	}
	timeout, err := time.ParseDuration(inv.Policies.Execution.HealthTimeout)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(stderr, "agentops: invalid health timeout")
		return 1
	}
	for _, name := range names {
		service := inv.Services[name]
		environment := service.Environments[environmentName]
		health := environment.Health
		var executor opsexec.Executor
		if environment.Kind == opsconfig.EnvironmentKindSSH {
			host := inv.Hosts[environment.Host]
			environment.Host = host.SSHAlias
			executor = opsexec.NewSSHExecutor()
		} else {
			executor = opsexec.NewLocalExecutor()
		}
		result := opsHealthProbe(context.Background(), executor, environment, health, timeout)
		state := "healthy"
		if !result.Healthy {
			state = "unhealthy"
			exit = 1
		}
		detail := result.Detail
		if detail == "" && result.Err != nil {
			detail = result.Type + " probe failed"
		}
		fmt.Fprintf(stdout, "%s\t%s", service.ID, state)
		if detail != "" {
			fmt.Fprintf(stdout, "\t%s", safeOpsText(detail))
		}
		fmt.Fprintln(stdout)
	}
	return exit
}

func hasGlobalOpsIssue(issues []opsconfig.Issue) bool {
	for _, issue := range issues {
		if issue.File == "hosts.yaml" || issue.File == "policies.yaml" || issue.File == "services" {
			return true
		}
	}
	return false
}

func opsValidate(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return opsUsageError(stderr, "validate requires all or one service")
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	target := args[0]
	if target != "all" {
		if service, ok := inv.Services[target]; ok {
			fmt.Fprintf(stdout, "%s: valid\n", service.ID)
			return 0
		}
		selected := issuesForService(issues, target)
		if len(selected) == 0 {
			fmt.Fprintf(stderr, "agentops: unknown service: %s\n", target)
			return 1
		}
		printOpsIssues(stderr, selected)
		return 1
	}
	for _, name := range sortedServiceNames(inv.Services) {
		fmt.Fprintf(stdout, "%s: valid\n", name)
	}
	printOpsIssues(stderr, issues)
	if len(issues) != 0 {
		return 1
	}
	return 0
}

func opsList(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	language, host, ok := parseOpsListFlags(args, stderr)
	if !ok {
		return 1
	}
	inv, issues := opsconfig.Load(p.OperationsRoot)
	for _, name := range sortedServiceNames(inv.Services) {
		service := inv.Services[name]
		production := service.Environments[opsconfig.EnvironmentProduction]
		if language != "" && service.Language != language {
			continue
		}
		if host != "" && production.Host != host {
			continue
		}
		local := service.Environments[opsconfig.EnvironmentLocal]
		fmt.Fprintf(stdout, "%s\t%s\tlocal=%s\tproduction=%s\thost=%s\n", service.ID, service.Language, local.Runner, production.Runner, production.Host)
	}
	printOpsIssues(stderr, issues)
	if len(issues) != 0 {
		return 1
	}
	return 0
}

func opsInspect(p paths.Paths, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return opsUsageError(stderr, "inspect requires one service")
	}
	serviceID := args[0]
	environment, ok := parseOpsInspectFlags(args[1:], stderr)
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
	defaultTimeout, timeoutErr := time.ParseDuration(inv.Policies.Execution.DefaultTimeout)
	if timeoutErr != nil || defaultTimeout <= 0 {
		fmt.Fprintln(stderr, "agentops: invalid default operation timeout")
		return 1
	}
	fmt.Fprintf(stdout, "service: %s\nlanguage: %s\nsource: %s\nrepository: %s\n", service.ID, service.Language, service.Source.Path, safeOpsLocation(service.Source.Repository))
	environments := []string{opsconfig.EnvironmentLocal, opsconfig.EnvironmentProduction}
	if environment != "" {
		environments = []string{environment}
	}
	for _, name := range environments {
		item := service.Environments[name]
		fmt.Fprintf(stdout, "environment: %s\nkind: %s\nrunner: %s\n", name, item.Kind, item.Runner)
		if item.Host != "" {
			fmt.Fprintf(stdout, "host: %s\n", item.Host)
		}
		if item.Root != "" {
			fmt.Fprintf(stdout, "root: %s\n", item.Root)
		}
		runnerEnvironment := item
		var executor opsexec.Executor
		if item.Kind == opsconfig.EnvironmentKindSSH {
			host := inv.Hosts[item.Host]
			runnerEnvironment.Host = host.SSHAlias
			executor = opsexec.NewSSHExecutor()
		} else {
			executor = opsexec.NewLocalExecutor()
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		check := opsRunnerNew(item.Runner, executor).Inspect(ctx, service, runnerEnvironment)
		cancel()
		fmt.Fprintf(stdout, "state: %s\n", check.State)
		if check.Err != nil {
			return 1
		}
	}
	return 0
}

func safeOpsText(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
}

func safeOpsLocation(value string) string {
	for _, character := range value {
		if character <= 0x1f || character == 0x7f {
			return "[invalid URL]"
		}
	}
	if isSCPLikeLocation(value) {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "[invalid URL]"
	}
	if parsed.Opaque != "" {
		return "[invalid URL]"
	}
	if parsed.Scheme == "" && parsed.Host == "" {
		if strings.ContainsAny(value, "@?#") {
			return "[invalid URL]"
		}
		return value
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

func isSCPLikeLocation(value string) bool {
	at := strings.IndexByte(value, '@')
	if at <= 0 || strings.IndexByte(value[at+1:], '@') >= 0 {
		return false
	}
	colonOffset := strings.IndexByte(value[at+1:], ':')
	if colonOffset <= 0 {
		return false
	}
	colon := at + 1 + colonOffset
	user, host, path := value[:at], value[at+1:colon], value[colon+1:]
	return path != "" && !strings.ContainsAny(user, " \t\r\n/:") && !strings.ContainsAny(host, " \t\r\n/:")
}

func parseOpsListFlags(args []string, stderr io.Writer) (string, string, bool) {
	var language, host string
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--language", "--host":
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				opsUsageError(stderr, args[index]+" requires a value")
				return "", "", false
			}
			flag := args[index]
			index++
			if flag == "--language" {
				language = args[index]
			} else {
				host = args[index]
			}
		default:
			opsUsageError(stderr, "unknown list option: "+args[index])
			return "", "", false
		}
	}
	return language, host, true
}

func parseOpsInspectFlags(args []string, stderr io.Writer) (string, bool) {
	if len(args) == 0 {
		return "", true
	}
	if len(args) != 2 || args[0] != "--environment" {
		opsUsageError(stderr, "unknown inspect option")
		return "", false
	}
	if args[1] != opsconfig.EnvironmentLocal && args[1] != opsconfig.EnvironmentProduction {
		opsUsageError(stderr, "--environment must be local or production")
		return "", false
	}
	return args[1], true
}

func sortedServiceNames(services map[string]opsconfig.Service) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func issuesForService(issues []opsconfig.Issue, serviceID string) []opsconfig.Issue {
	file := "services/" + serviceID + ".yaml"
	selected := make([]opsconfig.Issue, 0)
	for _, issue := range issues {
		if issue.File == file {
			selected = append(selected, issue)
		}
	}
	return selected
}

func printOpsIssues(stderr io.Writer, issues []opsconfig.Issue) {
	for _, issue := range issues {
		location := issue.File
		if issue.Field != "" {
			location += ":" + issue.Field
		}
		fmt.Fprintf(stderr, "%s: %s\n", location, issue.Message)
	}
}

func opsUsageError(stderr io.Writer, message string) int {
	usage := agentOpsUsage
	fmt.Fprintf(stderr, "agentops: %s\n%s\n", message, usage)
	return 1
}
