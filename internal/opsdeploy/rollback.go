package opsdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsrunner"
)

type RollbackPlan struct {
	Operation            string            `json:"operation"`
	Service              string            `json:"service"`
	Environment          string            `json:"environment"`
	Host                 string            `json:"host"`
	DeploymentRoot       string            `json:"deployment_root"`
	HostPlatform         string            `json:"host_platform"`
	HostArchitecture     string            `json:"host_architecture"`
	HostCapabilities     []string          `json:"host_capabilities"`
	CurrentVersion       string            `json:"current_version"`
	TargetVersion        string            `json:"target_version"`
	TargetArtifactSHA256 string            `json:"target_artifact_sha256"`
	RemoteUser           string            `json:"remote_user"`
	ConfigFingerprints   map[string]string `json:"config_fingerprints"`
	Runner               RunnerEvidence    `json:"runner"`
	Health               opsconfig.Health  `json:"health"`
	Policy               Policy            `json:"policy"`
	StopConditions       []string          `json:"stop_conditions"`
	Steps                []Step            `json:"steps"`
	Recovery             Recovery          `json:"recovery"`
	Blocked              bool              `json:"blocked"`
	BlockReason          string            `json:"block_reason,omitempty"`
}

type ConfirmedRollbackPlan struct {
	Plan   RollbackPlan
	Digest string
}

type RollbackStepResult struct {
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	ExitCode   int       `json:"exit_code"`
	TimedOut   bool      `json:"timed_out"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type RollbackResult struct {
	Success   bool                 `json:"success"`
	Activated bool                 `json:"activated"`
	Recovered bool                 `json:"recovered"`
	Steps     []RollbackStepResult `json:"steps"`
}

type RollbackReportSink func(context.Context, RollbackResult) error

func CreateRollback(ctx context.Context, executor opsexec.Executor, service opsconfig.Service, host opsconfig.Host, policies opsconfig.Policies, target string, timeout time.Duration) (RollbackPlan, error) {
	if ctx == nil || executor == nil || timeout <= 0 || !safeIdentity.MatchString(target) {
		return RollbackPlan{}, errors.New("rollback planning inputs are incomplete")
	}
	env, ok := service.Environments[opsconfig.EnvironmentProduction]
	if !ok || env.Kind != opsconfig.EnvironmentKindSSH || env.Root == "" || host.SSHAlias == "" {
		return RollbackPlan{}, errors.New("production rollback target is incomplete")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	current, err := collectCurrent(ctx, executor, host.SSHAlias, env.Root, timeout)
	if err != nil || current == "" {
		return RollbackPlan{}, errors.New("current release cannot be identified")
	}
	if current == target {
		return RollbackPlan{}, errors.New("rollback target must differ from current release")
	}
	marker := path.Join(env.Root, "releases", target, ".agentsetup-artifact.tar.gz")
	exists := runRead(ctx, executor, opsexec.Request{HostAlias: host.SSHAlias, Program: "stat", Args: []string{"-c", "%F", "--", marker}, Timeout: timeout})
	if exists.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return RollbackPlan{}, errors.New("rollback target inspection timed out")
	}
	if exists.Err != nil || exists.ExitCode != 0 || strings.TrimSpace(exists.Stdout) != "regular file" {
		return RollbackPlan{}, errors.New("rollback target artifact marker is unavailable")
	}
	checked := runRead(ctx, executor, opsexec.Request{HostAlias: host.SSHAlias, Program: "sha256sum", Args: []string{"--", marker}, Timeout: timeout})
	digest, digestPath, validDigest := parseSHA256Sum(checked.Stdout)
	if checked.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return RollbackPlan{}, errors.New("rollback target verification timed out")
	}
	if checked.Err != nil || checked.ExitCode != 0 || !validDigest || digestPath != marker {
		return RollbackPlan{}, errors.New("rollback target artifact marker is invalid")
	}
	if err := verifySealedRelease(ctx, executor, host.SSHAlias, path.Join(env.Root, "releases", target), timeout); err != nil {
		return RollbackPlan{}, err
	}
	remoteUser, err := scalarRead(ctx, executor, host.SSHAlias, "id", []string{"-un"}, timeout, "SSH session identity")
	if err != nil || !safeIdentity.MatchString(remoteUser) {
		return RollbackPlan{}, errors.New("SSH session identity metadata is invalid")
	}
	platform, err := scalarRead(ctx, executor, host.SSHAlias, "uname", []string{"-s", "-m"}, timeout, "remote platform")
	if err != nil {
		return RollbackPlan{}, err
	}
	parts := strings.Fields(platform)
	if len(parts) != 2 {
		return RollbackPlan{}, errors.New("remote platform metadata is invalid")
	}
	remoteOS, remoteArch := normalizeTarget(parts[0], parts[1])
	declaredOS, declaredArch := normalizeTarget(host.Platform, host.Architecture)
	if remoteOS != declaredOS || remoteArch != declaredArch {
		return RollbackPlan{}, errors.New("remote platform does not match declared host")
	}
	for _, command := range []string{"find", "ln", "mv", "sha256sum", "stat", "systemctl"} {
		available := runRead(ctx, executor, opsexec.Request{HostAlias: host.SSHAlias, Program: "which", Args: []string{command}, Timeout: timeout})
		if available.Err != nil || available.ExitCode != 0 || available.TimedOut {
			return RollbackPlan{}, errors.New("required remote command is unavailable")
		}
	}
	fingerprints, err := collectConfigFingerprints(ctx, executor, host.SSHAlias, env.Root, env.Config.Files, timeout)
	if err != nil {
		return RollbackPlan{}, err
	}
	runnerEnv := env
	runnerEnv.Host = host.SSHAlias
	check := opsrunner.New(env.Runner, executor).Inspect(ctx, service, runnerEnv)
	identity := runnerIdentity(env)
	if check.Err != nil || identity == "" || (check.State != opsrunner.StateRunning && check.State != opsrunner.StateStopped) {
		return RollbackPlan{}, errors.New("runner inspection failed")
	}
	if _, err := collectHealthEvidence(ctx, executor, runnerEnv, env.Health, timeout); err != nil {
		return RollbackPlan{}, err
	}
	plan := RollbackPlan{
		Operation: "rollback", Service: service.ID, Environment: opsconfig.EnvironmentProduction, Host: host.SSHAlias, DeploymentRoot: env.Root,
		HostPlatform: host.Platform, HostArchitecture: host.Architecture, HostCapabilities: append([]string(nil), host.Capabilities...),
		CurrentVersion: current, TargetVersion: target, TargetArtifactSHA256: digest, RemoteUser: remoteUser,
		ConfigFingerprints: fingerprints, Runner: RunnerEvidence{Kind: env.Runner, Identity: identity, ConfigOwner: env.ConfigOwner, ConfigPath: env.ConfigPath, State: check.State, Identified: true}, Health: env.Health,
		Policy:         Policy{DefaultTimeout: policies.Execution.DefaultTimeout, HealthTimeout: policies.Execution.HealthTimeout, ReleaseRetain: policies.Releases.Retain, RequirePreviewDigest: policies.Production.RequirePreviewDigest, RequireCleanArtifactManifest: policies.Production.RequireCleanArtifactManifest},
		StopConditions: []string{"preview input changed", "target artifact marker changed", "runner restart failed", "process health failed", "application health failed"},
		Recovery:       Recovery{Ready: true, Reason: "original current release remains cached"},
	}
	plan.Steps = rollbackSteps(plan)
	plan.Recovery.Steps = rollbackRecoverySteps(plan)
	if service.Data.MySQL != nil && strings.TrimSpace(service.Data.MySQL.MigrationCommand) != "" {
		plan.Blocked = true
		plan.BlockReason = "migration compatibility evidence is incomplete; binary rollback is not database recovery"
		plan.Recovery = Recovery{Ready: false, Reason: "database compatibility and recovery require separate evidence"}
	}
	if _, err := opsrunner.DeploymentContract(service, runnerEnv); err != nil {
		plan.Blocked = true
		plan.BlockReason = "automatic rollback does not support the declared runner contract"
		plan.Recovery = Recovery{Ready: false, Reason: "automatic runner recovery is unavailable"}
	}
	return plan, nil
}

func rollbackSteps(plan RollbackPlan) []Step {
	root := plan.DeploymentRoot
	steps := []Step{
		{Kind: "inspect-target-marker", Scope: "remote", Access: AccessRead, Condition: "after-confirm-before-write", Program: "stat", Args: []string{"-c", "%F", "--", path.Join(root, "releases", plan.TargetVersion, ".agentsetup-artifact.tar.gz")}},
		{Kind: "verify-target-artifact", Scope: "remote", Access: AccessRead, Condition: "after-confirm-before-write", Program: "sha256sum", Args: []string{"--", path.Join(root, "releases", plan.TargetVersion, ".agentsetup-artifact.tar.gz")}},
		{Kind: "verify-target-sealed", Scope: "remote", Access: AccessRead, Condition: "after-confirm-before-write", Program: "find", Args: []string{path.Join(root, "releases", plan.TargetVersion), "-perm", "/022", "-print", "-quit"}},
		{Kind: "revalidate-preflight", Scope: "remote", Access: AccessRead, Condition: "immediately-before-activation", Program: "preflight", Args: []string{path.Join(root, "current")}},
		{Kind: "create-previous-temporary-link", Scope: "remote", Access: AccessWrite, Condition: "after-confirm", Program: "ln", Args: []string{"-sfn", path.Join("releases", plan.CurrentVersion), path.Join(root, ".previous.rollback.tmp")}},
		{Kind: "create-current-temporary-link", Scope: "remote", Access: AccessWrite, Condition: "after-temporary-previous", Program: "ln", Args: []string{"-sfn", path.Join("releases", plan.TargetVersion), path.Join(root, ".current.rollback.tmp")}},
		{Kind: "rename-previous-link", Scope: "remote", Access: AccessWrite, Condition: "after-temporary-links", Program: "mv", Args: []string{"-Tf", path.Join(root, ".previous.rollback.tmp"), path.Join(root, "previous")}},
		{Kind: "rename-current-link", Scope: "remote", Access: AccessWrite, Condition: "after-temporary-links", Program: "mv", Args: []string{"-Tf", path.Join(root, ".current.rollback.tmp"), path.Join(root, "current")}},
	}
	steps = append(steps, rollbackRunnerSteps(plan, false)...)
	steps = append(steps,
		Step{Kind: "application-health", Scope: "remote", Access: AccessRead, Condition: "after-process-health", Program: "health-probe"},
		Step{Kind: "write-local-report", Scope: "local", Access: AccessWrite, Condition: "after-terminal-outcome", Program: "opsreport"},
	)
	for index := range steps {
		steps[index].Order = index + 1
	}
	return steps
}

func rollbackRecoverySteps(plan RollbackPlan) []Step {
	root := plan.DeploymentRoot
	steps := []Step{
		{Kind: "create-current-recovery-link", Scope: "remote", Access: AccessWrite, Condition: "on-failure-after-activation", Program: "ln", Args: []string{"-sfn", path.Join("releases", plan.CurrentVersion), path.Join(root, ".current.rollback.recovery.tmp")}},
		{Kind: "rename-current-recovery-link", Scope: "remote", Access: AccessWrite, Condition: "after-recovery-link", Program: "mv", Args: []string{"-Tf", path.Join(root, ".current.rollback.recovery.tmp"), path.Join(root, "current")}},
	}
	steps = append(steps, rollbackRunnerSteps(plan, true)...)
	steps = append(steps,
		Step{Kind: "verify-original-application", Scope: "remote", Access: AccessRead, Condition: "after-recovery-process", Program: "health-probe"},
		Step{Kind: "write-recovery-report", Scope: "local", Access: AccessWrite, Condition: "after-recovery-outcome", Program: "opsreport"},
	)
	for index := range steps {
		steps[index].Order = index + 1
	}
	return steps
}

func rollbackRunnerSteps(plan RollbackPlan, recovery bool) []Step {
	contract, err := opsrunner.DeploymentContract(opsconfig.Service{ID: plan.Service}, rollbackRunnerEnvironment(plan))
	if err != nil {
		return nil
	}
	commands := append(append([]opsrunner.DeploymentCommand(nil), contract.Activation...), contract.ProcessHealth...)
	steps := make([]Step, 0, len(commands))
	for _, command := range commands {
		access := AccessRead
		condition := "after-activation"
		if command.Kind == "activate-runner" {
			access = AccessWrite
		}
		steps = append(steps, Step{Kind: rollbackRunnerResultKind(plan.Runner.Kind, command.Kind, recovery), Scope: "remote", Access: access, Condition: condition, Program: command.Program, Args: append([]string(nil), command.Args...)})
	}
	return steps
}

func rollbackRunnerResultKind(runner, kind string, recovery bool) string {
	if runner == opsconfig.RunnerSystemd {
		if recovery {
			if kind == "activate-runner" {
				return "restart-original-runner"
			}
			return "verify-original-process"
		}
		if kind == "activate-runner" {
			return "restart-runner"
		}
		return "process-health"
	}
	if recovery {
		switch kind {
		case "verify-runner-metadata":
			return "verify-original-runner-metadata"
		case "verify-runner-config-owner":
			return "verify-original-runner-config-owner"
		case "activate-runner":
			return "activate-original-runner"
		case "process-health-metadata":
			return "verify-original-process-metadata"
		case "process-health-config-owner":
			return "verify-original-process-config-owner"
		}
	}
	return kind
}

func RollbackCanonicalJSON(plan RollbackPlan) ([]byte, error) {
	normalized := plan
	normalized.HostCapabilities = sortedUniqueStrings(plan.HostCapabilities)
	normalized.Health.SuccessStatuses = sortedUniqueInts(plan.Health.SuccessStatuses)
	type entry struct {
		Path  string `json:"path"`
		Value string `json:"value"`
	}
	entries := make([]entry, 0, len(plan.ConfigFingerprints))
	for name, value := range plan.ConfigFingerprints {
		entries = append(entries, entry{Path: name, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	normalized.ConfigFingerprints = nil
	return json.Marshal(struct {
		Plan         RollbackPlan `json:"plan"`
		Fingerprints []entry      `json:"config_fingerprints"`
	}{Plan: normalized, Fingerprints: entries})
}

func RollbackDigest(plan RollbackPlan) (string, error) {
	data, err := RollbackCanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func ConfirmRollback(plan RollbackPlan, digest string) error {
	if plan.Blocked {
		return errors.New(plan.BlockReason)
	}
	if !IsDigest(digest) {
		return errors.New("preview digest must be 64 lowercase hexadecimal characters")
	}
	current, err := RollbackDigest(plan)
	if err != nil {
		return err
	}
	if current != digest {
		return errors.New("preview digest is stale")
	}
	return nil
}

func MarshalRollbackIndented(plan RollbackPlan) ([]byte, error) {
	type command struct {
		Program       string `json:"program"`
		ArgCount      int    `json:"arg_count"`
		CommandDigest string `json:"command_digest"`
	}
	type previewStep struct {
		Order     int     `json:"order"`
		Kind      string  `json:"kind"`
		Scope     string  `json:"scope"`
		Access    string  `json:"access"`
		Condition string  `json:"condition"`
		Command   command `json:"command"`
	}
	type safeHealth struct {
		Type          string `json:"type"`
		URL           string `json:"url,omitempty"`
		Program       string `json:"program,omitempty"`
		ArgCount      int    `json:"arg_count"`
		CommandDigest string `json:"command_digest,omitempty"`
	}
	type targets struct {
		TargetRelease string `json:"target_release"`
		CurrentLink   string `json:"current_link"`
		PreviousLink  string `json:"previous_link"`
		Unit          string `json:"unit"`
	}
	convert := func(steps []Step) []previewStep {
		result := make([]previewStep, 0, len(steps))
		for _, step := range steps {
			result = append(result, previewStep{Order: step.Order, Kind: step.Kind, Scope: step.Scope, Access: step.Access, Condition: step.Condition, Command: command{Program: safeProgram(step.Program), ArgCount: len(step.Args), CommandDigest: commandDigest(step.Program, step.Args)}})
		}
		return result
	}
	preview := struct {
		Operation            string            `json:"operation"`
		Service              string            `json:"service"`
		Environment          string            `json:"environment"`
		Host                 string            `json:"host"`
		DeploymentRoot       string            `json:"deployment_root"`
		HostPlatform         string            `json:"host_platform"`
		HostArchitecture     string            `json:"host_architecture"`
		HostCapabilities     []string          `json:"host_capabilities"`
		CurrentVersion       string            `json:"current_version"`
		TargetVersion        string            `json:"target_version"`
		TargetArtifactSHA256 string            `json:"target_artifact_sha256"`
		ConfigFingerprints   map[string]string `json:"config_fingerprints"`
		Runner               RunnerEvidence    `json:"runner"`
		Health               safeHealth        `json:"health"`
		Targets              targets           `json:"targets"`
		Policy               Policy            `json:"policy"`
		StopConditions       []string          `json:"stop_conditions"`
		Steps                []previewStep     `json:"steps"`
		Recovery             []previewStep     `json:"recovery_steps"`
		RecoveryReady        bool              `json:"recovery_ready"`
		RecoveryReason       string            `json:"recovery_reason"`
		Blocked              bool              `json:"blocked"`
		BlockReason          string            `json:"block_reason,omitempty"`
	}{
		Operation: plan.Operation, Service: plan.Service, Environment: plan.Environment, Host: plan.Host, DeploymentRoot: plan.DeploymentRoot,
		HostPlatform: plan.HostPlatform, HostArchitecture: plan.HostArchitecture, HostCapabilities: sortedUniqueStrings(plan.HostCapabilities),
		CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion, TargetArtifactSHA256: plan.TargetArtifactSHA256,
		ConfigFingerprints: plan.ConfigFingerprints, Runner: plan.Runner,
		Health:         safeHealth{Type: plan.Health.Type, URL: safeURL(plan.Health.URL), Program: rollbackHealthProgram(plan.Health), ArgCount: rollbackHealthArgCount(plan.Health), CommandDigest: rollbackHealthCommandDigest(plan.Health)},
		Targets:        targets{TargetRelease: path.Join(plan.DeploymentRoot, "releases", plan.TargetVersion), CurrentLink: path.Join(plan.DeploymentRoot, "current"), PreviousLink: path.Join(plan.DeploymentRoot, "previous"), Unit: plan.Runner.Identity},
		Policy:         plan.Policy,
		StopConditions: plan.StopConditions, Steps: convert(plan.Steps), Recovery: convert(plan.Recovery.Steps), RecoveryReady: plan.Recovery.Ready,
		RecoveryReason: plan.Recovery.Reason, Blocked: plan.Blocked, BlockReason: plan.BlockReason,
	}
	return json.MarshalIndent(preview, "", "  ")
}

func rollbackHealthProgram(health opsconfig.Health) string {
	if health.Command == nil {
		return ""
	}
	return safeProgram(health.Command.Program)
}

func rollbackHealthArgCount(health opsconfig.Health) int {
	if health.Command == nil {
		return 0
	}
	return len(health.Command.Args)
}

func rollbackHealthCommandDigest(health opsconfig.Health) string {
	if health.Command == nil {
		return ""
	}
	return commandDigest(health.Command.Program, health.Command.Args)
}

func ApplyRollback(ctx context.Context, executor opsexec.Executor, confirmed ConfirmedRollbackPlan, timeout time.Duration, report RollbackReportSink) (RollbackResult, error) {
	var result RollbackResult
	plan := confirmed.Plan
	if ctx == nil || executor == nil || timeout <= 0 {
		return result, errors.New("rollback apply inputs are incomplete")
	}
	if err := ConfirmRollback(plan, confirmed.Digest); err != nil {
		return result, errors.New("rollback plan confirmation is invalid")
	}
	if err := validateRollbackPlan(plan); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	run := func(kind, program string, args ...string) error {
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: program, Args: append([]string(nil), args...), Timeout: timeout})
		state := "succeeded"
		if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
			state = "failed"
		}
		appendRollbackStep(&result, kind, state, response.ExitCode, response.TimedOut, started)
		if state == "failed" {
			return fmt.Errorf("%s failed", kind)
		}
		return nil
	}
	fail := func(err error) (RollbackResult, error) {
		if writeRollbackReport(ctx, timeout, report, result) != nil {
			return result, errors.New("rollback failed and report failed")
		}
		return result, err
	}
	root := plan.DeploymentRoot
	marker := path.Join(root, "releases", plan.TargetVersion, ".agentsetup-artifact.tar.gz")
	started := time.Now().UTC()
	inspected := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "stat", Args: []string{"-c", "%F", "--", marker}, Timeout: timeout})
	state := "succeeded"
	if inspected.Err != nil || inspected.ExitCode != 0 || inspected.TimedOut || strings.TrimSpace(inspected.Stdout) != "regular file" {
		state = "failed"
	}
	appendRollbackStep(&result, "inspect-target-marker", state, inspected.ExitCode, inspected.TimedOut, started)
	if state == "failed" {
		return fail(errors.New("rollback target artifact marker changed after preview"))
	}
	started = time.Now().UTC()
	checked := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "sha256sum", Args: []string{"--", marker}, Timeout: timeout})
	digest, digestPath, validDigest := parseSHA256Sum(checked.Stdout)
	state = "succeeded"
	if checked.Err != nil || checked.ExitCode != 0 || checked.TimedOut || !validDigest || digestPath != marker || digest != plan.TargetArtifactSHA256 {
		state = "failed"
	}
	appendRollbackStep(&result, "verify-target-artifact", state, checked.ExitCode, checked.TimedOut, started)
	if state == "failed" {
		return fail(errors.New("rollback target artifact changed after preview"))
	}
	started = time.Now().UTC()
	sealedErr := verifySealedRelease(ctx, executor, plan.Host, path.Join(root, "releases", plan.TargetVersion), timeout)
	appendRollbackStep(&result, "verify-target-sealed", resultState(sealedErr == nil), 0, false, started)
	if sealedErr != nil {
		return fail(sealedErr)
	}
	started = time.Now().UTC()
	preflightErr := revalidateRollbackPreflight(ctx, executor, plan, timeout)
	appendRollbackStep(&result, "revalidate-preflight", resultState(preflightErr == nil), 0, false, started)
	if preflightErr != nil {
		return fail(preflightErr)
	}
	if err := run("create-previous-temporary-link", "ln", "-sfn", path.Join("releases", plan.CurrentVersion), path.Join(root, ".previous.rollback.tmp")); err != nil {
		return fail(err)
	}
	if err := run("create-current-temporary-link", "ln", "-sfn", path.Join("releases", plan.TargetVersion), path.Join(root, ".current.rollback.tmp")); err != nil {
		return fail(err)
	}
	if err := run("rename-previous-link", "mv", "-Tf", path.Join(root, ".previous.rollback.tmp"), path.Join(root, "previous")); err != nil {
		return fail(err)
	}
	if err := run("rename-current-link", "mv", "-Tf", path.Join(root, ".current.rollback.tmp"), path.Join(root, "current")); err != nil {
		return fail(err)
	}
	result.Activated = true
	if err := executeRollbackRunnerContract(ctx, executor, plan, timeout, &result, false); err != nil {
		return recoverRollback(ctx, executor, plan, timeout, report, result, err)
	}
	if err := rollbackApplicationHealth(ctx, executor, plan, timeout, &result, "application-health"); err != nil {
		return recoverRollback(ctx, executor, plan, timeout, report, result, err)
	}
	result.Success = true
	if writeRollbackReport(ctx, timeout, report, result) != nil {
		result.Success = false
		return result, errors.New("rollback report failed")
	}
	return result, nil
}

func validateRollbackPlan(plan RollbackPlan) error {
	if plan.Operation != "rollback" || plan.Blocked || plan.Environment != opsconfig.EnvironmentProduction || !plan.Runner.Identified || plan.Runner.Identity == "" {
		return errors.New("rollback plan is not eligible for automatic apply")
	}
	if _, err := opsrunner.DeploymentContract(opsconfig.Service{ID: plan.Service}, rollbackRunnerEnvironment(plan)); err != nil {
		return errors.New("rollback plan is not eligible for automatic apply")
	}
	if !safeIdentity.MatchString(plan.Service) || !safeIdentity.MatchString(plan.CurrentVersion) || !safeIdentity.MatchString(plan.TargetVersion) || plan.CurrentVersion == plan.TargetVersion || !lowercaseSHA256.MatchString(plan.TargetArtifactSHA256) || plan.Host == "" || !path.IsAbs(plan.DeploymentRoot) || path.Clean(plan.DeploymentRoot) != plan.DeploymentRoot {
		return errors.New("rollback plan identity is invalid")
	}
	if !reflect.DeepEqual(plan.Steps, rollbackSteps(plan)) || !reflect.DeepEqual(plan.Recovery.Steps, rollbackRecoverySteps(plan)) {
		return errors.New("confirmed rollback plan is missing required apply semantics")
	}
	return nil
}

func revalidateRollbackPreflight(ctx context.Context, executor opsexec.Executor, plan RollbackPlan, timeout time.Duration) error {
	current, err := collectCurrent(ctx, executor, plan.Host, plan.DeploymentRoot, timeout)
	if err != nil || current != plan.CurrentVersion {
		return errors.New("rollback preflight current release changed")
	}
	if len(plan.ConfigFingerprints) != 0 {
		fingerprints, err := collectConfigFingerprints(ctx, executor, plan.Host, plan.DeploymentRoot, mapKeys(plan.ConfigFingerprints), timeout)
		if err != nil || !reflect.DeepEqual(fingerprints, plan.ConfigFingerprints) {
			return errors.New("rollback preflight configuration changed")
		}
	}
	return nil
}

func verifySealedRelease(ctx context.Context, executor opsexec.Executor, host, release string, timeout time.Duration) error {
	result := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "find", Args: []string{release, "-perm", "/022", "-print", "-quit"}, Timeout: timeout})
	if result.Err != nil || result.ExitCode != 0 || result.TimedOut || strings.TrimSpace(result.Stdout) != "" {
		return errors.New("rollback target release is not sealed")
	}
	return nil
}

func rollbackApplicationHealth(ctx context.Context, executor opsexec.Executor, plan RollbackPlan, timeout time.Duration, result *RollbackResult, kind string) error {
	started := time.Now().UTC()
	env := opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: plan.Host}
	check := opshealth.Probe(ctx, executor, env, plan.Health, timeout)
	state := "succeeded"
	if check.Err != nil || !check.Healthy {
		state = "failed"
	}
	appendRollbackStep(result, kind, state, 0, check.TimedOut, started)
	if state == "failed" {
		return fmt.Errorf("%s failed", kind)
	}
	return nil
}

func recoverRollback(ctx context.Context, executor opsexec.Executor, plan RollbackPlan, timeout time.Duration, report RollbackReportSink, result RollbackResult, cause error) (RollbackResult, error) {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	run := func(kind, program string, args ...string) error {
		started := time.Now().UTC()
		response := executor.Run(recoveryCtx, opsexec.Request{HostAlias: plan.Host, Program: program, Args: append([]string(nil), args...), Timeout: timeout})
		state := "succeeded"
		if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
			state = "failed"
		}
		appendRollbackStep(&result, kind, state, response.ExitCode, response.TimedOut, started)
		if state == "failed" {
			return fmt.Errorf("%s failed", kind)
		}
		return nil
	}
	root := plan.DeploymentRoot
	recoveryFailed := func(message string) (RollbackResult, error) {
		if writeRollbackReport(recoveryCtx, timeout, report, result) != nil {
			return result, errors.New("rollback recovery and report failed")
		}
		return result, errors.New(message)
	}
	if err := run("create-current-recovery-link", "ln", "-sfn", path.Join("releases", plan.CurrentVersion), path.Join(root, ".current.rollback.recovery.tmp")); err != nil {
		return recoveryFailed("rollback failed and recovery failed")
	}
	if err := run("rename-current-recovery-link", "mv", "-Tf", path.Join(root, ".current.rollback.recovery.tmp"), path.Join(root, "current")); err != nil {
		return recoveryFailed("rollback failed and recovery failed")
	}
	if err := executeRollbackRunnerContract(recoveryCtx, executor, plan, timeout, &result, true); err != nil {
		return recoveryFailed("rollback failed and recovery verification failed")
	}
	if err := rollbackApplicationHealth(recoveryCtx, executor, plan, timeout, &result, "verify-original-application"); err != nil {
		return recoveryFailed("rollback failed and recovery verification failed")
	}
	result.Recovered = true
	if writeRollbackReport(recoveryCtx, timeout, report, result) != nil {
		return result, errors.New("rollback recovered but report failed")
	}
	return result, fmt.Errorf("rollback failed and original release was restored: %w", cause)
}

func rollbackRunnerEnvironment(plan RollbackPlan) opsconfig.Environment {
	env := opsconfig.Environment{
		Kind: opsconfig.EnvironmentKindSSH, Host: plan.Host, Root: plan.DeploymentRoot,
		Runner: plan.Runner.Kind, ConfigOwner: plan.Runner.ConfigOwner, ConfigPath: plan.Runner.ConfigPath,
		Health: plan.Health,
	}
	if plan.Runner.Kind == opsconfig.RunnerSystemd {
		env.Unit = plan.Runner.Identity
	} else if plan.Runner.Kind == opsconfig.RunnerPHPFPM {
		env.Service = plan.Runner.Identity
	}
	return env
}

func executeRollbackRunnerContract(ctx context.Context, executor opsexec.Executor, plan RollbackPlan, timeout time.Duration, result *RollbackResult, recovery bool) error {
	contract, err := opsrunner.DeploymentContract(opsconfig.Service{ID: plan.Service}, rollbackRunnerEnvironment(plan))
	if err != nil {
		return errors.New("runner contract is invalid")
	}
	commands := append(append([]opsrunner.DeploymentCommand(nil), contract.Activation...), contract.ProcessHealth...)
	for _, command := range commands {
		kind := rollbackRunnerResultKind(plan.Runner.Kind, command.Kind, recovery)
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: command.Program, Args: append([]string(nil), command.Args...), Timeout: timeout})
		valid := response.Err == nil && response.ExitCode == 0 && !response.TimedOut && validateRunnerResponse(plan.Runner, command.Kind, response.Stdout)
		appendRollbackStep(result, kind, resultState(valid), response.ExitCode, response.TimedOut, started)
		if !valid {
			return fmt.Errorf("%s failed", kind)
		}
	}
	return nil
}

func appendRollbackStep(result *RollbackResult, kind, state string, exitCode int, timedOut bool, started time.Time) {
	finished := time.Now().UTC()
	if finished.Before(started) {
		finished = started
	}
	result.Steps = append(result.Steps, RollbackStepResult{Kind: kind, State: state, ExitCode: exitCode, TimedOut: timedOut, StartedAt: started, FinishedAt: finished})
}

func writeRollbackReport(ctx context.Context, timeout time.Duration, report RollbackReportSink, result RollbackResult) error {
	if report == nil {
		return nil
	}
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return report(reportCtx, result)
}
