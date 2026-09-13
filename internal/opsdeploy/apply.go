package opsdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wenqiangde/agentops/internal/opsartifact"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opshealth"
	"github.com/wenqiangde/agentops/internal/opsrunner"
)

type ConfirmedPlan struct {
	Plan   Plan
	Digest string
}

type ApplyStepResult struct {
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	ExitCode   int       `json:"exit_code"`
	TimedOut   bool      `json:"timed_out"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type ApplyResult struct {
	Success   bool              `json:"success"`
	Activated bool              `json:"activated"`
	Recovered bool              `json:"recovered"`
	Terminal  bool              `json:"terminal"`
	Steps     []ApplyStepResult `json:"steps"`
}

type ApplyReportSink func(context.Context, ApplyResult) error

func Apply(ctx context.Context, executor opsexec.Executor, confirmed ConfirmedPlan, artifactPath string, timeout time.Duration, report ApplyReportSink) (ApplyResult, error) {
	var result ApplyResult
	plan := confirmed.Plan
	if ctx == nil || executor == nil || timeout <= 0 || strings.TrimSpace(artifactPath) == "" {
		return result, errors.New("deployment apply inputs are incomplete")
	}
	if err := Confirm(plan, confirmed.Digest); err != nil {
		return result, errors.New("deployment plan confirmation is invalid")
	}
	if plan.Blocked || plan.Environment != opsconfig.EnvironmentProduction || !plan.Preflight.Runner.Identified || plan.Preflight.Runner.Identity == "" {
		return result, errors.New("deployment plan is not eligible for automatic apply")
	}
	if _, err := opsrunner.DeploymentContract(opsconfig.Service{ID: plan.Service}, runnerEnvironmentFromPlan(plan)); err != nil {
		return result, errors.New("deployment plan is not eligible for automatic apply")
	}
	if !safeIdentity.MatchString(plan.Service) || !safeIdentity.MatchString(plan.Version) || (plan.CurrentVersion != "" && !safeIdentity.MatchString(plan.CurrentVersion)) || !safeIdentity.MatchString(plan.Preflight.Runner.Identity) || !lowercaseSHA256.MatchString(plan.ArtifactSHA256) || plan.Host == "" || plan.DeploymentRoot == "" || path.Clean(plan.DeploymentRoot) != plan.DeploymentRoot || !path.IsAbs(plan.DeploymentRoot) {
		return result, errors.New("deployment plan identity is invalid")
	}
	if err := validateApplyStepContract(plan, artifactPath); err != nil {
		return result, err
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tempDir := path.Join(plan.DeploymentRoot, ".agentsetup", plan.Version)
	remoteArchive := path.Join(tempDir, "artifact.tar.gz")
	releaseDir := path.Join(plan.DeploymentRoot, "releases", plan.Version)
	marker := path.Join(releaseDir, ".agentsetup-artifact.tar.gz")

	run := func(kind, program string, args ...string) error {
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: program, Args: append([]string(nil), args...), Timeout: timeout})
		state := "succeeded"
		if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
			state = "failed"
		}
		appendApplyStep(&result, kind, state, response.ExitCode, response.TimedOut, started)
		if state == "failed" {
			return fmt.Errorf("%s failed", kind)
		}
		return nil
	}
	fail := func(err error) (ApplyResult, error) {
		result.Terminal = true
		if writeApplyReport(ctx, timeout, report, result) != nil {
			return result, errors.New("deployment failed and report failed")
		}
		return result, err
	}
	localStarted := time.Now().UTC()
	localDigest, err := digestLocalArtifact(ctx, artifactPath)
	appendApplyStep(&result, "verify-local-artifact-before-copy", resultState(err == nil && localDigest == plan.ArtifactSHA256), 0, false, localStarted)
	if err != nil || localDigest != plan.ArtifactSHA256 {
		return fail(errors.New("local artifact identity mismatch"))
	}

	if err := run("create-temporary-directory", "mkdir", "-p", tempDir); err != nil {
		return fail(err)
	}
	copyStarted := time.Now().UTC()
	copyResult := executor.Copy(ctx, opsexec.CopyRequest{HostAlias: plan.Host, Source: artifactPath, Destination: remoteArchive, Direction: opsexec.CopyToRemote, Timeout: timeout})
	copyState := "succeeded"
	if copyResult.Err != nil || copyResult.ExitCode != 0 || copyResult.TimedOut {
		copyState = "failed"
	}
	appendApplyStep(&result, "upload-artifact", copyState, copyResult.ExitCode, copyResult.TimedOut, copyStarted)
	if copyState == "failed" {
		return fail(errors.New("upload-artifact failed"))
	}
	localStarted = time.Now().UTC()
	localDigest, err = digestLocalArtifact(ctx, artifactPath)
	appendApplyStep(&result, "verify-local-artifact-after-copy", resultState(err == nil && localDigest == plan.ArtifactSHA256), 0, false, localStarted)
	if err != nil || localDigest != plan.ArtifactSHA256 {
		return fail(errors.New("local artifact changed during copy"))
	}
	verifyStarted := time.Now().UTC()
	verified := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "sha256sum", Args: []string{"--", remoteArchive}, Timeout: timeout})
	digest, digestPath, digestOK := parseSHA256Sum(verified.Stdout)
	digestState := "succeeded"
	if verified.Err != nil || verified.ExitCode != 0 || verified.TimedOut || !digestOK || digestPath != remoteArchive || digest != plan.ArtifactSHA256 {
		digestState = "failed"
	}
	appendApplyStep(&result, "verify-remote-sha256", digestState, verified.ExitCode, verified.TimedOut, verifyStarted)
	if digestState == "failed" {
		return fail(errors.New("verify-remote-sha256 failed"))
	}
	existsStarted := time.Now().UTC()
	exists := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "test", Args: []string{"-e", releaseDir}, Timeout: timeout})
	appendApplyStep(&result, "inspect-release-target", "succeeded", exists.ExitCode, exists.TimedOut, existsStarted)
	if exists.TimedOut || (exists.ExitCode != 0 && exists.ExitCode != 1) {
		result.Steps[len(result.Steps)-1].State = "failed"
		return fail(errors.New("inspect-release-target failed"))
	}
	if exists.ExitCode == 0 {
		markerStarted := time.Now().UTC()
		markerType := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "stat", Args: []string{"-c", "%F", "--", marker}, Timeout: timeout})
		markerState := "succeeded"
		if markerType.Err != nil || markerType.ExitCode != 0 || markerType.TimedOut || strings.TrimSpace(markerType.Stdout) != "regular file" {
			markerState = "failed"
		}
		appendApplyStep(&result, "inspect-existing-release-marker", markerState, markerType.ExitCode, markerType.TimedOut, markerStarted)
		if markerState == "failed" {
			return fail(errors.New("existing release artifact marker is invalid"))
		}
		existingStarted := time.Now().UTC()
		existing := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "sha256sum", Args: []string{"--", marker}, Timeout: timeout})
		existingDigest, existingPath, ok := parseSHA256Sum(existing.Stdout)
		appendApplyStep(&result, "verify-existing-release", "succeeded", existing.ExitCode, existing.TimedOut, existingStarted)
		if existing.Err != nil || existing.ExitCode != 0 || existing.TimedOut || !ok || existingPath != marker || existingDigest != plan.ArtifactSHA256 {
			result.Steps[len(result.Steps)-1].State = "failed"
			return fail(errors.New("existing release identity mismatch"))
		}
	} else {
		if err := run("create-release-directory", "mkdir", releaseDir); err != nil {
			return fail(err)
		}
		if err := run("extract-artifact", "tar", "--extract", "--gzip", "--file", remoteArchive, "--directory", releaseDir, "--no-same-owner", "--no-same-permissions"); err != nil {
			return fail(err)
		}
		if err := run("record-release-artifact", "mv", "-T", remoteArchive, marker); err != nil {
			return fail(err)
		}
		if err := run("seal-release", "chmod", "-R", "a-w", releaseDir); err != nil {
			return fail(err)
		}
	}
	preflightStarted := time.Now().UTC()
	preflightErr := revalidateApplyPreflight(ctx, executor, plan, timeout)
	appendApplyStep(&result, "revalidate-preflight", resultState(preflightErr == nil), 0, false, preflightStarted)
	if preflightErr != nil {
		return fail(preflightErr)
	}

	if plan.CurrentVersion != "" {
		if err := run("create-previous-temporary-link", "ln", "-sfn", path.Join("releases", plan.CurrentVersion), path.Join(plan.DeploymentRoot, ".previous.tmp")); err != nil {
			return fail(err)
		}
	}
	if err := run("create-current-temporary-link", "ln", "-sfn", path.Join("releases", plan.Version), path.Join(plan.DeploymentRoot, ".current.tmp")); err != nil {
		return fail(err)
	}
	if plan.CurrentVersion != "" {
		if err := run("rename-previous-link", "mv", "-Tf", path.Join(plan.DeploymentRoot, ".previous.tmp"), path.Join(plan.DeploymentRoot, "previous")); err != nil {
			return fail(err)
		}
	}
	if err := run("rename-current-link", "mv", "-Tf", path.Join(plan.DeploymentRoot, ".current.tmp"), path.Join(plan.DeploymentRoot, "current")); err != nil {
		return fail(err)
	}
	result.Activated = true
	if err := executeRunnerContract(ctx, executor, plan, timeout, &result, false); err != nil {
		return recoverApply(ctx, executor, plan, timeout, report, result, err)
	}
	if err := probeApplication(ctx, executor, plan, timeout, &result, "application-health"); err != nil {
		return recoverApply(ctx, executor, plan, timeout, report, result, err)
	}
	result.Success = true
	if report != nil {
		reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		err := report(reportCtx, result)
		reportCancel()
		if err != nil {
			result.Success = false
			return result, errors.New("deployment report failed")
		}
	}
	if err := pruneReleases(ctx, executor, plan, timeout, &result); err != nil {
		result.Success = false
		result.Terminal = true
		if writeApplyReport(ctx, timeout, report, result) != nil {
			return result, errors.New("deployment pruning and report failed")
		}
		return result, err
	}
	result.Terminal = true
	if writeApplyReport(ctx, timeout, report, result) != nil {
		result.Success = false
		return result, errors.New("deployment final report failed")
	}
	return result, nil
}

func validateApplyStepContract(plan Plan, artifactPath string) error {
	expected := applyStepContract(plan, artifactPath)
	expectedRecovery := recoverySteps(runnerEnvironmentFromPlan(plan), plan.CurrentVersion)
	if !reflect.DeepEqual(plan.Steps, expected) || !reflect.DeepEqual(plan.Recovery.Steps, expectedRecovery.Steps) {
		return errors.New("confirmed deployment plan does not match executable apply semantics")
	}
	return nil
}

func applyStepContract(plan Plan, artifactPath string) []Step {
	service := opsconfig.Service{ID: plan.Service}
	env := runnerEnvironmentFromPlan(plan)
	policies := opsconfig.Policies{Releases: opsconfig.ReleasePolicies{Retain: plan.Policy.ReleaseRetain}}
	artifact := opsartifact.Verified{ArchivePath: artifactPath, Manifest: opsartifact.Manifest{Version: plan.Version}}
	return futureSteps(service, env, policies, artifact, plan.CurrentVersion)
}

func runnerEnvironmentFromPlan(plan Plan) opsconfig.Environment {
	env := opsconfig.Environment{
		Kind:        opsconfig.EnvironmentKindSSH,
		Host:        plan.Host,
		Root:        plan.DeploymentRoot,
		Runner:      plan.Preflight.Runner.Kind,
		ConfigOwner: plan.Preflight.Runner.ConfigOwner,
		ConfigPath:  plan.Preflight.Runner.ConfigPath,
		Health:      plan.Health,
	}
	switch env.Runner {
	case opsconfig.RunnerSystemd:
		env.Unit = plan.Preflight.Runner.Identity
	case opsconfig.RunnerPHPFPM:
		env.Service = plan.Preflight.Runner.Identity
	}
	return env
}

func digestLocalArtifact(ctx context.Context, filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := hash.Write(buffer[:count]); err != nil {
				return "", err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return hex.EncodeToString(hash.Sum(nil)), nil
		}
		if readErr != nil {
			return "", readErr
		}
	}
}

func revalidateApplyPreflight(ctx context.Context, executor opsexec.Executor, plan Plan, timeout time.Duration) error {
	if plan.CurrentVersion != "" {
		current, err := collectCurrent(ctx, executor, plan.Host, plan.DeploymentRoot, timeout)
		if err != nil || current != plan.CurrentVersion {
			return errors.New("deployment preflight current release changed")
		}
	}
	if len(plan.ConfigFingerprints) != 0 {
		fingerprints, err := collectConfigFingerprints(ctx, executor, plan.Host, plan.DeploymentRoot, mapKeys(plan.ConfigFingerprints), timeout)
		if err != nil || !reflect.DeepEqual(fingerprints, plan.ConfigFingerprints) {
			return errors.New("deployment preflight configuration changed")
		}
	}
	return nil
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func resultState(success bool) string {
	if success {
		return "succeeded"
	}
	return "failed"
}

type releaseCandidate struct {
	name      string
	timestamp float64
}

func pruneReleases(ctx context.Context, executor opsexec.Executor, plan Plan, timeout time.Duration, result *ApplyResult) error {
	releasesRoot := path.Join(plan.DeploymentRoot, "releases")
	started := time.Now().UTC()
	response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "find", Args: []string{releasesRoot, "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-printf", "%T@ %f\\n"}, Timeout: timeout})
	state := "succeeded"
	if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
		state = "failed"
	}
	appendApplyStep(result, "list-releases-for-prune", state, response.ExitCode, response.TimedOut, started)
	if state == "failed" {
		return errors.New("prune-releases failed")
	}
	var candidates []releaseCandidate
	for _, line := range strings.Split(strings.TrimSpace(response.Stdout), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 || !safeIdentity.MatchString(parts[1]) {
			return errors.New("prune release inventory is invalid")
		}
		timestamp, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
			return errors.New("prune release inventory is invalid")
		}
		candidates = append(candidates, releaseCandidate{name: parts[1], timestamp: timestamp})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].timestamp == candidates[j].timestamp {
			return candidates[i].name > candidates[j].name
		}
		return candidates[i].timestamp > candidates[j].timestamp
	})
	retain := plan.Policy.ReleaseRetain
	if retain < 1 {
		return errors.New("release retention policy is invalid")
	}
	protected := make(map[string]bool, 2)
	protected[plan.Version] = true
	if plan.CurrentVersion != "" {
		protected[plan.CurrentVersion] = true
	}
	kept := len(protected)
	for _, candidate := range candidates {
		if protected[candidate.name] {
			continue
		}
		if kept < retain {
			kept++
			continue
		}
		current, err := collectCurrent(ctx, executor, plan.Host, plan.DeploymentRoot, timeout)
		if err != nil {
			return errors.New("cannot revalidate active release before pruning")
		}
		previous, err := collectReleaseLink(ctx, executor, plan.Host, plan.DeploymentRoot, "previous", timeout)
		if err != nil {
			return errors.New("cannot revalidate previous release before pruning")
		}
		if candidate.name == current || candidate.name == previous {
			continue
		}
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: "rm", Args: []string{"-rf", "--", path.Join(releasesRoot, candidate.name)}, Timeout: timeout})
		state := "succeeded"
		if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
			state = "failed"
		}
		appendApplyStep(result, "prune-release", state, response.ExitCode, response.TimedOut, started)
		if state == "failed" {
			return errors.New("prune-releases failed")
		}
	}
	return nil
}

func collectReleaseLink(ctx context.Context, executor opsexec.Executor, host, root, name string, timeout time.Duration) (string, error) {
	link := path.Join(root, name)
	exists := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "test", Args: []string{"-e", link}, Timeout: timeout})
	if exists.ExitCode == 1 && !exists.TimedOut {
		return "", nil
	}
	if exists.Err != nil || exists.ExitCode != 0 || exists.TimedOut {
		return "", errors.New("cannot inspect release link")
	}
	resolved := executor.Run(ctx, opsexec.Request{HostAlias: host, Program: "readlink", Args: []string{"-f", "--", link}, Timeout: timeout})
	if resolved.Err != nil || resolved.ExitCode != 0 || resolved.TimedOut {
		return "", errors.New("cannot resolve release link")
	}
	prefix := path.Join(root, "releases") + "/"
	value := strings.TrimSpace(resolved.Stdout)
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("release link is outside release root")
	}
	version := strings.TrimPrefix(value, prefix)
	if strings.Contains(version, "/") || !safeIdentity.MatchString(version) {
		return "", errors.New("release link version is invalid")
	}
	return version, nil
}

func recoverApply(ctx context.Context, executor opsexec.Executor, plan Plan, timeout time.Duration, report ApplyReportSink, result ApplyResult, cause error) (ApplyResult, error) {
	result.Terminal = true
	if !plan.Recovery.Ready || plan.CurrentVersion == "" {
		if writeApplyReport(ctx, timeout, report, result) != nil {
			return result, errors.New("deployment failed and report failed")
		}
		return result, cause
	}
	recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer recoveryCancel()
	ctx = recoveryCtx
	run := func(kind, program string, args ...string) error {
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: program, Args: args, Timeout: timeout})
		state := "succeeded"
		if response.Err != nil || response.ExitCode != 0 || response.TimedOut {
			state = "failed"
		}
		appendApplyStep(&result, kind, state, response.ExitCode, response.TimedOut, started)
		if state == "failed" {
			return fmt.Errorf("%s failed", kind)
		}
		return nil
	}
	root := plan.DeploymentRoot
	recoveryFailed := func(message string) (ApplyResult, error) {
		if writeApplyReport(ctx, timeout, report, result) != nil {
			return result, errors.New("deployment recovery and report failed")
		}
		return result, errors.New(message)
	}
	if err := run("create-current-recovery-link", "ln", "-sfn", path.Join("releases", plan.CurrentVersion), path.Join(root, ".current.recovery.tmp")); err != nil {
		return recoveryFailed("deployment failed and recovery failed")
	}
	if err := run("rename-current-recovery-link", "mv", "-Tf", path.Join(root, ".current.recovery.tmp"), path.Join(root, "current")); err != nil {
		return recoveryFailed("deployment failed and recovery failed")
	}
	if err := executeRunnerContract(ctx, executor, plan, timeout, &result, true); err != nil {
		return recoveryFailed("deployment failed and recovery verification failed")
	}
	if err := probeApplication(ctx, executor, plan, timeout, &result, "verify-previous-application"); err != nil {
		return recoveryFailed("deployment failed and recovery verification failed")
	}
	result.Recovered = true
	if writeApplyReport(ctx, timeout, report, result) != nil {
		return result, errors.New("deployment recovered but report failed")
	}
	return result, cause
}

func writeApplyReport(ctx context.Context, timeout time.Duration, report ApplyReportSink, result ApplyResult) error {
	if report == nil {
		return nil
	}
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return report(reportCtx, result)
}

func executeRunnerContract(ctx context.Context, executor opsexec.Executor, plan Plan, timeout time.Duration, result *ApplyResult, recovery bool) error {
	contract, err := opsrunner.DeploymentContract(opsconfig.Service{ID: plan.Service}, runnerEnvironmentFromPlan(plan))
	if err != nil {
		return errors.New("runner contract is invalid")
	}
	commands := append(append([]opsrunner.DeploymentCommand(nil), contract.Activation...), contract.ProcessHealth...)
	for _, command := range commands {
		kind := applyRunnerResultKind(plan.Preflight.Runner.Kind, command.Kind, recovery)
		started := time.Now().UTC()
		response := executor.Run(ctx, opsexec.Request{HostAlias: plan.Host, Program: command.Program, Args: append([]string(nil), command.Args...), Timeout: timeout})
		valid := response.Err == nil && response.ExitCode == 0 && !response.TimedOut && validateRunnerResponse(plan.Preflight.Runner, command.Kind, response.Stdout)
		appendApplyStep(result, kind, resultState(valid), response.ExitCode, response.TimedOut, started)
		if !valid {
			return fmt.Errorf("%s failed", kind)
		}
	}
	return nil
}

func applyRunnerResultKind(runner, kind string, recovery bool) string {
	if recovery {
		if runner == opsconfig.RunnerSystemd {
			if kind == "activate-runner" {
				return "restart-previous-runner"
			}
			return "verify-previous-process"
		}
		return mapRecoveryRunnerKind(kind)
	}
	if runner == opsconfig.RunnerSystemd {
		if kind == "activate-runner" {
			return "restart-runner"
		}
		return "process-health"
	}
	return kind
}

func validateRunnerResponse(runner RunnerEvidence, kind, output string) bool {
	switch kind {
	case "verify-runner-metadata", "process-health-metadata":
		if !activeRunnerMetadata(output) {
			return false
		}
		return runner.Kind != opsconfig.RunnerPHPFPM || systemctlProperty(output, "FragmentPath") == runner.ConfigPath
	case "verify-runner-config-owner", "process-health-config-owner":
		return strings.TrimSpace(output) == "regular file "+runner.ConfigOwner
	case "process-health":
		return activeRunnerMetadata(output)
	default:
		return true
	}
}

func activeRunnerMetadata(output string) bool {
	return systemctlProperty(output, "ActiveState") == "active" && systemctlProperty(output, "SubState") == "running" && validMainPID(output)
}

func systemctlProperty(output, name string) string {
	prefix := name + "="
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

func validMainPID(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "MainPID=") {
			pid, err := strconv.ParseUint(strings.TrimPrefix(line, "MainPID="), 10, 64)
			return err == nil && pid > 0
		}
	}
	return false
}

func probeApplication(ctx context.Context, executor opsexec.Executor, plan Plan, timeout time.Duration, result *ApplyResult, kind string) error {
	environment := opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: plan.Host, Runner: plan.Preflight.Runner.Kind}
	started := time.Now().UTC()
	probe := opshealth.Probe(ctx, executor, environment, plan.Health, timeout)
	state := "failed"
	if probe.Healthy && probe.Err == nil && !probe.TimedOut {
		state = "succeeded"
	}
	appendApplyStep(result, kind, state, 0, probe.TimedOut, started)
	if state == "failed" {
		return fmt.Errorf("%s failed", kind)
	}
	return nil
}

func appendApplyStep(result *ApplyResult, kind, state string, exitCode int, timedOut bool, started time.Time) {
	result.Steps = append(result.Steps, ApplyStepResult{Kind: kind, State: state, ExitCode: exitCode, TimedOut: timedOut, StartedAt: started, FinishedAt: time.Now().UTC()})
}
