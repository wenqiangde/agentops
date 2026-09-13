package opsdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
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

const AccessRead = "read"
const AccessWrite = "write"

var safeIdentity = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)
var lowercaseSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Plan struct {
	Service              string            `json:"service"`
	Environment          string            `json:"environment"`
	Host                 string            `json:"host"`
	DeploymentRoot       string            `json:"deployment_root"`
	HostPlatform         string            `json:"host_platform"`
	HostArchitecture     string            `json:"host_architecture"`
	HostCapabilities     []string          `json:"host_capabilities"`
	Version              string            `json:"version"`
	ArtifactSHA256       string            `json:"artifact_sha256"`
	ArtifactCommit       string            `json:"artifact_commit"`
	ArtifactPlatform     string            `json:"artifact_platform"`
	ArtifactArchitecture string            `json:"artifact_architecture"`
	ArtifactSize         int64             `json:"artifact_size"`
	ArtifactExpandedSize int64             `json:"artifact_expanded_size"`
	RequiredDiskBytes    int64             `json:"required_disk_bytes"`
	CurrentVersion       string            `json:"current_version"`
	ConfigFingerprints   map[string]string `json:"config_fingerprints"`
	Migration            Migration         `json:"migration"`
	Health               opsconfig.Health  `json:"health"`
	Policy               Policy            `json:"policy"`
	Preflight            Preflight         `json:"preflight"`
	StopConditions       []string          `json:"stop_conditions"`
	Steps                []Step            `json:"steps"`
	Recovery             Recovery          `json:"recovery"`
	Blocked              bool              `json:"blocked"`
	BlockReason          string            `json:"block_reason,omitempty"`
}

type Migration struct {
	Command      string `json:"command,omitempty"`
	BackupPolicy string `json:"backup_policy,omitempty"`
}

type Policy struct {
	DefaultTimeout               string `json:"default_timeout"`
	HealthTimeout                string `json:"health_timeout"`
	ReleaseRetain                int    `json:"release_retain"`
	RequirePreviewDigest         bool   `json:"require_preview_digest"`
	RequireCleanArtifactManifest bool   `json:"require_clean_artifact_manifest"`
}

type Preflight struct {
	RemoteUser         string            `json:"remote_user"`
	OS                 string            `json:"os"`
	Architecture       string            `json:"architecture"`
	DiskAvailableBytes int64             `json:"disk_available_bytes"`
	RequiredCommands   []CommandEvidence `json:"required_commands"`
	Runner             RunnerEvidence    `json:"runner"`
	Health             HealthEvidence    `json:"health"`
}

type CommandEvidence struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

type RunnerEvidence struct {
	Kind        string `json:"kind"`
	Identity    string `json:"identity"`
	ConfigOwner string `json:"config_owner,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`
	State       string `json:"state"`
	Identified  bool   `json:"identified"`
}

type HealthEvidence struct {
	Type       string `json:"type"`
	Executable bool   `json:"executable"`
	Executed   bool   `json:"executed"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"status_code,omitempty"`
	State      string `json:"state"`
}

type Step struct {
	Order     int      `json:"order"`
	Kind      string   `json:"kind"`
	Scope     string   `json:"scope"`
	Access    string   `json:"access"`
	Condition string   `json:"condition"`
	Program   string   `json:"program"`
	Args      []string `json:"args,omitempty"`
}

type Recovery struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason"`
	Steps  []Step `json:"steps"`
}

type fingerprint struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type canonicalPlan Plan

func CanonicalJSON(plan Plan) ([]byte, error) {
	normalized := canonicalPlan(plan)
	normalized.HostCapabilities = sortedUniqueStrings(plan.HostCapabilities)
	normalized.Health.SuccessStatuses = sortedUniqueInts(plan.Health.SuccessStatuses)
	normalized.Preflight.RequiredCommands = append([]CommandEvidence(nil), plan.Preflight.RequiredCommands...)
	sort.Slice(normalized.Preflight.RequiredCommands, func(i, j int) bool {
		return normalized.Preflight.RequiredCommands[i].Name < normalized.Preflight.RequiredCommands[j].Name
	})
	fingerprints := make([]fingerprint, 0, len(plan.ConfigFingerprints))
	for name, value := range plan.ConfigFingerprints {
		fingerprints = append(fingerprints, fingerprint{Path: name, Value: value})
	}
	sort.Slice(fingerprints, func(i, j int) bool { return fingerprints[i].Path < fingerprints[j].Path })
	type canonicalEnvelope struct {
		Plan         canonicalPlan `json:"plan"`
		Fingerprints []fingerprint `json:"config_fingerprints"`
	}
	normalized.ConfigFingerprints = nil
	return json.Marshal(canonicalEnvelope{Plan: normalized, Fingerprints: fingerprints})
}

func Digest(plan Plan) (string, error) {
	data, err := CanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func Create(ctx context.Context, executor opsexec.Executor, service opsconfig.Service, host opsconfig.Host, policies opsconfig.Policies, artifact opsartifact.Verified, timeout time.Duration) (Plan, error) {
	if ctx == nil || executor == nil || timeout <= 0 {
		return Plan{}, errors.New("deployment planning inputs are incomplete")
	}
	production, ok := service.Environments[opsconfig.EnvironmentProduction]
	if !ok || production.Kind != opsconfig.EnvironmentKindSSH || production.Root == "" || host.SSHAlias == "" {
		return Plan{}, errors.New("production target is incomplete")
	}
	if artifact.Manifest.Service != service.ID || !safeIdentity.MatchString(artifact.Manifest.Version) || artifact.Manifest.SHA256 != artifact.SHA256 || !lowercaseSHA256.MatchString(artifact.SHA256) {
		return Plan{}, errors.New("artifact identity does not match deployment request")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	current, err := collectCurrent(ctx, executor, host.SSHAlias, production.Root, timeout)
	if err != nil {
		return Plan{}, err
	}
	preflight, fingerprints, err := collectPreflight(ctx, executor, service, production, host, artifact, timeout)
	if err != nil {
		return Plan{}, err
	}
	requiredDisk, err := requiredDiskBytes(artifact)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Service: service.ID, Environment: opsconfig.EnvironmentProduction, Host: host.SSHAlias, DeploymentRoot: production.Root,
		HostPlatform: host.Platform, HostArchitecture: host.Architecture, HostCapabilities: append([]string(nil), host.Capabilities...),
		Version: artifact.Manifest.Version, ArtifactSHA256: artifact.SHA256, ArtifactCommit: artifact.Manifest.Commit,
		ArtifactPlatform: artifact.Manifest.Platform, ArtifactArchitecture: artifact.Manifest.Architecture, ArtifactSize: artifact.Size,
		ArtifactExpandedSize: artifact.ExpandedSize, RequiredDiskBytes: requiredDisk,
		CurrentVersion: current, ConfigFingerprints: fingerprints, Health: production.Health, Preflight: preflight,
		Policy:         Policy{DefaultTimeout: policies.Execution.DefaultTimeout, HealthTimeout: policies.Execution.HealthTimeout, ReleaseRetain: policies.Releases.Retain, RequirePreviewDigest: policies.Production.RequirePreviewDigest, RequireCleanArtifactManifest: policies.Production.RequireCleanArtifactManifest},
		StopConditions: []string{"artifact digest mismatch", "preflight input changed", "runner restart failed", "process health failed", "application health failed"},
	}
	plan.Steps = futureSteps(service, production, policies, artifact, current)
	plan.Recovery = recoverySteps(production, current)
	if service.Data.MySQL != nil && strings.TrimSpace(service.Data.MySQL.MigrationCommand) != "" {
		plan.Migration = Migration{Command: service.Data.MySQL.MigrationCommand, BackupPolicy: service.Data.MySQL.BackupPolicy}
		plan.Blocked = true
		plan.BlockReason = "migration recovery and compatibility evidence is incomplete"
		plan.Recovery = Recovery{Ready: false, Reason: "migration compatibility and verified recovery evidence are required"}
	}
	if _, err := opsrunner.DeploymentContract(service, production); err != nil {
		plan.Blocked = true
		plan.BlockReason = "automatic apply does not support the declared runner contract"
		plan.Recovery = Recovery{Ready: false, Reason: "automatic runner recovery is unavailable"}
	}
	return plan, nil
}

func collectCurrent(ctx context.Context, executor opsexec.Executor, host, root string, timeout time.Duration) (string, error) {
	exists := runRead(ctx, executor, opsexec.Request{HostAlias: host, Program: "test", Args: []string{"-e", path.Join(root, "current")}, Timeout: timeout})
	if exists.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", errors.New("remote state collection timed out")
	}
	if exists.ExitCode == 1 {
		return "", nil
	}
	if exists.Err != nil || exists.ExitCode != 0 {
		return "", errors.New("cannot inspect current release link")
	}
	result := runRead(ctx, executor, opsexec.Request{HostAlias: host, Program: "readlink", Args: []string{"-f", "--", path.Join(root, "current")}, Timeout: timeout})
	if result.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", errors.New("remote state collection timed out")
	}
	if result.Err != nil || result.ExitCode != 0 {
		return "", errors.New("cannot collect current release metadata")
	}
	prefix := path.Join(root, "releases") + "/"
	value := strings.TrimSpace(result.Stdout)
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("current release link is outside release root")
	}
	version := strings.TrimPrefix(value, prefix)
	if strings.Contains(version, "/") || !safeIdentity.MatchString(version) {
		return "", errors.New("current release version is invalid")
	}
	return version, nil
}

func collectPreflight(ctx context.Context, executor opsexec.Executor, service opsconfig.Service, env opsconfig.Environment, host opsconfig.Host, artifact opsartifact.Verified, timeout time.Duration) (Preflight, map[string]string, error) {
	user, err := scalarRead(ctx, executor, host.SSHAlias, "id", []string{"-un"}, timeout, "SSH session identity")
	if err != nil || !safeIdentity.MatchString(user) {
		return Preflight{}, nil, errors.New("SSH session identity metadata is invalid")
	}
	uname, err := scalarRead(ctx, executor, host.SSHAlias, "uname", []string{"-s", "-m"}, timeout, "remote platform")
	if err != nil {
		return Preflight{}, nil, err
	}
	parts := strings.Fields(uname)
	if len(parts) != 2 {
		return Preflight{}, nil, errors.New("remote platform metadata is invalid")
	}
	osName, architecture := normalizeTarget(parts[0], parts[1])
	declaredOS, declaredArch := normalizeTarget(host.Platform, host.Architecture)
	if osName != declaredOS || architecture != declaredArch {
		return Preflight{}, nil, errors.New("remote platform does not match declared host")
	}
	available, err := scalarRead(ctx, executor, host.SSHAlias, "df", []string{"--output=avail", "-B1", "--", env.Root}, timeout, "remote disk")
	if err != nil {
		return Preflight{}, nil, err
	}
	disk, err := parseAvailableBytes(available)
	requiredDisk, sizeErr := requiredDiskBytes(artifact)
	if err != nil || sizeErr != nil || disk < requiredDisk {
		return Preflight{}, nil, errors.New("remote disk metadata is invalid or insufficient")
	}
	required := []string{"chmod", "find", "ln", "mkdir", "mv", "rm", "sha256sum", "stat", "systemctl", "tar"}
	evidence := make([]CommandEvidence, 0, len(required))
	for _, command := range required {
		result := runRead(ctx, executor, opsexec.Request{HostAlias: host.SSHAlias, Program: "which", Args: []string{command}, Timeout: timeout})
		if result.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Preflight{}, nil, errors.New("remote preflight timed out")
		}
		if result.Err != nil || result.ExitCode != 0 {
			return Preflight{}, nil, errors.New("required remote command is unavailable")
		}
		evidence = append(evidence, CommandEvidence{Name: command, Available: true})
	}
	runnerEnv := env
	runnerEnv.Host = host.SSHAlias
	check := opsrunner.New(env.Runner, executor).Inspect(ctx, service, runnerEnv)
	if check.Err != nil || (check.State != opsrunner.StateRunning && check.State != opsrunner.StateStopped) {
		return Preflight{}, nil, errors.New("runner inspection failed")
	}
	runner := RunnerEvidence{Kind: env.Runner, Identity: runnerIdentity(env), ConfigOwner: env.ConfigOwner, ConfigPath: env.ConfigPath, State: check.State, Identified: runnerIdentity(env) != ""}
	if !runner.Identified {
		return Preflight{}, nil, errors.New("runner identity is incomplete")
	}
	fingerprints, err := collectConfigFingerprints(ctx, executor, host.SSHAlias, env.Root, env.Config.Files, timeout)
	if err != nil {
		return Preflight{}, nil, err
	}
	health, err := collectHealthEvidence(ctx, executor, runnerEnv, env.Health, timeout)
	if err != nil {
		return Preflight{}, nil, err
	}
	return Preflight{RemoteUser: user, OS: osName, Architecture: architecture, DiskAvailableBytes: disk, RequiredCommands: evidence, Runner: runner, Health: health}, fingerprints, nil
}

func collectConfigFingerprints(ctx context.Context, executor opsexec.Executor, host, root string, files []string, timeout time.Duration) (map[string]string, error) {
	result := make(map[string]string, len(files))
	for _, relative := range sortedStrings(files) {
		if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, "|\r\n\x00") {
			return nil, errors.New("configuration reference path is invalid")
		}
		absolute := path.Join(root, relative)
		response := runRead(ctx, executor, opsexec.Request{HostAlias: host, Program: "sha256sum", Args: []string{"--", absolute}, Timeout: timeout})
		if response.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("configuration fingerprint collection timed out")
		}
		if response.Err != nil || response.ExitCode != 0 {
			return nil, errors.New("cannot collect configuration fingerprint")
		}
		digest, outputPath, ok := parseSHA256Sum(response.Stdout)
		if !ok || outputPath != absolute {
			return nil, errors.New("configuration fingerprint is invalid")
		}
		result[relative] = digest
	}
	return result, nil
}

func collectHealthEvidence(ctx context.Context, executor opsexec.Executor, env opsconfig.Environment, health opsconfig.Health, timeout time.Duration) (HealthEvidence, error) {
	if health.Type == "command" {
		if health.Command == nil {
			return HealthEvidence{}, errors.New("command health contract is incomplete")
		}
		result := runRead(ctx, executor, opsexec.Request{HostAlias: env.Host, Program: "which", Args: []string{health.Command.Program}, Timeout: timeout})
		if result.Err != nil || result.ExitCode != 0 {
			return HealthEvidence{}, errors.New("health command is unavailable")
		}
		return HealthEvidence{Type: "command", Executable: true, Executed: false, State: "not-run-read-only-boundary"}, nil
	}
	result := opshealth.Probe(ctx, executor, env, health, timeout)
	if result.TimedOut {
		return HealthEvidence{}, errors.New("health preflight timed out")
	}
	if result.Err != nil && !result.Healthy {
		return HealthEvidence{}, errors.New("health contract is not executable")
	}
	state := "unhealthy"
	if result.Healthy {
		state = "healthy"
	}
	return HealthEvidence{Type: health.Type, Executable: true, Executed: true, Healthy: result.Healthy, StatusCode: result.StatusCode, State: state}, nil
}

func futureSteps(service opsconfig.Service, env opsconfig.Environment, policies opsconfig.Policies, artifact opsartifact.Verified, current string) []Step {
	root := env.Root
	tempDir := path.Join(root, ".agentsetup", artifact.Manifest.Version)
	archive := path.Join(tempDir, "artifact.tar.gz")
	release := path.Join(root, "releases", artifact.Manifest.Version)
	var steps []Step
	add := func(kind, scope, access, condition, program string, args ...string) {
		steps = append(steps, Step{Order: len(steps) + 1, Kind: kind, Scope: scope, Access: access, Condition: condition, Program: program, Args: args})
	}
	add("verify-local-artifact-before-copy", "local", AccessRead, "after-confirm", "sha256", artifact.ArchivePath)
	add("create-temporary-directory", "remote", AccessWrite, "after-confirm", "mkdir", "-p", tempDir)
	add("upload-artifact", "transfer", AccessWrite, "after-temporary-directory", "scp", artifact.ArchivePath, archive)
	add("verify-local-artifact-after-copy", "local", AccessRead, "after-upload", "sha256", artifact.ArchivePath)
	add("verify-remote-sha256", "remote", AccessRead, "after-upload", "sha256sum", "--", archive)
	add("revalidate-preflight", "remote", AccessRead, "immediately-before-activation", "preflight", path.Join(root, "current"))
	add("inspect-release-target", "remote", AccessRead, "after-digest-match", "test", "-e", release)
	add("inspect-existing-release-marker", "remote", AccessRead, "when-release-exists", "stat", "-c", "%F", "--", path.Join(release, ".agentsetup-artifact.tar.gz"))
	add("verify-existing-release", "remote", AccessRead, "when-release-exists", "sha256sum", "--", path.Join(release, ".agentsetup-artifact.tar.gz"))
	add("create-release-directory", "remote", AccessWrite, "when-release-missing", "mkdir", release)
	add("extract-artifact", "remote", AccessWrite, "after-release-directory", "tar", "--extract", "--gzip", "--file", archive, "--directory", release, "--no-same-owner", "--no-same-permissions")
	add("record-release-artifact", "remote", AccessWrite, "after-extract", "mv", "-T", archive, path.Join(release, ".agentsetup-artifact.tar.gz"))
	add("seal-release", "remote", AccessWrite, "after-recording-artifact", "chmod", "-R", "a-w", release)
	if service.Data.MySQL != nil && service.Data.MySQL.MigrationCommand != "" {
		add("run-migration", "remote", AccessWrite, "after-approved-backup-and-compatibility", service.Data.MySQL.MigrationCommand)
	}
	if current != "" {
		add("create-previous-temporary-link", "remote", AccessWrite, "before-activation", "ln", "-sfn", path.Join("releases", current), path.Join(root, ".previous.tmp"))
	}
	add("create-current-temporary-link", "remote", AccessWrite, "before-activation", "ln", "-sfn", path.Join("releases", artifact.Manifest.Version), path.Join(root, ".current.tmp"))
	if current != "" {
		add("rename-previous-link", "remote", AccessWrite, "after-temporary-links", "mv", "-Tf", path.Join(root, ".previous.tmp"), path.Join(root, "previous"))
	}
	add("rename-current-link", "remote", AccessWrite, "after-temporary-links", "mv", "-Tf", path.Join(root, ".current.tmp"), path.Join(root, "current"))
	contract, _ := opsrunner.DeploymentContract(service, deploymentEnvironment(env))
	if env.Runner == opsconfig.RunnerSystemd {
		if len(contract.Activation) == 1 {
			command := contract.Activation[0]
			add("restart-runner", "remote", AccessWrite, "after-activation", command.Program, command.Args...)
		}
		if len(contract.ProcessHealth) == 1 {
			command := contract.ProcessHealth[0]
			add("process-health", "remote", AccessRead, "after-restart", command.Program, command.Args...)
		}
	} else {
		for _, command := range contract.Activation {
			access := AccessRead
			if command.Kind == "activate-runner" {
				access = AccessWrite
			}
			add(command.Kind, "remote", access, "after-activation", command.Program, command.Args...)
		}
		for _, command := range contract.ProcessHealth {
			add(command.Kind, "remote", AccessRead, "after-runner-activation", command.Program, command.Args...)
		}
	}
	add("application-health", "remote", AccessRead, "after-process-health", "health-probe")
	add("write-local-report", "local", AccessWrite, "after-terminal-outcome", "opsreport")
	add("prune-releases", "remote", AccessWrite, "success-only", "find+rm", path.Join(root, "releases"), strconv.Itoa(policies.Releases.Retain), artifact.Manifest.Version, current)
	return steps
}

func recoverySteps(env opsconfig.Environment, current string) Recovery {
	if current == "" {
		return Recovery{Ready: false, Reason: "first deployment has no previous release; stop and report on failure"}
	}
	var steps []Step
	add := func(kind, scope, access, condition, program string, args ...string) {
		steps = append(steps, Step{Order: len(steps) + 1, Kind: kind, Scope: scope, Access: access, Condition: condition, Program: program, Args: args})
	}
	root := env.Root
	add("create-current-recovery-link", "remote", AccessWrite, "on-compatible-failure", "ln", "-sfn", path.Join("releases", current), path.Join(root, ".current.recovery.tmp"))
	add("rename-current-recovery-link", "remote", AccessWrite, "after-recovery-link", "mv", "-Tf", path.Join(root, ".current.recovery.tmp"), path.Join(root, "current"))
	service := opsconfig.Service{ID: "recovery"}
	contract, _ := opsrunner.DeploymentContract(service, deploymentEnvironment(env))
	if env.Runner == opsconfig.RunnerSystemd || (env.Runner == "" && env.Unit != "") {
		if len(contract.Activation) == 1 {
			command := contract.Activation[0]
			add("restart-previous-runner", "remote", AccessWrite, "after-recovery-activation", command.Program, command.Args...)
		}
		if len(contract.ProcessHealth) == 1 {
			command := contract.ProcessHealth[0]
			add("verify-previous-process", "remote", AccessRead, "after-recovery-restart", command.Program, command.Args...)
		}
	} else {
		for _, command := range contract.Activation {
			kind := mapRecoveryRunnerKind(command.Kind)
			access := AccessRead
			if command.Kind == "activate-runner" {
				access = AccessWrite
			}
			add(kind, "remote", access, "after-recovery-activation", command.Program, command.Args...)
		}
		for _, command := range contract.ProcessHealth {
			add(mapRecoveryRunnerKind(command.Kind), "remote", AccessRead, "after-recovery-runner-activation", command.Program, command.Args...)
		}
	}
	add("verify-previous-application", "remote", AccessRead, "after-recovery-process", "health-probe")
	add("write-recovery-report", "local", AccessWrite, "after-recovery-outcome", "opsreport")
	return Recovery{Ready: true, Reason: "previous release is available and data compatibility is unchanged", Steps: steps}
}

func deploymentEnvironment(env opsconfig.Environment) opsconfig.Environment {
	if env.Runner == "" && env.Unit != "" {
		env.Runner = opsconfig.RunnerSystemd
	}
	return env
}

func mapRecoveryRunnerKind(kind string) string {
	switch kind {
	case "verify-runner-metadata":
		return "verify-previous-runner-metadata"
	case "verify-runner-config-owner":
		return "verify-previous-runner-config-owner"
	case "activate-runner":
		return "activate-previous-runner"
	case "process-health-metadata":
		return "verify-previous-process-metadata"
	case "process-health-config-owner":
		return "verify-previous-process-config-owner"
	default:
		return kind
	}
}

func MarshalPreview(plan Plan) ([]byte, error) {
	type safeCommand struct {
		Program       string `json:"program"`
		ArgCount      int    `json:"arg_count"`
		CommandDigest string `json:"command_digest"`
	}
	type safeStep struct {
		Order     int         `json:"order"`
		Kind      string      `json:"kind"`
		Scope     string      `json:"scope"`
		Access    string      `json:"access"`
		Condition string      `json:"condition"`
		Command   safeCommand `json:"command"`
	}
	type safeHealth struct {
		Type          string `json:"type"`
		URL           string `json:"url,omitempty"`
		Program       string `json:"program,omitempty"`
		ArgCount      int    `json:"arg_count"`
		CommandDigest string `json:"command_digest,omitempty"`
	}
	type safeMigration struct {
		Script        string `json:"script,omitempty"`
		CommandDigest string `json:"command_digest"`
		BackupPolicy  string `json:"backup_policy,omitempty"`
	}
	type safeTargets struct {
		Release  string `json:"release"`
		Current  string `json:"current"`
		Previous string `json:"previous,omitempty"`
		Unit     string `json:"unit"`
		Retain   int    `json:"retain"`
	}
	safeSteps := func(steps []Step) []safeStep {
		out := make([]safeStep, 0, len(steps))
		for _, step := range steps {
			program := safeProgram(step.Program)
			if step.Kind == "run-migration" {
				program = "migration-command"
			}
			out = append(out, safeStep{Order: step.Order, Kind: step.Kind, Scope: step.Scope, Access: step.Access, Condition: step.Condition, Command: safeCommand{Program: program, ArgCount: len(step.Args), CommandDigest: commandDigest(step.Program, step.Args)}})
		}
		return out
	}
	health := safeHealth{Type: plan.Health.Type}
	if plan.Health.URL != "" {
		health.URL = safeURL(plan.Health.URL)
	}
	if plan.Health.Command != nil {
		health.Program = safeProgram(plan.Health.Command.Program)
		health.ArgCount = len(plan.Health.Command.Args)
		health.CommandDigest = commandDigest(plan.Health.Command.Program, plan.Health.Command.Args)
	}
	preview := struct {
		Service              string            `json:"service"`
		Environment          string            `json:"environment"`
		Host                 string            `json:"host"`
		Version              string            `json:"version"`
		ArtifactSHA256       string            `json:"artifact_sha256"`
		ArtifactCommit       string            `json:"artifact_commit"`
		ArtifactPlatform     string            `json:"artifact_platform"`
		ArtifactArchitecture string            `json:"artifact_architecture"`
		ArtifactSize         int64             `json:"artifact_size"`
		ArtifactExpandedSize int64             `json:"artifact_expanded_size"`
		RequiredDiskBytes    int64             `json:"required_disk_bytes"`
		CurrentVersion       string            `json:"current_version"`
		HostPlatform         string            `json:"host_platform"`
		HostArchitecture     string            `json:"host_architecture"`
		HostCapabilities     []string          `json:"host_capabilities"`
		ConfigFingerprints   map[string]string `json:"config_fingerprints"`
		Health               safeHealth        `json:"health"`
		Migration            safeMigration     `json:"migration"`
		Targets              safeTargets       `json:"targets"`
		Policy               Policy            `json:"policy"`
		Preflight            Preflight         `json:"preflight"`
		StopConditions       []string          `json:"stop_conditions"`
		Steps                []safeStep        `json:"steps"`
		RecoverySteps        []safeStep        `json:"recovery_steps"`
		RecoveryReady        bool              `json:"recovery_ready"`
		RecoveryReason       string            `json:"recovery_reason"`
		Blocked              bool              `json:"blocked"`
		BlockReason          string            `json:"block_reason,omitempty"`
	}{
		Service: plan.Service, Environment: plan.Environment, Host: plan.Host, Version: plan.Version, ArtifactSHA256: plan.ArtifactSHA256, ArtifactCommit: plan.ArtifactCommit,
		ArtifactPlatform: plan.ArtifactPlatform, ArtifactArchitecture: plan.ArtifactArchitecture, ArtifactSize: plan.ArtifactSize, ArtifactExpandedSize: plan.ArtifactExpandedSize, RequiredDiskBytes: plan.RequiredDiskBytes, CurrentVersion: plan.CurrentVersion,
		HostPlatform: plan.HostPlatform, HostArchitecture: plan.HostArchitecture, HostCapabilities: sortedUniqueStrings(plan.HostCapabilities), ConfigFingerprints: plan.ConfigFingerprints,
		Health: health, Migration: safeMigration{Script: migrationLabel(plan.Migration.Command), CommandDigest: commandDigest(plan.Migration.Command, nil), BackupPolicy: plan.Migration.BackupPolicy},
		Targets: safeTargets{Release: releaseTarget(plan), Current: currentTarget(plan), Previous: previousTarget(plan), Unit: plan.Preflight.Runner.Identity, Retain: plan.Policy.ReleaseRetain},
		Policy:  plan.Policy, Preflight: plan.Preflight, StopConditions: plan.StopConditions, Steps: safeSteps(plan.Steps), RecoverySteps: safeSteps(plan.Recovery.Steps),
		RecoveryReady: plan.Recovery.Ready, RecoveryReason: plan.Recovery.Reason, Blocked: plan.Blocked, BlockReason: plan.BlockReason,
	}
	return json.MarshalIndent(preview, "", "  ")
}

func MarshalIndented(plan Plan) ([]byte, error) { return MarshalPreview(plan) }
func Confirm(plan Plan, digest string) error {
	if plan.Blocked {
		return errors.New(plan.BlockReason)
	}
	if !IsDigest(digest) {
		return errors.New("preview digest must be 64 lowercase hexadecimal characters")
	}
	current, err := Digest(plan)
	if err != nil {
		return err
	}
	if current != digest {
		return errors.New("preview digest is stale")
	}
	return nil
}
func IsDigest(value string) bool { return lowercaseSHA256.MatchString(value) }

func requiredDiskBytes(artifact opsartifact.Verified) (int64, error) {
	if artifact.Size < 0 || artifact.ExpandedSize < 0 || artifact.Size > int64(^uint64(0)>>1)-artifact.ExpandedSize {
		return 0, errors.New("artifact disk requirement is invalid")
	}
	return artifact.Size + artifact.ExpandedSize, nil
}

func parseSHA256Sum(output string) (string, string, bool) {
	line := strings.TrimSuffix(output, "\n")
	line = strings.TrimSuffix(line, "\r")
	escaped := strings.HasPrefix(line, `\`)
	if escaped {
		line = line[1:]
	}
	if len(line) < 66 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
		return "", "", false
	}
	digest := line[:64]
	if !lowercaseSHA256.MatchString(digest) {
		return "", "", false
	}
	name := line[66:]
	if escaped {
		var builder strings.Builder
		for index := 0; index < len(name); index++ {
			if name[index] != '\\' {
				builder.WriteByte(name[index])
				continue
			}
			index++
			if index >= len(name) {
				return "", "", false
			}
			switch name[index] {
			case '\\':
				builder.WriteByte('\\')
			case 'n':
				builder.WriteByte('\n')
			case 'r':
				builder.WriteByte('\r')
			default:
				return "", "", false
			}
		}
		name = builder.String()
	}
	return digest, name, true
}

func parseAvailableBytes(output string) (int64, error) {
	fields := strings.Fields(output)
	if len(fields) == 2 && strings.EqualFold(fields[0], "avail") {
		fields = fields[1:]
	}
	if len(fields) != 1 || fields[0] == "" {
		return 0, errors.New("remote disk metadata is invalid")
	}
	for _, character := range fields[0] {
		if character < '0' || character > '9' {
			return 0, errors.New("remote disk metadata is invalid")
		}
	}
	value, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("remote disk metadata is invalid")
	}
	return value, nil
}

func runRead(ctx context.Context, executor opsexec.Executor, request opsexec.Request) opsexec.Result {
	return executor.Run(ctx, request)
}
func scalarRead(ctx context.Context, executor opsexec.Executor, host, program string, args []string, timeout time.Duration, label string) (string, error) {
	result := runRead(ctx, executor, opsexec.Request{HostAlias: host, Program: program, Args: args, Timeout: timeout})
	if result.TimedOut || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("%s collection timed out", label)
	}
	if result.Err != nil || result.ExitCode != 0 {
		return "", fmt.Errorf("cannot collect %s metadata", label)
	}
	return strings.TrimSpace(result.Stdout), nil
}
func normalizeTarget(osName, arch string) (string, string) {
	osName = strings.ToLower(osName)
	arch = strings.ToLower(arch)
	if osName == "ubuntu" {
		osName = "linux"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	if arch == "aarch64" {
		arch = "arm64"
	}
	return osName, arch
}
func runnerIdentity(env opsconfig.Environment) string {
	switch env.Runner {
	case opsconfig.RunnerSystemd:
		return env.Unit
	case opsconfig.RunnerPHPFPM:
		return env.Service
	case opsconfig.RunnerPM2:
		return env.App
	case opsconfig.RunnerProcess:
		return env.PIDFile
	default:
		return ""
	}
}
func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
func sortedUniqueStrings(values []string) []string {
	sorted := sortedStrings(values)
	result := sorted[:0]
	for _, value := range sorted {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
func sortedUniqueInts(values []int) []int {
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	result := sorted[:0]
	for _, value := range sorted {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
func commandDigest(program string, args []string) string {
	sum := sha256.Sum256([]byte(program + "\x00" + strings.Join(args, "\x00")))
	return hex.EncodeToString(sum[:])
}
func safeProgram(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return path.Base(fields[0])
}
func migrationLabel(command string) string {
	if strings.TrimSpace(command) == "" {
		return ""
	}
	return "migration-command"
}
func releaseTarget(plan Plan) string { return path.Join(plan.DeploymentRoot, "releases", plan.Version) }
func currentTarget(plan Plan) string { return path.Join(plan.DeploymentRoot, "current") }
func previousTarget(plan Plan) string {
	if plan.CurrentVersion == "" {
		return ""
	}
	return path.Join(plan.DeploymentRoot, "previous")
}
func safeURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return "[invalid URL]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}
