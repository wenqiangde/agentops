package opscloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"sort"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
)

const rollbackMessage = "AgentOps confirmed rollback"

type RollbackTargetRequest struct {
	SourcePath     string
	WranglerConfig string
	TargetID       string
	Timeout        time.Duration
}

type RollbackTarget struct {
	VersionID    string
	DeploymentID string
}

type RollbackPlanRequest struct {
	Service               string
	TargetID              string
	Git                   opsgit.Evidence
	Preflight             Request
	RepositorySourcePath  string
	DeploymentInputSHA256 string
	RequireCommittedScope bool
}

type CloudflareRollbackPlan struct {
	Service               string         `json:"service"`
	Environment           string         `json:"environment"`
	Worker                string         `json:"worker"`
	AccountID             string         `json:"account_id"`
	WranglerConfig        string         `json:"wrangler_config"`
	WranglerConfigSHA256  string         `json:"wrangler_config_sha256"`
	WranglerVersion       string         `json:"wrangler_version"`
	BaseCommit            string         `json:"base_commit"`
	ScopeState            string         `json:"scope_state"`
	ScopeContentSHA256    string         `json:"scope_content_sha256"`
	DeploymentInputSHA256 string         `json:"deployment_input_sha256"`
	ScopeEntries          []opsgit.Entry `json:"scope_entries,omitempty"`
	RequireCommittedScope bool           `json:"require_committed_scope"`
	RequestedTargetID     string         `json:"requested_target_id"`
	TargetVersionID       string         `json:"target_version_id"`
	TargetDeploymentID    string         `json:"target_deployment_id,omitempty"`
	CurrentDeploymentID   string         `json:"current_deployment_id"`
	CurrentVersionIDs     []string       `json:"current_version_ids"`
	TargetVerified        bool           `json:"target_verified"`
	Blocked               bool           `json:"blocked"`
	BlockReason           string         `json:"block_reason,omitempty"`
	SourcePath            string         `json:"-"`
	Timeout               time.Duration  `json:"-"`
}

type ConfirmedRollbackPlan struct {
	Plan   CloudflareRollbackPlan
	Digest string
}

type ConfirmedProductionRollbackPlan struct {
	plan     CloudflareRollbackPlan
	request  opscloudflarepayload.RollbackRequest
	identity ProductionConfirmationIdentity
	digest   string
}

type RollbackResult struct {
	Success                  bool
	ProductionWriteSucceeded bool
	DeploymentID             string
	VersionID                string
}

func ResolveRollbackTarget(ctx context.Context, executor opsexec.Executor, request RollbackTargetRequest) (RollbackTarget, error) {
	if ctx == nil || executor == nil || request.SourcePath == "" || request.WranglerConfig == "" || request.Timeout <= 0 {
		return RollbackTarget{}, errors.New("Cloudflare rollback target lookup inputs are incomplete")
	}
	if !cloudflareUUIDPattern.MatchString(request.TargetID) {
		return RollbackTarget{}, errors.New("explicit Cloudflare rollback target UUID is required")
	}
	versions := executor.Run(ctx, opsexec.Request{
		Program: "node_modules/.bin/wrangler", Args: []string{"versions", "list", "--json", "--config", request.WranglerConfig},
		Directory: request.SourcePath, Timeout: request.Timeout,
	})
	var versionItems []struct {
		ID string `json:"id"`
	}
	if versions.Err != nil || versions.TimedOut || versions.ExitCode != 0 || json.Unmarshal([]byte(versions.Stdout), &versionItems) != nil {
		return RollbackTarget{}, errors.New("Cloudflare rollback version lookup failed")
	}
	for _, version := range versionItems {
		if version.ID == request.TargetID {
			return RollbackTarget{VersionID: version.ID}, nil
		}
	}
	deployments, err := readDeployments(ctx, executor, request.SourcePath, request.WranglerConfig, request.Timeout, "list")
	if err != nil {
		return RollbackTarget{}, err
	}
	for _, deployment := range deployments {
		if deployment.ID != request.TargetID {
			continue
		}
		if len(deployment.Versions) != 1 || deployment.Versions[0].Percentage != 100 {
			return RollbackTarget{}, errors.New("Cloudflare rollback deployment must contain a single 100% version")
		}
		return RollbackTarget{VersionID: deployment.Versions[0].VersionID, DeploymentID: deployment.ID}, nil
	}
	return RollbackTarget{}, errors.New("Cloudflare rollback target was not found")
}

func CreateRollbackPlan(ctx context.Context, executor opsexec.Executor, request RollbackPlanRequest) (CloudflareRollbackPlan, error) {
	if ctx == nil || executor == nil {
		return CloudflareRollbackPlan{}, errors.New("Cloudflare rollback planning inputs are incomplete")
	}
	if err := validatePlanRequest(PlanRequest{Service: request.Service, RequestedVersion: "rollback", Git: request.Git, Preflight: request.Preflight, RepositorySourcePath: request.RepositorySourcePath, DeploymentInputSHA256: request.DeploymentInputSHA256}); err != nil {
		return CloudflareRollbackPlan{}, err
	}
	preflight, err := Inspect(ctx, executor, request.Preflight)
	if err != nil {
		return CloudflareRollbackPlan{}, err
	}
	configContent, err := readRegularFile(filepath.Join(request.Preflight.SourcePath, request.Preflight.WranglerConfig), "Wrangler config")
	if err != nil {
		return CloudflareRollbackPlan{}, err
	}
	configDigest := sha256.Sum256(configContent)
	target, err := ResolveRollbackTarget(ctx, executor, RollbackTargetRequest{
		SourcePath: request.Preflight.SourcePath, WranglerConfig: request.Preflight.WranglerConfig,
		TargetID: request.TargetID, Timeout: request.Preflight.Timeout,
	})
	if err != nil {
		return CloudflareRollbackPlan{}, err
	}
	current, err := readCurrentDeployment(ctx, executor, request.Preflight.SourcePath, request.Preflight.WranglerConfig, request.Preflight.Timeout)
	if err != nil {
		return CloudflareRollbackPlan{}, err
	}
	currentVersions := deploymentVersionIDs(current)
	blocked := request.RequireCommittedScope && request.Git.State != opsgit.StateClean
	blockReason := ""
	if blocked {
		blockReason = "deployment scope contains uncommitted changes"
	} else if len(currentVersions) == 1 && currentVersions[0] == target.VersionID {
		blocked = true
		blockReason = "rollback target is already active"
	}
	return CloudflareRollbackPlan{
		Service: request.Service, Environment: cloudflareProductionEnvironment,
		Worker: preflight.Worker, AccountID: preflight.AccountID,
		WranglerConfig: preflight.WranglerConfig, WranglerConfigSHA256: hex.EncodeToString(configDigest[:]), WranglerVersion: preflight.WranglerVersion,
		BaseCommit: request.Git.BaseCommit, ScopeState: request.Git.State, ScopeContentSHA256: request.Git.ContentSHA256,
		DeploymentInputSHA256: request.DeploymentInputSHA256,
		ScopeEntries:          append([]opsgit.Entry(nil), request.Git.Entries...), RequireCommittedScope: request.RequireCommittedScope,
		RequestedTargetID: request.TargetID, TargetVersionID: target.VersionID, TargetDeploymentID: target.DeploymentID,
		CurrentDeploymentID: current.ID, CurrentVersionIDs: currentVersions, TargetVerified: true,
		Blocked: blocked, BlockReason: blockReason, SourcePath: request.Preflight.SourcePath, Timeout: request.Preflight.Timeout,
	}, nil
}

func RollbackCanonicalJSON(plan CloudflareRollbackPlan) ([]byte, error) {
	normalized := plan
	normalized.SourcePath = ""
	normalized.Timeout = 0
	normalized.ScopeEntries = append([]opsgit.Entry(nil), plan.ScopeEntries...)
	sort.Slice(normalized.ScopeEntries, func(i, j int) bool {
		if normalized.ScopeEntries[i].Path != normalized.ScopeEntries[j].Path {
			return normalized.ScopeEntries[i].Path < normalized.ScopeEntries[j].Path
		}
		return normalized.ScopeEntries[i].OriginalPath < normalized.ScopeEntries[j].OriginalPath
	})
	normalized.CurrentVersionIDs = append([]string(nil), plan.CurrentVersionIDs...)
	sort.Strings(normalized.CurrentVersionIDs)
	return json.Marshal(normalized)
}

func RollbackDigest(plan CloudflareRollbackPlan) (string, error) {
	canonical, err := RollbackCanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func ConfirmRollbackPlan(plan CloudflareRollbackPlan, providedDigest string) (ConfirmedRollbackPlan, error) {
	if plan.Blocked || !plan.TargetVerified {
		return ConfirmedRollbackPlan{}, errors.New("Cloudflare rollback plan cannot be confirmed")
	}
	digest, err := RollbackDigest(plan)
	if err != nil || providedDigest == "" || digest != providedDigest {
		return ConfirmedRollbackPlan{}, errors.New("Cloudflare rollback preview digest is stale")
	}
	return ConfirmedRollbackPlan{Plan: plan, Digest: digest}, nil
}

type RollbackWriter interface {
	Rollback(context.Context, opscloudflarepayload.RollbackRequest) (opscloudflarepayload.Evidence, error)
}

func ConfirmProductionRollback(plan CloudflareRollbackPlan, request opscloudflarepayload.RollbackRequest, identity ProductionConfirmationIdentity, providedDigest string) (ConfirmedProductionRollbackPlan, error) {
	if plan.Blocked || !plan.TargetVerified {
		return ConfirmedProductionRollbackPlan{}, errors.New("Cloudflare production rollback cannot be confirmed")
	}
	digest, err := RollbackProductionDigest(plan, request, identity)
	if err != nil || providedDigest == "" || providedDigest != digest {
		return ConfirmedProductionRollbackPlan{}, errors.New("Cloudflare production rollback confirmation is stale")
	}
	owned, err := opscloudflarepayload.OwnRollbackRequest(request)
	if err != nil {
		return ConfirmedProductionRollbackPlan{}, errors.New("Cloudflare production rollback request is invalid")
	}
	identity.EndpointSequence = append([]string(nil), identity.EndpointSequence...)
	return ConfirmedProductionRollbackPlan{plan: plan, request: owned, identity: identity, digest: digest}, nil
}

func ApplyRollback(ctx context.Context, writer RollbackWriter, confirmed ConfirmedProductionRollbackPlan) (RollbackResult, error) {
	if ctx == nil || writer == nil {
		return RollbackResult{}, errors.New("Cloudflare rollback apply inputs are incomplete")
	}
	digest, err := RollbackProductionDigest(confirmed.plan, confirmed.request, confirmed.identity)
	if err != nil || digest != confirmed.digest {
		return RollbackResult{}, errors.New("Cloudflare rollback confirmation is invalid")
	}
	evidence, err := writer.Rollback(ctx, confirmed.request)
	if err != nil {
		return rollbackResultFromEvidence(evidence), errors.New("Cloudflare trusted rollback failed")
	}
	if !cloudflareUUIDPattern.MatchString(evidence.RequestID) || evidence.RequestID == confirmed.plan.CurrentDeploymentID || evidence.InputSHA256 != confirmed.request.ExpectedSHA256 || len(evidence.VersionIDs) != 1 || evidence.VersionIDs[0] != confirmed.plan.TargetVersionID {
		return rollbackResultFromEvidence(evidence), errors.New("Cloudflare rollback active deployment verification failed")
	}
	return RollbackResult{Success: true, ProductionWriteSucceeded: true, DeploymentID: evidence.RequestID, VersionID: evidence.VersionIDs[0]}, nil
}

func rollbackResultFromEvidence(evidence opscloudflarepayload.Evidence) RollbackResult {
	result := RollbackResult{ProductionWriteSucceeded: evidence.RemoteWritePossible}
	if !evidence.RemoteWritePossible {
		return result
	}
	result.DeploymentID = evidence.RequestID
	if len(evidence.VersionIDs) == 1 {
		result.VersionID = evidence.VersionIDs[0]
	}
	return result
}

type deploymentRecord struct {
	ID       string `json:"id"`
	Versions []struct {
		VersionID  string  `json:"version_id"`
		Percentage float64 `json:"percentage"`
	} `json:"versions"`
}

func readDeployments(ctx context.Context, executor opsexec.Executor, sourcePath, config string, timeout time.Duration, command string) ([]deploymentRecord, error) {
	result := executor.Run(ctx, opsexec.Request{
		Program: "node_modules/.bin/wrangler", Args: []string{"deployments", command, "--json", "--config", config},
		Directory: sourcePath, Timeout: timeout,
	})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return nil, errors.New("Cloudflare deployment identity lookup failed")
	}
	var deployments []deploymentRecord
	if command == "status" {
		var deployment deploymentRecord
		if json.Unmarshal([]byte(result.Stdout), &deployment) != nil {
			return nil, errors.New("Cloudflare deployment identity response is malformed")
		}
		deployments = []deploymentRecord{deployment}
	} else if json.Unmarshal([]byte(result.Stdout), &deployments) != nil {
		return nil, errors.New("Cloudflare deployment identity response is malformed")
	}
	for _, deployment := range deployments {
		if !cloudflareUUIDPattern.MatchString(deployment.ID) || len(deployment.Versions) == 0 {
			return nil, errors.New("Cloudflare durable deployment identity is missing")
		}
		seenVersions := make(map[string]struct{}, len(deployment.Versions))
		totalTraffic := 0.0
		for _, version := range deployment.Versions {
			if !cloudflareUUIDPattern.MatchString(version.VersionID) || version.Percentage < 0 || version.Percentage > 100 {
				return nil, errors.New("Cloudflare durable deployment identity is missing")
			}
			if _, duplicate := seenVersions[version.VersionID]; duplicate {
				return nil, errors.New("Cloudflare durable deployment identity is missing")
			}
			seenVersions[version.VersionID] = struct{}{}
			totalTraffic += version.Percentage
		}
		if math.Abs(totalTraffic-100) > 0.000001 {
			return nil, errors.New("Cloudflare durable deployment identity is missing")
		}
	}
	return deployments, nil
}

func readCurrentDeployment(ctx context.Context, executor opsexec.Executor, sourcePath, config string, timeout time.Duration) (deploymentRecord, error) {
	deployments, err := readDeployments(ctx, executor, sourcePath, config, timeout, "status")
	if err != nil || len(deployments) != 1 {
		return deploymentRecord{}, errors.New("Cloudflare active deployment identity lookup failed")
	}
	return deployments[0], nil
}

func deploymentVersionIDs(deployment deploymentRecord) []string {
	versions := make([]string, 0, len(deployment.Versions))
	for _, version := range deployment.Versions {
		versions = append(versions, version.VersionID)
	}
	sort.Strings(versions)
	return versions
}
