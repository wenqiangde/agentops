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
	if err := validatePlanRequest(PlanRequest{Service: request.Service, RequestedVersion: "rollback", Git: request.Git, Preflight: request.Preflight}); err != nil {
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
		ScopeEntries: append([]opsgit.Entry(nil), request.Git.Entries...), RequireCommittedScope: request.RequireCommittedScope,
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

func ApplyRollback(ctx context.Context, executor opsexec.Executor, confirmed ConfirmedRollbackPlan) (RollbackResult, error) {
	if ctx == nil || executor == nil {
		return RollbackResult{}, errors.New("Cloudflare rollback apply inputs are incomplete")
	}
	validated, err := ConfirmRollbackPlan(confirmed.Plan, confirmed.Digest)
	if err != nil || validated.Digest != confirmed.Digest || confirmed.Plan.SourcePath == "" || confirmed.Plan.Timeout <= 0 {
		return RollbackResult{}, errors.New("Cloudflare rollback confirmation is invalid")
	}
	result := executor.Run(ctx, opsexec.Request{
		Program:   "node_modules/.bin/wrangler",
		Args:      []string{"rollback", confirmed.Plan.TargetVersionID, "--message", rollbackMessage, "--config", confirmed.Plan.WranglerConfig},
		Directory: confirmed.Plan.SourcePath, Timeout: confirmed.Plan.Timeout,
	})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return RollbackResult{}, errors.New("Cloudflare Wrangler rollback failed")
	}
	writeResult := RollbackResult{ProductionWriteSucceeded: true}
	current, err := readCurrentDeployment(ctx, executor, confirmed.Plan.SourcePath, confirmed.Plan.WranglerConfig, confirmed.Plan.Timeout)
	if err != nil || len(current.Versions) != 1 || current.Versions[0].VersionID != confirmed.Plan.TargetVersionID || current.Versions[0].Percentage != 100 || current.ID == confirmed.Plan.CurrentDeploymentID {
		return writeResult, errors.New("Cloudflare rollback active deployment verification failed")
	}
	writeResult.Success = true
	writeResult.DeploymentID = current.ID
	writeResult.VersionID = current.Versions[0].VersionID
	return writeResult, nil
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
