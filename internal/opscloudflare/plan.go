package opscloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
)

const cloudflareProductionEnvironment = "production"

var (
	commitPattern           = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	lowercaseSHA256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestedVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,127}$`)
)

type PlanRequest struct {
	Service               string
	RequestedVersion      string
	Git                   opsgit.Evidence
	Preflight             Request
	RequireCommittedScope bool
}

type CloudflareDeployPlan struct {
	Service               string         `json:"service"`
	Environment           string         `json:"environment"`
	RequestedVersion      string         `json:"requested_version"`
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
	DryRunVerified        bool           `json:"dry_run_verified"`
	Blocked               bool           `json:"blocked"`
	BlockReason           string         `json:"block_reason,omitempty"`
	SourcePath            string         `json:"-"`
	Timeout               time.Duration  `json:"-"`
}

func CreatePlan(ctx context.Context, executor opsexec.Executor, request PlanRequest) (CloudflareDeployPlan, error) {
	if ctx == nil || executor == nil {
		return CloudflareDeployPlan{}, errors.New("Cloudflare deployment planning inputs are incomplete")
	}
	if err := validatePlanRequest(request); err != nil {
		return CloudflareDeployPlan{}, err
	}
	preflight, err := Inspect(ctx, executor, request.Preflight)
	if err != nil {
		return CloudflareDeployPlan{}, err
	}
	configPath := filepath.Join(request.Preflight.SourcePath, request.Preflight.WranglerConfig)
	configBefore, err := readRegularFile(configPath, "Wrangler config")
	if err != nil {
		return CloudflareDeployPlan{}, err
	}
	configDigest := sha256.Sum256(configBefore)

	blocked := request.RequireCommittedScope && request.Git.State != opsgit.StateClean
	plan := CloudflareDeployPlan{
		Service: request.Service, Environment: cloudflareProductionEnvironment,
		RequestedVersion: request.RequestedVersion,
		Worker:           preflight.Worker, AccountID: preflight.AccountID,
		WranglerConfig:       preflight.WranglerConfig,
		WranglerConfigSHA256: hex.EncodeToString(configDigest[:]),
		WranglerVersion:      preflight.WranglerVersion,
		BaseCommit:           request.Git.BaseCommit, ScopeState: request.Git.State,
		ScopeContentSHA256:    request.Git.ContentSHA256,
		ScopeEntries:          append([]opsgit.Entry(nil), request.Git.Entries...),
		RequireCommittedScope: request.RequireCommittedScope,
		Blocked:               blocked, SourcePath: request.Preflight.SourcePath, Timeout: request.Preflight.Timeout,
	}
	if blocked {
		plan.BlockReason = "deployment scope contains uncommitted changes"
		return plan, nil
	}

	dryRun := executor.Run(ctx, opsexec.Request{
		Program:   "node_modules/.bin/wrangler",
		Args:      []string{"deploy", "--dry-run", "--config", request.Preflight.WranglerConfig},
		Directory: request.Preflight.SourcePath, Timeout: request.Preflight.Timeout,
	})
	if dryRun.Err != nil || dryRun.TimedOut || dryRun.ExitCode != 0 {
		return CloudflareDeployPlan{}, errors.New("Cloudflare Wrangler dry-run failed")
	}
	configAfter, err := readRegularFile(configPath, "Wrangler config")
	if err != nil {
		return CloudflareDeployPlan{}, err
	}
	if after := sha256.Sum256(configAfter); after != configDigest {
		return CloudflareDeployPlan{}, errors.New("Wrangler config changed during deployment preview")
	}
	plan.DryRunVerified = true
	return plan, nil
}

func validatePlanRequest(request PlanRequest) error {
	if !requestedVersionPattern.MatchString(request.Service) || !requestedVersionPattern.MatchString(request.RequestedVersion) {
		return errors.New("Cloudflare deployment identity is invalid")
	}
	if request.Git.RepositoryRoot == "" || request.Preflight.SourcePath == "" {
		return errors.New("Cloudflare Git evidence is incomplete")
	}
	resolvedRoot, err := filepath.EvalSymlinks(request.Git.RepositoryRoot)
	if err != nil {
		return errors.New("Cloudflare Git repository root is unavailable")
	}
	resolvedSource, err := filepath.EvalSymlinks(request.Preflight.SourcePath)
	if err != nil {
		return errors.New("Cloudflare source path is unavailable")
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedSource)
	if err != nil || relative == ".." || filepath.IsAbs(relative) || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return errors.New("Cloudflare source path is outside the Git repository")
	}
	if !commitPattern.MatchString(request.Git.BaseCommit) || !lowercaseSHA256Pattern.MatchString(request.Git.ContentSHA256) {
		return errors.New("Cloudflare Git evidence is invalid")
	}
	if request.Git.State != opsgit.StateClean && request.Git.State != opsgit.StateDirty {
		return errors.New("Cloudflare Git scope state is invalid")
	}
	return nil
}

func CanonicalJSON(plan CloudflareDeployPlan) ([]byte, error) {
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
	return json.Marshal(normalized)
}

func Digest(plan CloudflareDeployPlan) (string, error) {
	canonical, err := CanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
