package opscloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type ConfirmedPlan struct {
	Plan   CloudflareDeployPlan
	Digest string
}

type ApplyResult struct {
	Success                  bool
	ProductionWriteSucceeded bool
	DeploymentID             string
	VersionIDs               []string
}

var cloudflareUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func Confirm(plan CloudflareDeployPlan, providedDigest string) (ConfirmedPlan, error) {
	if plan.Blocked || !plan.DryRunVerified {
		return ConfirmedPlan{}, errors.New("Cloudflare deployment plan cannot be confirmed")
	}
	digest, err := Digest(plan)
	if err != nil {
		return ConfirmedPlan{}, errors.New("Cloudflare deployment plan digest failed")
	}
	if providedDigest == "" || providedDigest != digest {
		return ConfirmedPlan{}, errors.New("Cloudflare deployment preview digest is stale")
	}
	return ConfirmedPlan{Plan: plan, Digest: digest}, nil
}

func Apply(ctx context.Context, executor opsexec.Executor, confirmed ConfirmedPlan) (ApplyResult, error) {
	if ctx == nil || executor == nil {
		return ApplyResult{}, errors.New("Cloudflare deployment apply inputs are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	validated, err := Confirm(confirmed.Plan, confirmed.Digest)
	if err != nil || validated.Digest != confirmed.Digest || confirmed.Plan.SourcePath == "" || confirmed.Plan.Timeout <= 0 {
		return ApplyResult{}, errors.New("Cloudflare deployment confirmation is invalid")
	}
	before, err := collectDeployments(ctx, executor, confirmed.Plan)
	if err != nil {
		return ApplyResult{}, err
	}
	result := executor.Run(ctx, opsexec.Request{
		Program:   "node_modules/.bin/wrangler",
		Args:      []string{"deploy", "--config", confirmed.Plan.WranglerConfig},
		Directory: confirmed.Plan.SourcePath, Timeout: confirmed.Plan.Timeout,
	})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return ApplyResult{}, errors.New("Cloudflare Wrangler deployment failed")
	}
	writeResult := ApplyResult{ProductionWriteSucceeded: true}
	after, err := collectDeployments(ctx, executor, confirmed.Plan)
	if err != nil {
		return writeResult, err
	}
	deployment, err := findNewDeployment(before, after)
	if err != nil {
		return writeResult, err
	}
	writeResult.Success = true
	writeResult.DeploymentID = deployment.ID
	writeResult.VersionIDs = deployment.VersionIDs
	return writeResult, nil
}

type deploymentEvidence struct {
	ID         string
	VersionIDs []string
}

func collectDeployments(ctx context.Context, executor opsexec.Executor, plan CloudflareDeployPlan) ([]deploymentEvidence, error) {
	result := executor.Run(ctx, opsexec.Request{
		Program:   "node_modules/.bin/wrangler",
		Args:      []string{"deployments", "list", "--json", "--config", plan.WranglerConfig},
		Directory: plan.SourcePath, Timeout: plan.Timeout,
	})
	if result.Err != nil || result.TimedOut || result.ExitCode != 0 {
		return nil, errors.New("Cloudflare deployment identity lookup failed")
	}
	var payload []struct {
		ID       string `json:"id"`
		Versions []struct {
			VersionID string `json:"version_id"`
			ID        string `json:"id"`
		} `json:"versions"`
	}
	if json.Unmarshal([]byte(result.Stdout), &payload) != nil {
		return nil, errors.New("Cloudflare deployment identity response is malformed")
	}
	deployments := make([]deploymentEvidence, 0, len(payload))
	for _, item := range payload {
		if !cloudflareUUIDPattern.MatchString(item.ID) {
			return nil, errors.New("Cloudflare durable deployment identity is missing")
		}
		versions := make([]string, 0, len(item.Versions))
		for _, version := range item.Versions {
			id := version.VersionID
			if id == "" {
				id = version.ID
			}
			if !cloudflareUUIDPattern.MatchString(id) {
				return nil, errors.New("Cloudflare durable deployment identity is missing")
			}
			versions = append(versions, id)
		}
		if len(versions) == 0 {
			return nil, errors.New("Cloudflare durable deployment identity is missing")
		}
		sort.Strings(versions)
		deployments = append(deployments, deploymentEvidence{ID: item.ID, VersionIDs: versions})
	}
	return deployments, nil
}

func findNewDeployment(before, after []deploymentEvidence) (deploymentEvidence, error) {
	known := make(map[string]struct{}, len(before))
	for _, deployment := range before {
		known[deployment.ID] = struct{}{}
	}
	var added []deploymentEvidence
	for _, deployment := range after {
		if _, exists := known[deployment.ID]; !exists {
			added = append(added, deployment)
		}
	}
	if len(added) != 1 {
		return deploymentEvidence{}, errors.New("Cloudflare durable deployment identity is missing or ambiguous")
	}
	return added[0], nil
}
