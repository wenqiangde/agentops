package opscloudflare

import (
	"context"
	"errors"
	"regexp"

	"github.com/wenqiangde/agentops/internal/opscloudflarepayload"
)

type ConfirmedPlan struct {
	Plan   CloudflareDeployPlan
	Digest string
}

type ConfirmedProductionPlan struct {
	plan     CloudflareDeployPlan
	request  opscloudflarepayload.Request
	identity ProductionConfirmationIdentity
	digest   string
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

type DeploymentWriter interface {
	Deploy(context.Context, opscloudflarepayload.Request) (opscloudflarepayload.Evidence, error)
}

func ConfirmProduction(plan CloudflareDeployPlan, request opscloudflarepayload.Request, identity ProductionConfirmationIdentity, providedDigest string) (ConfirmedProductionPlan, error) {
	if plan.Blocked || !plan.DryRunVerified {
		return ConfirmedProductionPlan{}, errors.New("Cloudflare production plan cannot be confirmed")
	}
	digest, err := ProductionDigest(plan, request, identity)
	if err != nil || providedDigest == "" || providedDigest != digest {
		return ConfirmedProductionPlan{}, errors.New("Cloudflare production confirmation is stale")
	}
	owned, err := opscloudflarepayload.OwnRequest(request)
	if err != nil {
		return ConfirmedProductionPlan{}, errors.New("Cloudflare production request is invalid")
	}
	identity.EndpointSequence = append([]string(nil), identity.EndpointSequence...)
	return ConfirmedProductionPlan{plan: plan, request: owned, identity: identity, digest: digest}, nil
}

func Apply(ctx context.Context, writer DeploymentWriter, confirmed ConfirmedProductionPlan) (ApplyResult, error) {
	if ctx == nil || writer == nil {
		return ApplyResult{}, errors.New("Cloudflare deployment apply inputs are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, err
	}
	digest, err := ProductionDigest(confirmed.plan, confirmed.request, confirmed.identity)
	if err != nil || digest != confirmed.digest {
		return ApplyResult{}, errors.New("Cloudflare deployment confirmation is invalid")
	}
	evidence, err := writer.Deploy(ctx, confirmed.request)
	if err != nil {
		return applyResultFromEvidence(evidence), errors.New("Cloudflare trusted deployment failed")
	}
	if !cloudflareUUIDPattern.MatchString(evidence.RequestID) || evidence.InputSHA256 != confirmed.request.ExpectedSHA256 || len(evidence.VersionIDs) != 1 || !cloudflareUUIDPattern.MatchString(evidence.VersionIDs[0]) {
		return ApplyResult{ProductionWriteSucceeded: true}, errors.New("Cloudflare durable deployment identity is missing")
	}
	return ApplyResult{Success: true, ProductionWriteSucceeded: true, DeploymentID: evidence.RequestID, VersionIDs: append([]string(nil), evidence.VersionIDs...)}, nil
}

func applyResultFromEvidence(evidence opscloudflarepayload.Evidence) ApplyResult {
	if !evidence.RemoteWritePossible {
		return ApplyResult{}
	}
	return ApplyResult{
		ProductionWriteSucceeded: true,
		DeploymentID:             evidence.RequestID,
		VersionIDs:               append([]string(nil), evidence.VersionIDs...),
	}
}
