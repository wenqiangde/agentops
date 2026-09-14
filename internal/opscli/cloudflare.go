package opscli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/wenqiangde/agentops/internal/opscloudflare"
	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
	"github.com/wenqiangde/agentops/internal/opsgit"
)

var opsCloudflareExecutor = func() opsexec.Executor { return opsexec.NewLocalExecutor() }

func opsCloudflareDeploy(service opsconfig.Service, production opsconfig.Environment, requestedVersion string, confirm bool, timeout time.Duration, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	gitEvidence, err := opsgit.Inspect(ctx, opsgit.Request{
		RepositoryRoot: service.Source.RepositoryRoot,
		Scopes:         service.Source.DeploymentScope,
	})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare Git scope inspection failed")
		return 1
	}
	plan, err := opscloudflare.CreatePlan(ctx, opsCloudflareExecutor(), opscloudflare.PlanRequest{
		Service: service.ID, RequestedVersion: requestedVersion,
		Git: gitEvidence,
		Preflight: opscloudflare.Request{
			SourcePath: service.Source.Path, Worker: production.Worker,
			AccountID: production.AccountID, WranglerConfig: production.WranglerConfig,
			Timeout: timeout,
		},
		RequireCommittedScope: service.Deployment.RequireCommittedScope,
	})
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview failed")
		return 1
	}
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview encoding failed")
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	if plan.Blocked {
		fmt.Fprintf(stderr, "agentops: Cloudflare deployment preview blocked: %s\n", plan.BlockReason)
		return 1
	}
	digest, err := opscloudflare.Digest(plan)
	if err != nil {
		fmt.Fprintln(stderr, "agentops: Cloudflare deployment preview digest failed")
		return 1
	}
	fmt.Fprintf(stdout, "preview-digest: %s\n", digest)
	if confirm {
		fmt.Fprintln(stderr, "agentops: confirmed Cloudflare deployment is not available")
		return 1
	}
	return 0
}
