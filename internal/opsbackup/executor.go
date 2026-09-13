package opsbackup

import (
	"context"

	"github.com/wenqiangde/agentops/internal/opsexec"
)

type RoutedExecutor struct {
	Remote Executor
	Local  Executor
}

func NewRoutedExecutor(remote, local Executor) *RoutedExecutor {
	return &RoutedExecutor{Remote: remote, Local: local}
}

func (e *RoutedExecutor) Run(ctx context.Context, request opsexec.Request) opsexec.Result {
	if request.HostAlias == "" {
		return e.Local.Run(ctx, request)
	}
	return e.Remote.Run(ctx, request)
}

func (e *RoutedExecutor) Pipeline(ctx context.Context, request opsexec.PipelineRequest) opsexec.Result {
	if request.HostAlias == "" {
		return e.Local.Pipeline(ctx, request)
	}
	return e.Remote.Pipeline(ctx, request)
}

func (e *RoutedExecutor) Copy(ctx context.Context, request opsexec.CopyRequest) opsexec.Result {
	return e.Remote.Copy(ctx, request)
}
