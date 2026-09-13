# AgentOps

AgentOps is an independent command-line tool for operating application services.
It validates service inventories, builds release artifacts, checks health,
deploys releases, creates encrypted database backups, and performs rollbacks.

AgentOps is developed and released independently from AgentSetup. It does not
read AgentSetup project or registry configuration.

## Configuration

The default configuration root is `~/.agentops/operations`:

```text
~/.agentops/operations/
├── services/
├── hosts.yaml
├── policies.yaml
├── backups/
└── reports/
```

Set `AGENTOPS_HOME` to replace the home used by AgentOps, or set
`AGENTOPS_OPERATIONS` to select the operations directory directly.

Every managed service must declare an absolute source path:

```yaml
source:
  path: /absolute/path/to/service
  repository: git@github.com:owner/service.git
```

## Development

```bash
go test ./...
go build ./cmd/agentops
```

See [Service operations](docs/service-operations.md) for the configuration and
command reference.

## Releases

Pushing a semantic version tag such as `v1.0.0` runs the release workflow. It
tests the module, builds macOS and Linux binaries for AMD64 and ARM64, publishes
the binaries and checksums to this repository's GitHub Release, and updates
`Formula/agentops.rb` in `wenqiangde/homebrew-agentsetup`.

The repository requires a `HOMEBREW_TAP_TOKEN` Actions secret with permission
to update the Homebrew tap repository.
