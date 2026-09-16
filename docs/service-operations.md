# Service Operations

AgentOps manages a small inventory of independently deployed services. It
supports explicit `local` and `production` environments, including SSH-hosted
services and Cloudflare Workers. It does not run a
daemon, discover credentials, provision infrastructure, manage containers, or
replace a full deployment platform.

```bash
brew install wenqiangde/agent-tools/agentops
```

This installation command becomes available after the first AgentOps release.

Command parsing and orchestration live in `internal/opscli`.

## Directory Layout

The default root is `~/.agentops/operations`. AgentOps resolves it in this
order:

1. `AGENTOPS_OPERATIONS`
2. `AGENTOPS_HOME` plus `/.agentops/operations`
3. the current user's `~/.agentops/operations`

AgentOps does not read or migrate AgentSetup configuration implicitly.

```text
~/.agentops/operations/
├── hosts.yaml
├── policies.yaml
├── services/
│   └── catalog-api.yaml
├── backups/
└── reports/
```

Keep one service in each file. The filename, without `.yaml`, must equal the service `id`.

For independent AgentOps ownership, declare the local source path directly:

```yaml
source:
  path: /Users/example/workspace/catalog-api
  repository: git@github.com:example/catalog-api.git
```

`path` must be an absolute canonical path other than filesystem root. Build and
deployment commands use it directly. `source.project` is not supported.

A Cloudflare Worker uses its deployed Worker identity, repository-scoped input,
and a project-relative Wrangler configuration path. It does not require or
permit a fabricated SSH host or server root:

```yaml
version: 1
id: example-relay
language: typescript
source:
  path: /Users/example/workspace/example/example-relay
  repository: git@github.com:example/example.git
  repositoryRoot: /Users/example/workspace/example
  deploymentScope:
    - example-relay
    - example-admin
deployment:
  requireCommittedScope: false
environments:
  local:
    kind: local
    runner: manual
  production:
    kind: cloudflare-workers
    runner: manual
    worker: example-relay
    accountId: 0123456789abcdef0123456789abcdef
    wranglerConfig: wrangler.jsonc
    apiProfile: wrangler-4.107-preveal-v1
    health:
      type: http
      url: https://api.example.com/health
      successStatuses: [200]
```

`source.path` must be inside `repositoryRoot`, and every deployment scope must
be a clean repository-relative path. The Worker project must declare Wrangler
in `package.json`, include a lockfile, and have an executable
`node_modules/.bin/wrangler`. AgentOps never falls back to an unpinned global
binary or `npx wrangler@latest`.

AgentOps snapshots only the declared `deploymentScope` entries, preserving
their paths relative to `repositoryRoot`. Wrangler still runs from the copied
`source.path`, so a Worker may reference a sibling build output such as
`../example-admin/dist` only when that sibling is also a declared deployment
scope. Undeclared siblings and symlinks that resolve outside the declared
scopes are rejected before Wrangler runs.

This mode supports inventory validation, listing, inspection, HTTP health,
preview-gated deployment, and version-based rollback. Cloudflare backup is not
available. Worker writes require the exact preview digest and produce a private
operation report.

## Hosts And Policies

`hosts.yaml` uses OpenSSH aliases. AgentOps passes the alias to the system `ssh`
and `scp` commands; connection details remain in `~/.ssh/config`.

```yaml
version: 1
hosts:
  prod-catalog:
    sshAlias: prod-catalog
    platform: ubuntu
    architecture: amd64
    allowedRoots: [/opt/apps]
    capabilities: [systemd, php-fpm, pm2]
```

```sshconfig
Host prod-catalog
  HostName 203.0.113.10
  User deploy
  IdentityFile ~/.ssh/catalog_deploy
```

`policies.yaml` defines bounded execution and retention:

```yaml
version: 1
execution:
  defaultTimeout: 30s
  healthTimeout: 10s
  batchConcurrency: 1
production:
  requirePreviewDigest: true
  requireCleanArtifactManifest: true
releases:
  retain: 3
backups:
  serverCopies: 1
  localCopies: 7
  requireEncryption: true
```

## Service File

`build` is optional. A build-less SSH service is observe-only: `build`,
`deploy`, and `rollback` fail before local or remote execution. A Cloudflare
Worker uses its project-local Wrangler workflow and therefore does not require
the SSH artifact build contract. When `build` is present, `adapter`, `command`,
`artifact`, and `manifest` are all required; do not use placeholders for an
existing in-place deployment workflow.

```yaml
version: 1
id: catalog-api
language: go
source:
  path: /Users/example/workspace/catalog-api
  repository: git@example.com:catalog/api.git
build:
  adapter: command
  command: ./scripts/build.sh
  artifact: dist/catalog-api.tar.gz
  manifest: dist/catalog-api.manifest.json
environments:
  local:
    kind: local
    runner: manual
    health:
      type: command
      command:
        program: /usr/bin/true
  production:
    kind: ssh
    host: prod-catalog
    root: /opt/apps/catalog-api
    runner: systemd
    unit: catalog-api.service
    config:
      files: [shared/config/app.env]
      requiredKeys: [DATABASE_URL]
      secretKeys: [DATABASE_PASSWORD]
    health:
      type: http
      url: http://127.0.0.1:8080/health
      successStatuses: [200]
data:
  mysql:
    resource: catalog_db
    migrationCommand: ./migrate
    backupPolicy: before-migration
futureResources:
  redis:
    status: planned
    intendedRoles: [token-expiry]
```

Configuration contains identities and secret key names, never passwords, tokens, private keys, or secret values.

## Read-Only Inspection

```bash
agentops validate all
agentops validate catalog-api
agentops list
agentops list --language go --host prod-catalog
agentops inspect catalog-api --environment local
agentops inspect catalog-api --environment production
agentops health catalog-api --environment local
agentops health all --environment production
```

`validate`, `list`, and `inspect` do not change service state. Built-in HTTP, TCP, and process health probes are observational. A command probe executes its declared argv, so the configuration owner must ensure that command is read-only. All-service health runs sequentially and reports each failure independently.

## Runner Contracts

| Runner | Required environment fields | Runtime requirement | Write behavior |
|---|---|---|---|
| `systemd` | `unit` | Host capability `systemd`; machine-readable `systemctl` output | Start/stop/restart the declared unit |
| `php-fpm` | `service`, `configOwner`, absolute `configPath` | Host capability `php-fpm`; `FragmentPath` and declared config ownership must match | Deploy and rollback use graceful reload of the declared service after identity validation |
| `pm2` | `app`, `configOwner`, absolute `configPath` | Host capability `pm2`; machine-readable state and config ownership | Operate only the uniquely declared app |
| `process` | `user`, safe `command`, `pidfile`, `logs`, graceful `shutdownSignal` | `start-stop-daemon`, owned regular pidfile, matching executable and user | Use the declared process identity and graceful signal |
| `manual` | no lifecycle identity | Operator-owned process or Cloudflare Worker | Inspection reports `manual`; automatic lifecycle writes are rejected |

Every production environment requires a canonical absolute `root` strictly below one of its host's `allowedRoots`. When `allowedRoots` is omitted, it defaults to `[/opt/apps]` for backward compatibility. Declare an existing layout explicitly, for example `allowedRoots: [/home/maidou/projects/www]`; `/` and an allowed root itself are never valid service roots. Local environments prohibit `root`. A local process `command` must be a canonical absolute path; production may use a safe absolute command or a command relative to its `root`. Production `systemd`, `php-fpm`, and `pm2` runners must be supported by the selected host capability list. Pidfile and log paths must be canonical absolute paths. Runner inspection never treats ambiguous or malformed state as healthy.

## Builds And Manifests

`agentops build catalog-api` runs the project-owned build command from the
service's configured `source.path`. The command must update both the archive and
manifest. The manifest is immutable deployment input:

```json
{
  "service": "catalog-api",
  "version": "1.2.3",
  "commit": "0123456789abcdef",
  "built_at": "2026-09-12T12:00:00Z",
  "platform": "linux",
  "architecture": "amd64",
  "sha256": "64-lowercase-hex-characters"
}
```

AgentOps rejects stale outputs, mismatched service/version/target data, unsafe archive entries, changed files, and digest mismatches.

## Production Preview And Confirmation

Production deployment and rollback are two-step operations. First generate a normalized preview:

```bash
agentops deploy catalog-api --environment production --version 1.2.3
agentops rollback catalog-api --environment production --version 1.2.2
```

Review the service, host, version, health route, migration compatibility, steps, recovery action, and `preview-digest`. Then run the same command with the exact digest:

```bash
agentops deploy catalog-api --environment production --version 1.2.3 \
  --confirm --preview-digest <64-lowercase-hex>
```

Any material input change invalidates confirmation. Deployment uploads to an immutable release directory, verifies the remote digest, switches the current release atomically, activates the declared runner, verifies health, and attempts recovery on failure. A `systemd` application unit is restarted. A `php-fpm` transaction executes the digest-bound contract below for both activation and recovery:

```text
systemctl show <service> --property=ActiveState,SubState,MainPID,FragmentPath --no-pager
stat -c '%F %U' -- <configPath>
systemctl reload <service>
systemctl show <service> --property=ActiveState,SubState,MainPID,FragmentPath --no-pager
stat -c '%F %U' -- <configPath>
```

The observed `FragmentPath` must equal `configPath`, the path must be a regular file owned by `configOwner`, and post-reload state must be active with a positive PID. Any mismatch stops before reload or enters recovery after activation. Preview output records command digests and bounded identities rather than raw command output.

Nginx validation/reload and serving-path cutover remain separate operator-controlled work. A successful PHP-FPM release transaction does not implicitly edit or reload Nginx. A `manual`, `pm2`, or `process` runner never performs automatic deploy or rollback lifecycle writes under the current release transaction contract.

Binary rollback does not reverse database migrations. A rollback is blocked when data compatibility evidence is insufficient.

## Cloudflare Worker Lifecycle

For a configured Worker, deployment preview runs only bounded identity reads
and the project-local dry run:

```text
node_modules/.bin/wrangler --version
node_modules/.bin/wrangler whoami --account <account-id> --json
node_modules/.bin/wrangler deployments status --json --config <file>
node_modules/.bin/wrangler deploy --dry-run --outdir .agentops-production-bundle --config <file>
```

Generate and review a preview:

```bash
agentops deploy example-relay --environment production --version 2026.09.14-1
```

Successful deployment previews include bounded diagnostics for `git-inspect`,
`snapshot`, `wrangler-version`, `account-membership`, and `dry-run`. Each entry
contains a stable stage code, elapsed duration in nanoseconds, timeout
classification, one correlation ID shared by that preview, and a fixed safe
remediation message. Runtime diagnostics are excluded from the canonical
preview digest, so elapsed time and correlation ID changes do not invalidate an
otherwise identical plan.

The preview binds the active deployment ID and version IDs. The trusted SDK
transport reads domains, schedules, and the latest active deployment again
immediately before its first asset, version, or deployment write. Any endpoint
or deployment identity drift, timeout, or malformed response fails before a
write. Deploy and rollback both retain a separate post-write deployment
identity readback.

When the canonical profile contains Durable Object migrations, confirmation
also binds the complete ordered local history, the `ordered-history-v1`
derivation policy, the allowed remote-state classes, and one sorted version
detail read per confirmed active version. After confirmation, the trusted SDK
requires every active version to expose the same absent, null, or known local
migration tag, derives only the pending suffix, and repeats the deployment
identity read before its first write. Unknown, empty, divergent, or mismatched
state fails closed. One pending step uses the typed single-step API; multiple
steps use the ordered multi-step API; an already-current Worker omits migration
metadata. The no-assets upload path does not accept migrations.

An external-stage failure prints the same bounded fields as a single diagnostic
line. It never includes raw Wrangler stdout/stderr, tokens, the complete account
ID, source content, or arbitrary command details. Each external stage receives
its own configured timeout budget; time consumed by an earlier stage does not
reduce a later stage's budget. Timeout classification is `none`,
`deadline-exceeded`, or `cancelled` for the active stage.

Cloudflare production routing requires the supported `apiProfile`, the exact
production preview digest, and the reviewed trusted API client. The client reads
its credential only from the inherited `AGENTOPS_CLOUDFLARE_API_TOKEN`
environment variable after confirmation. A missing or invalid profile, missing
or stale digest, missing token, payload mismatch, or unavailable trusted client
fails closed. The token must not be stored in service YAML, argv, reports, or
project files. SSH deployment and rollback are unaffected.

The `wrangler-4.107-preveal-v1` profile accepts only stable Wrangler `4.107.x`
versions. Earlier, later, prerelease, or otherwise mismatched versions fail
before dry-run output can become a production payload. Wrangler writes its
bundled Worker into the controlled snapshot output directory. This profile is
deliberately narrower than general Wrangler module rules: AgentOps captures
exactly one generated JavaScript main module, zero or more generated WASM
modules, and approved assets into owned memory. Text, data, CommonJS, Python,
and other Wrangler module kinds are unsupported by this profile and fail closed.
Wrangler's root `README.md` and the main module's matching `.map` are local
dry-run metadata and are not uploaded because this profile does not enable
source-map upload.
It never substitutes the configured TypeScript or JavaScript source entry for
the generated bundle. Symlinks, missing bundles, ambiguous multiple modules,
and unsupported output files fail closed. The temporary bundle directory is
removed after capture so snapshot sealing continues to validate only the
original approved source snapshot.

Wrangler remains a pre-confirmation version,
membership, and dry-run tool only. A production confirmation owns copied module,
asset, metadata, or rollback-request values and binds the API profile, pinned
client version, ordered endpoint sequence, and the fixed token-provider identity
into a separate canonical digest. Token bytes and token hashes never enter that
material. The production action re-computes the digest immediately before the
typed Cloudflare API writer; a stale or mutated value stops with no writer call
and no project path is reopened. Opening this routing capability does not
authorize a production operation: the first real deploy or rollback still
requires the separately approved, digest-specific rehearsal procedure.

The endpoint sequence is derived from the canonical profile and owned payload;
callers cannot supply an alternate, shorter, reordered, or additional sequence.
Custom-domain and cron state is always read and compared for exact equality
before the first write, including when the local declarations are empty. This
profile never creates, updates, or deletes those endpoints. Any mismatch fails
closed. Every successful version/deployment operation is
followed by a deployment GET that must prove the expected single version at
100 percent traffic. A no-assets Worker that includes bindings, variables, or
migrations not representable by the selected typed SDK endpoint fails before
network access instead of silently dropping configuration.

The preview copies every declared deployment scope into a private controlled
snapshot rooted at the repository layout, including ignored build output and
project-local dependencies. Wrangler runs from the snapshot copy of
`source.path`. The resolved source, config, Wrangler `main`, assets/site
directories, and build working directories must remain inside the declared
snapshot scopes. Internal npm links such as `node_modules/.bin/wrangler` are
rewritten into the snapshot; links resolving outside the declared scopes are
rejected. These checks support preview integrity but do not by themselves
authorize a production write.

Rollback requires an explicit Worker version UUID or a deployment UUID that
maps unambiguously to one version at 100% traffic:

```bash
agentops rollback example-relay --environment production \
  --version aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
```

AgentOps resolves the target from Wrangler JSON, rejects an already-active or
ambiguous target, and verifies that rollback created a new deployment serving
the selected version at 100% before checking HTTP health. The command does not
restore KV, D1, R2, Durable Objects, queues, or other bound resource state.
Target discovery uses `versions list --json` and, when needed,
`deployments list --json`. Production rollback confirmation remains behind the
same closed security gate as deployment confirmation.

### Git Scope And Frozen Input

Repository cleanliness and frozen deployment input are separate concepts:

- Changes outside `deploymentScope` do not affect this Worker plan.
- `requireCommittedScope: true` blocks when any scoped path differs from the
  base commit.
- `requireCommittedScope: false` permits scoped tracked or untracked changes,
  but their paths, kinds, and content hashes are included in the preview
  digest. It does not mean "deploy whatever exists later."
- Any scoped bytes, Wrangler config, account membership, Worker identity,
  Wrangler version, base commit, or requested version change requires a new
  preview and digest.
- Ignored files are absent from Git cleanliness evidence but remain part of the
  complete deployment snapshot digest when they are inside a declared scope.

### Remediation And Stop Conditions

- Missing installed Wrangler with a declared dependency and lockfile: run
  `npm ci` in `source.path`, then preview again.
- Authentication or account-membership failure: use Wrangler to authenticate
  the intended operator account, then verify that AgentOps `accountId`, the
  Wrangler config `account_id`, and authenticated membership agree.
- Dirty scope blocked by policy: commit the intended scoped change or obtain an
  approved configuration change to `requireCommittedScope`; never bypass the
  digest.
- Stale digest, missing target, malformed JSON identity, failed health, or
  report persistence failure: stop and inspect the bounded error/report before
  creating a new preview.
- Typed Cloudflare reports distinguish `succeeded`, `known-failure`,
  `unknown-state`, and `health-failure`. A known failure before a write is
  terminal for that attempt and may be retried only after correction. Missing
  durable identity after a possible write, including rollback identity mismatch,
  is non-terminal `unknown-state` and requires remote inspection before retry.
  Transport evidence marks every operation after a potentially accepted remote
  write and preserves any known deployment/version IDs even when a later request
  fails; client and apply layers must not erase that evidence. CLI failure paths
  persist those IDs through the typed Cloudflare `unknown-state` report schema,
  rather than a generic terminal failure report.
  Health failure is recorded separately and requires an explicit rollback
  decision; it never triggers rollback automatically.
- Cloudflare reports contain bounded stage evidence and durable deployment or
  version UUIDs, never token values, raw Wrangler output, `.dev.vars`, source
  bytes, module bytes, or asset bytes. Files use mode `0600`. If the primary
  report root is unavailable, the existing fallback writes to a private sibling
  `emergency-reports-<random>` directory created atomically. A predictable
  pre-existing link is never followed; failure of both locations leaves the
  production state unknown and must be surfaced to the operator.

AgentOps does not install dependencies, run Wrangler login, stage/commit/push
Git changes, create secrets, apply D1 migrations, or infer a rollback target.
Do not place API tokens, OAuth credentials, `.dev.vars` values, secret values,
or raw command output in inventory files, command arguments, or reports.
Preview output masks the Cloudflare account ID; its complete value remains only
in the validated runtime configuration and private operation report.

## Encrypted Database Recovery

Backup also uses preview and exact-digest confirmation. It checks `age` remotely, streams `mysqldump --single-transaction --quick` directly into recipient encryption, transfers only the `.age` archive, and compares server/local SHA-256 digests. No plaintext SQL dump is written.

```bash
agentops backup catalog-api --environment production \
  --archive-id 20260912T120000Z \
  --age-recipient '<age-public-recipient>' \
  --mysql-option-file /run/secrets/catalog-backup.cnf \
  --restore-age-identity /Users/example/.config/age/keys.txt \
  --restore-option-file /Users/example/.config/mysql/restore.cnf \
  --restore-socket /tmp/catalog-restore/mysql.sock \
  --restore-hostname catalog-restore \
  --restore-port 3307 \
  --restore-database agentsetup_restore_20260912_a1b2 \
  --integrity-query 'SELECT COUNT(*) FROM migrations'
```

The restore rehearsal is local-only: every MySQL command is forced through the confirmed Unix socket, the observed hostname/port must match the preview and differ from production, and the temporary database is dropped afterward. Integrity checks accept only `SELECT COUNT(*) FROM <table>` queries. Retention starts only after successful restoration and affects only managed `<resource>-<archive-id>.sql.age` files.

Never copy the age private identity to production. MySQL option files must be protected by local/server filesystem permissions.

## Stop Conditions And Evidence

AgentOps stops before writes when inventory validation fails, the SSH alias or runner identity is ambiguous, credentials appear in configuration, build evidence is stale, remote preflight fails, a digest is stale, migration compatibility is missing, recovery identity is unsafe, or a report cannot be persisted.

Private JSON reports are written under `operations/reports` with mode `0600`. They contain bounded step, health, digest, recovery, and timing evidence without raw command output or credential values.

Automated tests and local fake-backed checks cover the current implementation. No production deploy or rollback is part of release verification. A real production operation remains pending the separately authorized, digest-specific rehearsal and must not be inferred from installation, configuration, release, or a prior review approval.
