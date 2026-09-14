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
node_modules/.bin/wrangler deploy --dry-run --config <file>
```

Generate and review a preview before every production write:

```bash
agentops deploy example-relay --environment production --version 2026.09.14-1
agentops deploy example-relay --environment production --version 2026.09.14-1 \
  --confirm --preview-digest <64-lowercase-hex>
```

The preview and confirmed command each copy the complete Worker source into a
private controlled snapshot, including ignored build output and project-local
dependencies. Dry-run, deploy or rollback, and post-operation identity reads
all use that same snapshot. The confirmed command also repeats Git, Wrangler,
account, and config checks and runs `wrangler deploy --config <file>` only when
the snapshot digest and recomputed plan match the supplied digest. After the
dry-run, AgentOps recomputes the snapshot digest and removes write permission
before any production command. The resolved
`source.path` and nested config must remain inside their resolved roots. Internal
npm links such as `node_modules/.bin/wrangler` are rewritten into the snapshot;
links resolving outside the source are rejected. Wrangler `main`, assets/site
directories, and build working directories must be clean relative paths inside
the snapshot. Success additionally requires one new
machine-readable deployment UUID, valid version UUID evidence, configured HTTP
health, and a mode-`0600` report. Raw Wrangler output is not report content.
AgentOps compares machine-readable output from
`wrangler deployments list --json --config <file>` before and after deployment;
a zero exit code without exactly one new durable deployment is a failure.

Rollback requires an explicit Worker version UUID or a deployment UUID that
maps unambiguously to one version at 100% traffic:

```bash
agentops rollback example-relay --environment production \
  --version aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
agentops rollback example-relay --environment production \
  --version aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa \
  --confirm --preview-digest <64-lowercase-hex>
```

AgentOps resolves the target from Wrangler JSON, rejects an already-active or
ambiguous target, and verifies that rollback created a new deployment serving
the selected version at 100% before checking HTTP health. The command does not
restore KV, D1, R2, Durable Objects, queues, or other bound resource state.
Target discovery uses `versions list --json` and, when needed,
`deployments list --json`. Confirmation runs
`rollback <version-id> --message <bounded-message> --config <file>`, then
verifies `deployments status --json`.

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
  complete source snapshot digest when they can be read from `source.path`.

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
- If Wrangler reports a successful production write but durable deployment
  identity verification fails, AgentOps writes a terminal mode-`0600` failure
  report and requires manual Cloudflare state inspection before any retry. If
  the primary report root is unavailable, it writes to a private sibling
  `emergency-reports-<random>` directory created atomically and prints that
  path. A predictable pre-existing link is never followed.

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

Automated tests and a local read-only smoke test cover the current implementation. A real-host read-only pilot and all real production writes remain pending explicit authorization; this feature is not yet declared production-ready.
