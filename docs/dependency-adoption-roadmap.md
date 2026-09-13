# AgentOps Dependency Adoption Roadmap

This document controls when AgentOps may add third-party Go dependencies. The
goal is to replace error-prone infrastructure only when a concrete capability
requires it, while keeping the operational binary auditable and portable.

The roadmap is ordered. A later stage is not authorized merely because an
earlier stage is complete. Each stage begins only when its entry condition is
met and receives its own implementation approval, tests, commit, and release.

## Baseline

AgentOps is independent from AgentSetup. It may use the same public Go library
when that library fits AgentOps, but it must not import AgentSetup packages or
inherit AgentSetup configuration.

Current direct dependencies:

| Dependency | Ownership | Purpose | Decision |
|---|---|---|---|
| `gopkg.in/yaml.v3` | Third party | Decode operations configuration | Keep |
| `golang.org/x/sys` | Go extended library | Unix-specific file and process checks | Keep |

The default decision for every proposed dependency is `do not add` until its
entry condition and acceptance criteria are satisfied.

## Stage 1: Standard CLI Contract

**Status:** awaiting verification

**Dependency:** `github.com/spf13/cobra`

**Problem:** The current handwritten root dispatcher exposes only a one-line
usage string. `agentops version` and `agentops --version` are not registered,
and release builds do not contain version provenance.

**Scope:**

- Replace only the top-level command routing and help generation with Cobra.
- Preserve the existing operational handlers and their safety behavior.
- Add standard `help`, `<command> --help`, `version`, and `--version` behavior.
- Add shell completion generation for Bash, Zsh, and Fish.
- Inject version, commit, build date, and channel through release linker flags.
- Update the Homebrew test to verify the released version as well as help.

**Compatibility constraints:**

- Existing command names, positional arguments, flags, output contracts, and
  exit codes must remain compatible unless a test records an intentional fix.
- Cobra must not execute an operational handler while rendering help.
- No AgentSetup source package may be imported.

**Required evidence:**

```text
agentops help
agentops help deploy
agentops --help
agentops version
agentops --version
agentops completion zsh
go test ./...
```

Release acceptance requires the installed Homebrew binary to report the tag,
commit, build date, and `github-release` channel embedded by CI. The target
release is `v1.1.0` because this adds user-visible CLI capabilities without
breaking the existing operations contract.

## Stage 2: Semantic Version Policy

**Status:** deferred until triggered

**Candidate:** `github.com/Masterminds/semver/v3`

**Entry condition:** AgentOps needs to compare versions rather than carry an
opaque release identifier. Examples include minimum AgentOps requirements,
upgrade or downgrade policy, pre-release channels, or version ranges.

**Scope when triggered:** Centralize version parsing and comparison in one
focused package. Do not scatter library calls through deploy and rollback
handlers. Preserve the original version string in reports and manifests.

**Required evidence:** Tests must cover strict releases, `v` prefixes,
pre-release ordering, invalid input, allowed rollback, blocked downgrade, and
the existing opaque-version behavior selected for migration.

**Stop condition:** Do not add this library merely to validate that a version
string is non-empty or safe for a path; current validation remains sufficient.

## Stage 3: Embedded Backup Encryption

**Status:** deferred; requires a separate security design

**Candidate:** `filippo.io/age`

**Entry condition:** A supported deployment must perform encrypted backup or
restore without an external `age` executable, or field evidence shows material
version drift in the external command.

**Scope when triggered:** Replace only the encryption/decryption boundary. Keep
streaming behavior, prohibit plaintext SQL files, retain digest verification,
and keep private identities off production hosts.

**Required evidence:** Threat-model review, known-vector tests, interrupted
stream tests, recipient and identity mismatch tests, file-permission checks,
large-stream memory bounds, and a real restore rehearsal in an isolated local
database.

**Stop condition:** Do not combine this work with CLI, deployment, retention,
or database migration changes. Cryptographic changes require their own release.

## Stage 4: Human-Readable Tables

**Status:** deferred until output becomes difficult to scan

**Candidate:** `github.com/jedib0t/go-pretty/v6/table`

**Entry condition:** Real inventories make `list`, `inspect`, or health output
hard to scan, and representative terminal-width tests show that aligned tables
improve operator decisions.

**Scope when triggered:** Apply tables only to interactive human output. Add or
preserve a stable machine-readable JSON mode before changing output that scripts
may consume. Non-TTY output must remain deterministic and free of color codes.

**Required evidence:** Narrow and wide terminal snapshots, long service and host
names, empty results, unhealthy states, non-TTY output, JSON compatibility, and
Light/Dark terminal readability.

**Stop condition:** Do not add a full terminal UI framework. AgentOps remains a
scriptable command-line tool.

## Stage 5: Complex Test Comparisons

**Status:** deferred until standard tests lose diagnostic clarity

**Candidate:** `github.com/google/go-cmp/cmp`

**Entry condition:** Repeated hand-written comparisons of nested plans,
manifests, or reports make failures difficult to diagnose or conceal relevant
field differences.

**Scope when triggered:** Use `cmp` only in tests. Define explicit options for
timestamps, unexported fields, and intentionally ignored values. Never make it
a runtime dependency.

**Required evidence:** At least one existing complex assertion becomes smaller
and its failure output becomes more precise without weakening field coverage.

**Stop condition:** Keep direct equality and focused assertions when they are
clearer than a structural diff.

## Dependencies Not Planned

| Dependency category | Decision | Reason |
|---|---|---|
| Configuration framework such as Viper | Do not add | Existing explicit YAML loading and validation avoids hidden precedence between files, environment variables, and defaults. |
| Logging framework | Do not add | Use the standard library `log/slog` if structured diagnostic logging becomes necessary. |
| Go SSH client | Do not add | System OpenSSH preserves aliases, ProxyJump, SSH Agent, hardware keys, and the user's existing SSH policy. |
| Interactive TUI framework | Do not add | Stable text and JSON are more suitable for automation and incident recovery. |
| ORM or embedded application database | Do not add | AgentOps currently has no persistent relational domain model. |

## Stage Gate

Before adding any candidate dependency, record:

1. The concrete user or operational problem.
2. Evidence that current code or the standard library is insufficient.
3. API fit, maintenance activity, license, security posture, compatibility,
   binary impact, transitive dependencies, and exit cost.
4. The smallest integration boundary and rollback plan.
5. Tests that fail before integration and pass afterward.
6. The release type and any compatibility impact.

Run `go mod tidy`, inspect the resulting direct and transitive dependency diff,
run `go test ./...`, build every release target, and review the final binary
before accepting a stage. A dependency is retained only while its capability is
used and verified.

## Execution Order

| Order | Stage | Start decision | Release expectation |
|---|---|---|---|
| 1 | Standard CLI Contract | Start after implementation authorization | `v1.1.0` |
| 2 | Semantic Version Policy | Wait for a real comparison policy | Separate minor release |
| 3 | Embedded Backup Encryption | Wait for security design and external-tool evidence | Separate security-focused release |
| 4 | Human-Readable Tables | Wait for representative usability evidence | Separate minor release |
| 5 | Complex Test Comparisons | Wait for repeated diagnostic pain in tests | Patch or minor release with its owning change |

The plan or issue that authorizes a stage becomes the execution authority for
that stage. This roadmap supplies ordering and gates; it does not authorize code
changes, production operations, publication, or cross-project synchronization.

## Current Execution Checkpoint

- Stage: `Stage 1: Standard CLI Contract`
- Authority: user authorization in the AgentSetup maintenance workspace
- Current state: `awaiting_verification`
- Allowed scope: top-level CLI routing, build metadata, release linker flags,
  Homebrew formula verification, tests, and directly affected documentation
- Excluded scope: operational handlers, safety policy, configuration schema,
  production operations, release publication, and project synchronization
- Implemented artifact: working tree based on AgentOps `v1.0.0`; Cobra command
  tree, version provenance, shell completion, CI, Formula checks, and user
  documentation are present
- Verified evidence: focused tests failed before implementation; `go test
  ./...`, `go vet ./...`, Formula generation tests, four release-target builds,
  injected metadata output, command help, and Bash/Zsh/Fish completion passed
- Remaining acceptance: commit and publish `v1.1.0`, update the Homebrew tap,
  install the released binary, and verify its tag, commit, build date, channel,
  Help, Version, and completion output
- Next action: perform commit and release preparation after explicit publication
  authorization
