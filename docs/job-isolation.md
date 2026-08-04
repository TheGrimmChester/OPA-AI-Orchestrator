# Job isolation (ORA)


When `OPA_JOB_SANDBOX=docker`, untrusted phases (secrets scan, automated review, autofix)
run in short-lived containers built from the runner targets in the Dockerfile.
Default remains `off` so existing smoke stays host-exec with curated `jobEnv`.

## Enable (laptop / smoke only)

```bash
./rebuild-smoke-images.sh          # builds *:smoke — never *:nas
./job-escape-smoke.sh           # every probe must FAIL inside the box

export OPA_JOB_SANDBOX=docker
# Egress proxy defaults ON in docker mode (OPA_JOB_EGRESS_PROXY=0 → old bridge fallback)
export OPA_JOB_EGRESS_PROXY_IMAGE=opa-egress-proxy:smoke
export OPA_JOB_IMAGE_SCAN=opa-runner-scan:smoke
export OPA_JOB_IMAGE_GIT=opa-runner-git:smoke
export OPA_JOB_IMAGE_AI=opa-runner-ai:smoke
export OPA_JOB_IMAGE_PHP=opa-runner-php:smoke
export OPA_JOB_IMAGE_CHECKUP=opa-runner-php:smoke
export OPA_JOB_IMAGE_ALLOW='opa-runner-*,node:22*,mysql:8.4*,redis:7*,php:8.4*,hebabil/php-8.4-cli*'
export OPA_INSTANCE_ID=laptop-dev   # reaper only kills this instance's labels
# Optional: OPA_SKIP_PHP_IMAGE=1 / OPA_SKIP_AI_IMAGE=1  # fast rebuild loops
# Optional: OPA_REVIEW_TMP=/opa-jobs  # identity path shared with container binds
# Optional: OPA_JOB_EGRESS_NPM=1      # add registry.npmjs.org (prefer image-pinned deps)
# Optional: OPA_JOB_EGRESS_ALLOWLIST — **full override** of defaults (not a merge).
#   Leave unset to keep the default model-provider API hosts plus any checkup
#   registry hosts the proxy ships with. Setting this replaces the entire list —
#   do not omit checkup registries in prod if installs need npm/packagist.
#   Model-provider hosts only (example — not a merge with checkup defaults):
#   export OPA_JOB_EGRESS_ALLOWLIST=api.cursor.sh,api2.cursor.sh,api3.cursor.sh,api4.cursor.sh,api5.cursor.sh
# Optional: OPA_JOB_EGRESS_STACK_NETWORKS=opa-stack_opa_internal,opa_network
#   (default) also join compose bridges so NAS egress routing/DNS matches the stack
```

Enable checkup via job prefs (`checkup_enabled: true` at org/installation/repo).
Without docker sandbox the checkup child is skipped with an honesty reason.

Do **not** deploy `*:smoke` images to NAS prod — use `*:nas` and prod compose only.

## Checkup (model-planned)

Plan is derived from project instruction files (`AGENTS.md` and common
assistant-config filenames under the repo root) that contain an
`opa-checkup-plan` fenced JSON block, or from a conservative heuristic, then
clamped by `intersectSpecWithPolicy` (image/binary/secret/egress caps). Steps
use argv slices only; post-conditions (e.g. JUnit with ≥1 testcase) are
mandatory.

Service sidecars join `--internal` `opa-job-<id>`; teardown is
`docker rm -fv` by label `opa.job=<id>` (never `docker rm --filter`).

### Checkup workspace

Checkup runs in an isolated per-job layout, not a developer tree:

```
$OPA_REVIEW_TMP/<job-id>/
  primary/                # the pull request checkout — the step working dir
  related/<owner-repo>/    # sibling clones for cross-repo context (read-only)
  <Module-Dir>/            # resolved go.mod replace targets (read-only)
```

Services that pin shared libraries to sibling directories:

```
replace github.com/example/shared-auth => ../Shared-Auth
```

resolve against a developer tree but not against `primary/` alone, so the
toolchain aborts before any test runs:

```
auth_wire.go:7:2: …/shared-auth@v0.0.0: replacement directory ../Shared-Auth does not exist
```

Before the first step, Checkup reads `go.mod`, materializes each missing
filesystem `replace` target as a sibling of `primary/`, and binds it read-only
into the sandbox at the matching path. Sources come from
`OPA_CHECKUP_MODULE_SRC` (then `FAMILY_ROOT`, then `OPA_FAMILY_SRC`); `.git`,
`vendor/` and build output are not copied, and symlinks are skipped so a link in
a source tree cannot pull host paths into the layout. Targets that resolve
outside the job layout are refused rather than mounted.

When a replacement cannot be resolved, the run is **blocked**: no step executes
and the check reports `neutral` with the module names and the variable to set.
A runner that could not build the tree has learned nothing about the commit, so
it must not report a failure.

Runner state from an earlier attempt (`primary/.opa-checkup/`, which holds
per-step output captures) is removed before each run, so a retry on a reused
layout cannot read a previous attempt's log as its own.

## Images

| Target | Contents | Phase |
|--------|----------|-------|
| `opa-runner-scan` | gitleaks + `/etc/opa/gitleaks.toml` | `security.scan` |
| `opa-runner-git` | git only | prepare-adjacent |
| `opa-runner-ai` | Review runner binary, Playwright, pinned `@playwright/mcp` | review / autofix |
| `opa-runner-php` | PHP 8.4 CLI + common extensions + Composer | checkup / `cloud.verify` |
| `opa-egress-proxy` | allowlist CONNECT proxy (`egress-proxy` mode) | shared review egress |

Heuristic checkup plans pick `OPA_JOB_IMAGE_PHP` / `opa-runner-php:<tag>` when
`composer.json` (and optionally `phpunit.xml`) is present; Node/Go trees keep
their own image envs. When `phpstan.neon` / `.dist` is present, the heuristic
adds `vendor/bin/phpstan analyse --no-progress --error-format=checkstyle` with
a checkstyle post-condition (stdout). **New-errors-only** is best-effort: if
`phpstan-baseline.neon` (or `.neon.php`) exists **and** the neon `includes` it,
phpstan itself only fails on new errors; without a baseline, any reported error
fails the check. Model-authored phpstan steps are normalized the same way in
`intersectSpecWithPolicy`.

## Hardening (argv builder)

**Job boxes** go only through `buildDockerRunArgv`. That path always sets
`--user 65532:65532`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--read-only`, equal `--memory`/`--memory-swap`, and rejects `--privileged`,
`--cap-add`, `-p`, docker.sock mounts, and `-e` (non-secrets use `--env-file`;
secrets only via `docker exec --env-file`).

**Checkup service sidecars** use `buildDockerServiceArgv` (cap-drop /
no-new-privileges / no publish / no docker.sock) but intentionally omit
`--user` / `--read-only` so MySQL/Redis images can start as designed.

**Shared egress proxy** (`ensureSharedEgressProxy`) is a trusted long-lived
container with its own argv (including `-e`); it is not a job box.

**Networks:** Scan uses `--network none`. Review/autofix phases use a
per-job `--internal` network with the shared allowlist proxy attached (DNS
alias `opa-egress-proxy`) and `HTTP(S)_PROXY` pointing at it. Checkup
`runCheckupPlan` uses the **same** allowlist proxy path when
`OPA_JOB_EGRESS_PROXY` is enabled and there are no sidecar services (so
`composer`/`npm` can reach registries on the allowlist). With sidecars or
proxy disabled, checkup falls back to a sealed `--internal` net (offline /
vendor-only).

## Prepare → sandbox tree

In docker mode, prepare materializes a `checkout-index` copy under
`{job}/sandbox/` (no `.git`, parity-checked against tracked files) so
`export-ignore` cannot shrink the scanned tree. Security/bugbot prefer that path
when present.

## Honesty

- Mounting the docker socket on the **orchestrator** makes that service
  host-root-equivalent. Sandboxing moves untrusted code out of that container; it
  does not make the socket safe.
- **`--internal` is the network boundary**, not `HTTP(S)_PROXY`. A sandboxed
  process can unset proxy env (and Chromium ignores it without `--proxy-server`).
  Job boxes have no default route; only the shared `opa.role=egress-proxy`
  container also joins `opa-egress-<instance>` and can dial the allowlist.
  Defaults are model-provider API hosts (`api.cursor.sh` … `api5.cursor.sh`).
  When `OPA_JOB_SANDBOX=docker` (and `OPA_JOB_EGRESS_CHECKUP` is not `0`), the
  same proxy also allowlists checkup registries: npm (`registry.npmjs.org`,
  `registry.yarnpkg.com`), Go (`proxy.golang.org`, `sum.golang.org`,
  `storage.googleapis.com`, `github.com`, `objects.githubusercontent.com`,
  `codeload.github.com`, `proxy.golang.com`), and Composer/Packagist
  (`repo.packagist.org`, `packagist.org`). `OPA_JOB_EGRESS_PROXY=0` falls back
  to unrestricted `bridge` for review runners (break-glass).
- Prompt injection survives the container. Review-runner stdout can reach check
  runs / comments; masking is heuristic, not a boundary.
- Checkup sidecars and the shared egress proxy are **not** under the job-box
  non-root / read-only envelope; treat them as trusted helpers on the job
  `--internal` network, not as untrusted review-runner sandboxes.
- **Checkup registry egress** follows the shared allowlist proxy when
  `OPA_JOB_EGRESS_PROXY` is on and the plan has no sidecar services (same
  `--internal` + proxy path as review). With sidecars or proxy off, checkup nets
  stay sealed — `composer`/`npm`/`yarn` then only succeed when `vendor/` /
  `node_modules` (or an offline cache bind) is already in the tree. Expanding
  the allowlist for registries is an explicit product change, not break-glass
  bridge/host exec.
- `OPA_JOB_ALLOW_HOST_EXEC=1` falls back to host exec and stamps
  `UNSANDBOXED: tools ran as root` — use only for break-glass debugging.
- Chromium inside `opa-runner-ai` needs `--no-sandbox` inside an already
  hardened box; do not `--cap-add SYS_ADMIN` to “fix” that.
- Escape smoke (`job-escape-smoke.sh`) is a local guardrail, not a proof of
  isolation against a compromised orchestrator.
- Cloud autofix lands by applying a **gateCloudDiff-validated** patch onto a
  fresh checkout (`cloud-land-*`), not by committing the runner-writable tree.
- **PHP checkup image choice:** `opa-runner-php` is built from official
  `php:8.4-cli-bookworm` plus `install-php-extensions` (bcmath, pcntl, redis,
  event, opentelemetry, pdo_mysql, intl, …) and Composer 2 — not from
  `hebabil/php-8.4-cli`, which is private/unavailable in public smoke builds.
  That org image stays on the default allowlist (`hebabil/php-8.4-cli*`) so
  operators can set `OPA_JOB_IMAGE_PHP` to it when a fleet needs exact prod
  extension parity. Stock `php:8.4*` alone is insufficient for many composer
  require-ext sets; the runner image exists to close that gap without a
  third-party base. phpunit/phpstan/php-cs-fixer are **not** baked in — they
  come from project `vendor/` after `composer install`.
- Agents UI ships in ORA-Dashboard (prefs APIs live here).
- Checkup step log viewer in the dashboard remains a follow-up; phpstan
  checkstyle annotations cover the lint path only.
