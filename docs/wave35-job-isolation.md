# Job isolation (sandboxed runners)

When `OPA_JOB_SANDBOX=docker`, untrusted phases (secrets scan, AI review, autofix)
run in short-lived containers built from the runner targets in the Dockerfile.
Default remains `off` so existing smoke stays host-exec with curated `jobEnv`.

## Enable (laptop / smoke only)

```bash
./rebuild-smoke-images.sh          # builds *:smoke — never *:nas
./wave35-escape-smoke.sh           # every probe must FAIL inside the box

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
# Optional: OPA_JOB_EGRESS_ALLOWLIST=api.cursor.sh,api2.cursor.sh  # override defaults
```

Enable checkup via agent prefs (`checkup_enabled: true` at org/installation/repo).
Without docker sandbox the checkup child is skipped with an honesty reason.

Do **not** deploy `*:smoke` images to NAS prod — use `*:nas` and prod compose only.

## Checkup (AI-planned)

Plan is derived from `AGENTS.md` / `CLAUDE.md` / `CURSOR.md` / `.cursor/rules`
(an `opa-checkup-plan` fenced JSON block) or a conservative heuristic, then
clamped by `intersectSpecWithPolicy` (image/binary/secret/egress caps). Steps
use argv slices only; post-conditions (e.g. JUnit with ≥1 testcase) are
mandatory.

Service sidecars join `--internal` `opa-job-<id>`; teardown is
`docker rm -fv` by label `opa.job=<id>` (never `docker rm --filter`).

## Images

| Target | Contents | Phase |
|--------|----------|-------|
| `opa-runner-scan` | gitleaks + `/etc/opa/gitleaks.toml` | `security.scan` |
| `opa-runner-git` | git only | prepare-adjacent |
| `opa-runner-ai` | `/opt/opa/agent`, Playwright, pinned `@playwright/mcp` | review / autofix |
| `opa-runner-php` | PHP 8.4 CLI + common extensions + Composer | checkup / `cloud.verify` |
| `opa-egress-proxy` | allowlist CONNECT proxy (`egress-proxy` mode) | shared AI egress |

Heuristic checkup plans pick `OPA_JOB_IMAGE_PHP` / `opa-runner-php:<tag>` when
`composer.json` (and optionally `phpunit.xml`) is present; Node/Go trees keep
their own image envs. When `phpstan.neon` / `.dist` is present, the heuristic
adds `vendor/bin/phpstan analyse --no-progress --error-format=checkstyle` with
a checkstyle post-condition (stdout). **New-errors-only** is best-effort: if
`phpstan-baseline.neon` (or `.neon.php`) exists **and** the neon `includes` it,
phpstan itself only fails on new errors; without a baseline, any reported error
fails the check. AI-authored phpstan steps are normalized the same way in
`intersectSpecWithPolicy`.

## Hardening (argv builder)

`buildDockerRunArgv` is the only place that emits `docker run` flags. It always
sets `--user 65532:65532`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
`--read-only`, equal `--memory`/`--memory-swap`, and rejects `--privileged`,
`--cap-add`, `-p`, docker.sock mounts, and `-e` (non-secrets use `--env-file`;
secrets only via `docker exec --env`).

Scan uses `--network none`. Review/autofix/checkup AI phases use a per-job
`--internal` network with the shared allowlist proxy attached (DNS alias
`opa-egress-proxy`) and `HTTP(S)_PROXY` pointing at it. Checkup service sidecars
share that `--internal` net without the Cursor allowlist (no default route).

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
  container also joins `opa-egress-<instance>` and can dial the allowlist
  (`api.cursor.sh`, `api2.cursor.sh` by default). `OPA_JOB_EGRESS_PROXY=0`
  falls back to unrestricted `bridge` for AI (break-glass).
- Prompt injection survives the container. Agent stdout can reach check runs /
  comments; masking is heuristic, not a boundary.
- `OPA_JOB_ALLOW_HOST_EXEC=1` falls back to host exec and stamps
  `UNSANDBOXED: tools ran as root` — use only for break-glass debugging.
- Chromium inside `opa-runner-ai` needs `--no-sandbox` inside an already
  hardened box; do not `--cap-add SYS_ADMIN` to “fix” that.
- Escape smoke (`wave35-escape-smoke.sh`) is a local guardrail, not a proof of
  isolation against a compromised orchestrator.
- Cloud autofix lands by applying a **gateCloudDiff-validated** patch onto a
  fresh checkout (`cloud-land-*`), not by committing the agent-writable tree.
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
- Dashboard Agents UI ships in OPA-Dashboard (prefs APIs live here).
- Checkup step log viewer in Dashboard remains a follow-up; phpstan checkstyle
  annotations cover the lint path only.
