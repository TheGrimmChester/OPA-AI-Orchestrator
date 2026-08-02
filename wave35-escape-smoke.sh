#!/usr/bin/env bash
# Escape assertions for OPA_JOB_SANDBOX=docker. Every probe must FAIL from
# inside the box. Laptop/smoke only — never run against NAS prod.
set -euo pipefail

TAG="${OPA_JOB_IMAGE_TAG:-smoke}"
IMAGE="${OPA_JOB_IMAGE_SCAN:-opa-runner-scan:${TAG}}"
NAME="opa-escape-smoke-$$"
WORKDIR="$(mktemp -d /tmp/opa-escape-XXXXXX)"
trap 'docker rm -fv "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORKDIR"' EXIT

echo "using image=$IMAGE workdir=$WORKDIR"

# Minimal tree so bind is non-empty.
echo "hello" >"$WORKDIR/README"

docker rm -fv "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --pids-limit 64 \
  --memory 256m --memory-swap 256m \
  --network none \
  -v "$WORKDIR:/opa-jobs/escape/primary:ro" \
  -w /opa-jobs/escape/primary \
  "$IMAGE" sleep infinity >/dev/null

fail_inside() {
  local label="$1"
  shift
  if docker exec "$NAME" "$@" >/dev/null 2>&1; then
    echo "FAIL: expected denial for: $label" >&2
    exit 1
  fi
  echo "ok denied: $label"
}

# Host filesystem
fail_inside "read /etc/shadow" cat /etc/shadow
fail_inside "read docker.sock" ls /var/run/docker.sock
fail_inside "list other opa-jobs" ls /opa-jobs/other

# Egress (network none). Scan image has no curl/wget — use /dev/tcp.
fail_inside "tcp to orchestrator" timeout 2 sh -c 'echo >/dev/tcp/127.0.0.1/8091'
fail_inside "tcp to clickhouse" timeout 2 sh -c 'echo >/dev/tcp/127.0.0.1/8123'

# Privilege
fail_inside "sudo" sudo -n true
fail_inside "remount rw" mount -o remount,rw /
fail_inside "write /usr/local/bin" sh -c 'echo x >/usr/local/bin/pwn'

# Env must not carry orchestrator secrets (box started without them)
if docker exec "$NAME" sh -c 'env | grep -E "JWT_SECRET|OPA_CONNECTOR_SECRET|CLICKHOUSE_URL|OPA_GIT_ASKPASS"'; then
  echo "FAIL: secret-looking env present in box" >&2
  exit 1
fi
echo "ok no secret env"

# Inspect hardening
inspect="$(docker inspect "$NAME")"
echo "$inspect" | grep -q '"User": "65532:65532"' || { echo "FAIL: User"; exit 1; }
echo "$inspect" | grep -q 'ALL' || { echo "FAIL: CapDrop"; exit 1; }
echo "$inspect" | grep -qi 'ReadonlyRootfs.: true' || { echo "FAIL: ReadonlyRootfs"; exit 1; }
echo "$inspect" | grep -qi 'docker.sock' && { echo "FAIL: docker.sock mounted"; exit 1; } || true
echo "ok inspect hardening"

# --- --internal without proxy: no default route to the public internet ---
NET="opa-escape-internal-$$"
docker network create --internal "$NET" >/dev/null
INT_NAME="opa-escape-internal-box-$$"
trap 'docker rm -fv "$NAME" "$INT_NAME" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$WORKDIR"' EXIT
docker run -d --name "$INT_NAME" \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --pids-limit 64 \
  --memory 256m --memory-swap 256m \
  --network "$NET" \
  -v "$WORKDIR:/opa-jobs/escape/primary:ro" \
  -w /opa-jobs/escape/primary \
  "$IMAGE" sleep infinity >/dev/null

fail_inside_net() {
  local label="$1"
  shift
  if docker exec "$INT_NAME" "$@" >/dev/null 2>&1; then
    echo "FAIL: expected denial for: $label" >&2
    exit 1
  fi
  echo "ok denied: $label"
}

# Without the shared egress proxy attached, Cursor API (and the public net) is unreachable.
fail_inside_net "tcp to api.cursor.sh on --internal (no proxy)" \
  timeout 3 sh -c 'echo >/dev/tcp/api.cursor.sh/443'

# Allowlist denial — only when opa-egress-proxy image is present locally.
PROXY_IMAGE="${OPA_JOB_EGRESS_PROXY_IMAGE:-opa-egress-proxy:${TAG}}"
if docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1; then
  PROXY_NAME="opa-escape-proxy-$$"
  EG_NET="opa-escape-egress-$$"
  trap 'docker rm -fv "$NAME" "$INT_NAME" "$PROXY_NAME" >/dev/null 2>&1 || true; docker network rm "$NET" "$EG_NET" >/dev/null 2>&1 || true; rm -rf "$WORKDIR"' EXIT
  docker network create "$EG_NET" >/dev/null
  docker run -d --name "$PROXY_NAME" \
    --label opa.owner=opa-orchestrator \
    --label opa.role=egress-proxy \
    --network "$EG_NET" \
    -e OPA_EGRESS_ALLOWLIST=api.cursor.sh \
    "$PROXY_IMAGE" >/dev/null
  docker network connect --alias opa-egress-proxy "$NET" "$PROXY_NAME"
  # Probe from a curl-capable image on the same --internal net (scan image has no curl).
  set +e
  deny_code="$(docker run --rm --network "$NET" \
      -e HTTPS_PROXY=http://opa-egress-proxy:3128 \
      -e HTTP_PROXY=http://opa-egress-proxy:3128 \
      curlimages/curl:8.5.0 \
      -sS -o /dev/null -w "%{http_code}" \
      --connect-timeout 5 \
      https://example.com/ 2>/dev/null)"
  deny_rc=$?
  set -e
  if [[ "$deny_code" == "403" ]] || [[ "$deny_rc" -ne 0 ]]; then
    echo "ok denied: proxy allowlist blocks example.com (code=${deny_code:-n/a} rc=$deny_rc)"
  else
    echo "FAIL: proxy allowed example.com (not on allowlist) code=$deny_code" >&2
    exit 1
  fi
else
  echo "skip allowlist probe (no $PROXY_IMAGE — run ./rebuild-smoke-images.sh)"
fi

echo "ALL ESCAPE PROBES DENIED (as required)"
