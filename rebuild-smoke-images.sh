#!/usr/bin/env bash
# Build local smoke-tagged runner images for OPA_JOB_SANDBOX=docker.
# Never tags *:nas — laptop/smoke only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
TAG="${OPA_JOB_IMAGE_TAG:-smoke}"

build_one() {
  local target="$1"
  echo "==> building ${target}:${TAG}"
  docker build --target "$target" -t "${target}:${TAG}" .
  docker image inspect "${target}:${TAG}" >/dev/null
  echo "ok ${target}:${TAG}"
}

build_one opa-runner-scan
build_one opa-runner-git
build_one opa-egress-proxy
# AI image pulls Cursor + Playwright — skip with OPA_SKIP_AI_IMAGE=1 for fast loops.
if [[ "${OPA_SKIP_AI_IMAGE:-0}" != "1" ]]; then
  build_one opa-runner-ai
else
  echo "skip opa-runner-ai (OPA_SKIP_AI_IMAGE=1)"
fi
# PHP checkup image compiles extensions — skip with OPA_SKIP_PHP_IMAGE=1 for fast loops.
if [[ "${OPA_SKIP_PHP_IMAGE:-0}" != "1" ]]; then
  build_one opa-runner-php
else
  echo "skip opa-runner-php (OPA_SKIP_PHP_IMAGE=1)"
fi

echo "done."
echo "  OPA_JOB_SANDBOX=docker \\"
echo "  OPA_JOB_EGRESS_PROXY=1 \\"
echo "  OPA_JOB_EGRESS_PROXY_IMAGE=opa-egress-proxy:${TAG} \\"
echo "  OPA_JOB_IMAGE_SCAN=opa-runner-scan:${TAG} \\"
echo "  OPA_JOB_IMAGE_GIT=opa-runner-git:${TAG} \\"
echo "  OPA_JOB_IMAGE_AI=opa-runner-ai:${TAG} \\"
echo "  OPA_JOB_IMAGE_PHP=opa-runner-php:${TAG} \\"
echo "  OPA_JOB_IMAGE_CHECKUP=opa-runner-php:${TAG} \\"
echo "  OPA_JOB_IMAGE_ALLOW='opa-runner-*,node:22*,mysql:8.4*,redis:7*,php:8.4*,hebabil/php-8.4-cli*'"
