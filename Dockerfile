# ORA-API — Open Review Agent control plane
FROM golang:1.25-alpine AS builder
RUN apk --no-cache add git ca-certificates
WORKDIR /app
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o ora-api .

# Default compose target — keep this stage named; later runner/egress stages must
# not become the default image (docker build uses the last stage otherwise).
FROM debian:bookworm-slim AS ora-api
ARG TARGETARCH
ARG PLAYWRIGHT_VERSION=1.50.1

# Runtime: git/curl + Cursor Agent CLI + Node/npx + Playwright Chromium
# (required for OPA Review UI visual MCP via @playwright/mcp --headless).
# docker.io = CLI client for OPA_JOB_SANDBOX=docker (daemon via mounted sock).
# AppSec scanners live in OSA — do not bake gitleaks or lite scan scripts here.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git bash \
      docker.io \
      nodejs npm \
      libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
      libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
      libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
      libx11-6 libx11-xcb1 libxcb1 libxext6 libglib2.0-0 libgtk-3-0 \
      libxcb-shm0 libxshmfence1 libegl1 libxcursor1 libxi6 libxtst6 \
      fonts-liberation fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/* \
 && command -v docker \
 && node -v && npm -v && command -v npx \
 && (NO_COLOR=1 curl -fsS https://cursor.com/install | bash \
      && test -x /root/.local/bin/agent \
      && ln -sf /root/.local/bin/agent /usr/local/bin/agent \
      && ln -sf /root/.local/bin/cursor-agent /usr/local/bin/cursor-agent) \
    || echo "WARN: Cursor Agent CLI install skipped (OPA Review AI unavailable until installed)" \
 && npx --yes "playwright@${PLAYWRIGHT_VERSION}" install-deps chromium \
 && npx --yes "playwright@${PLAYWRIGHT_VERSION}" install chromium \
 && rm -rf /root/.npm /tmp/*

WORKDIR /root/
COPY --from=builder /app/ora-api .

# Browser MCP is a required capability for UI OPA Reviews (disable only via env).
ENV HTTP_ADDR=:8091 \
    OPA_REVIEW_BROWSER_MCP=1 \
    OPA_REVIEW_BROWSER_DEPS_OK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright \
    OPA_JOB_SANDBOX=off

EXPOSE 8091
CMD ["./ora-api"]

# --- Runner images (OPA_JOB_SANDBOX=docker) ---
# AppSec scan runners live in OSA-API (osa-runner-scan).
# Git-only runner for prepare-adjacent host tools that still need a box.
FROM debian:bookworm-slim AS ora-runner-git
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && test -x /usr/bin/git
USER 65532:65532
WORKDIR /home/opa
CMD ["sleep", "infinity"]

# AI runner: Cursor agent at a baked fixed path + Playwright for browser MCP.
# Chromium needs --no-sandbox inside an already-hardened box (accepted).
FROM debian:bookworm-slim AS ora-runner-ai
ARG TARGETARCH
ARG PLAYWRIGHT_VERSION=1.50.1
ARG PLAYWRIGHT_MCP_VERSION=0.0.28
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git bash \
      nodejs npm \
      libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
      libdbus-1-3 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
      libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
      libx11-6 libx11-xcb1 libxcb1 libxext6 libglib2.0-0 libgtk-3-0 \
      libxcb-shm0 libxshmfence1 libegl1 libxcursor1 libxi6 libxtst6 \
      fonts-liberation fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/* \
 && node -v && npm -v \
 && mkdir -p /opt/opa /opt/ms-playwright /home/opa \
 && (NO_COLOR=1 curl -fsS https://cursor.com/install | bash \
      && test -x /root/.local/bin/agent \
      && AGENT_REAL="$(readlink -f /root/.local/bin/agent)" \
      && test -n "$AGENT_REAL" && test -x "$AGENT_REAL" \
      && AGENT_DIR="$(dirname "$AGENT_REAL")" \
      && rm -rf /opt/opa/cursor-agent-dist \
      && cp -a "$AGENT_DIR" /opt/opa/cursor-agent-dist \
      && ln -sfn /opt/opa/cursor-agent-dist/$(basename "$AGENT_REAL") /opt/opa/agent \
      && ln -sfn /opt/opa/agent /opt/opa/cursor-agent \
      && chmod -R a+rX /opt/opa/cursor-agent-dist \
      && chmod 0755 /opt/opa/agent \
      && test -x /opt/opa/agent) \
 || (echo "ERROR: Cursor Agent CLI required for ora-runner-ai" >&2; exit 1) \
 && PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
      npx --yes "playwright@${PLAYWRIGHT_VERSION}" install-deps chromium \
 && PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
      npx --yes "playwright@${PLAYWRIGHT_VERSION}" install chromium \
 && npm install -g "@playwright/mcp@${PLAYWRIGHT_MCP_VERSION}" \
 && chown -R 65532:65532 /home/opa /opt/ms-playwright \
 && rm -rf /root/.npm /tmp/* /root/.local \
 && test -x /opt/opa/agent \
 && (/opt/opa/agent --help >/dev/null 2>&1 || /opt/opa/agent --version >/dev/null 2>&1 || true)
ENV PATH="/opt/opa:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    NO_OPEN_BROWSER=1 \
    HOME=/home/opa
USER 65532:65532
WORKDIR /home/opa
CMD ["sleep", "infinity"]

# PHP checkup runner: official PHP 8.4 CLI + common extensions + Composer.
# Prefer this over third-party images; org-private hebabil/php-8.4-cli remains
# allowlisted when operators need full extension parity for a specific fleet.
# phpunit/phpstan/php-cs-fixer are expected from project vendor/ after composer install.
FROM php:8.4-cli-bookworm AS ora-runner-php
COPY --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git unzip zip \
 && rm -rf /var/lib/apt/lists/* \
 && install-php-extensions \
      bcmath pcntl sockets intl mbstring xml curl zip gd \
      pdo_mysql redis event opentelemetry opcache \
 && test -x /usr/local/bin/php \
 && test -x /usr/local/bin/composer \
 && php -m | grep -qi bcmath \
 && php -m | grep -qi redis \
 && php -m | grep -qi pcntl \
 && mkdir -p /home/opa/.composer /tmp \
 && chown -R 65532:65532 /home/opa /tmp
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/home/opa \
    COMPOSER_HOME=/home/opa/.composer \
    COMPOSER_ALLOW_SUPERUSER=0
USER 65532:65532
WORKDIR /home/opa
CMD ["sleep", "infinity"]

# Shared allowlist HTTPS CONNECT proxy for review job boxes on --internal networks.
# Only this container joins both the egress network and per-job bridges.
FROM alpine:3.20 AS ora-egress-proxy
RUN apk --no-cache add ca-certificates \
 && adduser -D -u 65532 -g 65532 opa
COPY --from=builder /app/ora-api /ora-api
USER 65532:65532
ENV OPA_EGRESS_PROXY_LISTEN=:3128 \
    OPA_EGRESS_ALLOWLIST=api.cursor.sh,api2.cursor.sh
EXPOSE 3128
ENTRYPOINT ["/ora-api", "egress-proxy"]
