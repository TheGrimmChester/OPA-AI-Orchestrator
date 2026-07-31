# OPA AI Orchestrator — Wave 33 runs + Wave 34 SCM / OPA Review
FROM golang:1.25-alpine AS builder
RUN apk --no-cache add git ca-certificates
WORKDIR /app
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY gitleaks.toml ./
RUN CGO_ENABLED=0 GOOS=linux go build -o opa-orchestrator .

FROM debian:bookworm-slim
ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl wget git bash \
 && rm -rf /var/lib/apt/lists/* \
 && arch="$TARGETARCH" \
 && case "$arch" in amd64|x86_64) gl_arch=x64 ;; arm64|aarch64) gl_arch=arm64 ;; *) gl_arch=x64 ;; esac \
 && wget -qO /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm -f /tmp/gitleaks.tgz \
 && NO_COLOR=1 curl -fsS https://cursor.com/install | bash \
 && test -x /root/.local/bin/agent \
 && ln -sf /root/.local/bin/agent /usr/local/bin/agent \
 && ln -sf /root/.local/bin/cursor-agent /usr/local/bin/cursor-agent

WORKDIR /root/
COPY --from=builder /app/opa-orchestrator .
COPY gitleaks.toml /etc/opa/gitleaks.toml
COPY scripts/ /opt/opa/scripts/
ENV HTTP_ADDR=:8091
EXPOSE 8091
CMD ["./opa-orchestrator"]
