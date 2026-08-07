# Optional micro-services

Phase 1–2 ship a single `ora-api` process. A later peel may place domain services behind `ora-gateway` without changing dashboard URLs.

```text
ora-gateway
  ├── ora-scm
  ├── ora-review
  ├── ora-agents
  └── ora-ai          # review-provider settings / runner dispatch
ora-orchestrator      # remains the job owner
ora-runner-{git,ai,php}
ora-egress-proxy
```

Compose comments (enable when peeled):

```yaml
# ora-gateway:
#   image: ora-gateway:nas
#   ports: ["8091:8091"]
```

Until peeled, all routes live on `ora-api`. No legacy path aliases.
