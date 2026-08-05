# Go modules and the family libraries

ORA-API depends on seven shared libraries that live in their own repositories:

| Module | Repository |
| --- | --- |
| `open-auth-go` | `TheGrimmChester/Open-Auth-Go` |
| `open-client-go` | `TheGrimmChester/Open-Client-Go` |
| `open-job-go` | `TheGrimmChester/Open-Job-Go` |
| `open-tenant-go` | `TheGrimmChester/Open-Tenant-Go` |
| `open-clickhouse-go` | `TheGrimmChester/Open-ClickHouse-Go` |
| `open-http-go` | `TheGrimmChester/Open-HTTP-Go` |
| `open-logger-go` | `TheGrimmChester/Open-Logger-Go` |

All seven are public, so `go.mod` pins them at proxy-resolvable versions and the
repository builds from a checkout of ORA-API alone.

## Why the filesystem replaces are gone

`go.mod` used to wire each library to a sibling directory:

```
replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go
```

That works in a developer tree, where all the repositories sit side by side. It
cannot work in CI, which checks out one repository. The OPA Checkup `go-test`
step failed on every commit with seven variations of:

```
auth_wire.go:7:2: github.com/TheGrimmChester/open-auth-go@v0.0.0:
	replacement directory ../Open-Auth-Go does not exist
```

The failure was reported as a red check, so the signal said "this commit is
broken" when the commit was fine and the runner layout was not. Pinning real
versions removes the dependency on the checkout layout entirely.

## Local development against live sibling checkouts

Editing a library and seeing the change immediately still works — through a
workspace file rather than `go.mod`:

```bash
./scripts/dev-go-work.sh
```

That writes a `go.work` listing this repository plus the seven siblings. `go.work`
is gitignored on purpose: if it were committed, CI would fail exactly the way it
did before. Point the script somewhere else with `FAMILY_ROOT`:

```bash
FAMILY_ROOT=~/src ./scripts/dev-go-work.sh
```

To build against the pinned versions again — which is what CI does — remove the
file or set `GOWORK=off`:

```bash
rm go.work
```

```bash
GOWORK=off go test ./...
```

## Bumping a library

A library change reaches ORA-API only once it is pushed and the version here is
bumped:

```bash
go get github.com/TheGrimmChester/open-auth-go@main && go mod tidy
```

Use a tag instead of `@main` where one exists; `open-tenant-go`,
`open-clickhouse-go` and `open-logger-go` are tagged, the rest resolve to commit
pseudo-versions.

## The open-auth-go replace

`go.mod` carries one replace directive:

```
replace github.com/TheGrimmChester/open-auth-go => github.com/TheGrimmChester/open-auth-go v0.0.0-20260804130009-bc589c3d949d
```

It maps a version onto a version — not onto a directory — so it resolves in CI.
It exists because `open-client-go`'s own published `go.mod` requires
`open-auth-go v0.0.0`, a version that was never tagged. Without the replace,
resolution fails before the build starts:

```
go: github.com/TheGrimmChester/open-client-go@main requires
	github.com/TheGrimmChester/open-auth-go@v0.0.0, not …@main
```

The real fix belongs in `Open-Client-Go`: drop its own `../Open-Auth-Go` replace,
require a resolvable `open-auth-go` version, and push. Once that is published,
`go get github.com/TheGrimmChester/open-client-go@main` here and delete this
replace directive along with the `use`-override in `scripts/dev-go-work.sh`.

## Other services in the family

`OPM-API`, `OSA-API` and `OPL-API` still carry the same filesystem replaces and
their checkups fail for the same reason. The fix transfers directly, with the
same `Open-Client-Go` ordering caveat for the two that depend on it.
