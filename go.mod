module github.com/TheGrimmChester/ora-api

go 1.25.0

require (
	github.com/TheGrimmChester/open-auth-go v0.0.0
	github.com/TheGrimmChester/open-clickhouse-go v0.2.0
	github.com/TheGrimmChester/open-client-go v0.0.0-20260803093649-eb6d2f7a2423
	github.com/TheGrimmChester/open-http-go v0.0.0-20260804055231-a9462e336412
	github.com/TheGrimmChester/open-job-go v0.0.0-20260803091535-04d163946627
	github.com/TheGrimmChester/open-logger-go v0.2.0
	github.com/TheGrimmChester/open-tenant-go v0.2.2
	github.com/golang-jwt/jwt/v5 v5.3.1
)

// The family libraries were wired with filesystem replaces (=> ../Open-Auth-Go).
// Those resolve in a developer tree but not in a single-repo checkout, so every
// CI checkup aborted before a test ran:
//
//	auth_wire.go:7:2: …/open-auth-go@v0.0.0: replacement directory
//	../Open-Auth-Go does not exist
//
// The versions above come from the public module proxy instead, so this go.mod
// resolves anywhere. To develop against live sibling checkouts, create a
// go.work (gitignored) — see docs/go-modules.md.
//
// open-client-go's own published go.mod requires open-auth-go v0.0.0, a version
// that was never tagged, so resolution cannot proceed on the require line
// alone. This replace maps that dead version onto a real commit. Drop it once
// open-client-go is republished requiring a resolvable version.
replace github.com/TheGrimmChester/open-auth-go => ../Open-Auth-Go
