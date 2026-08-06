package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const githubInstallStateAudience = "ora-github-install"

type githubInstallState struct {
	OrganizationID string
	ProjectID      string
	UserID         string
}

func installStateSigningKey() ([]byte, error) {
	if s := strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")); len(s) >= 16 {
		return []byte(s), nil
	}
	if s := strings.TrimSpace(os.Getenv("JWT_SECRET")); len(s) >= 32 && s != jwtSecretPlaceholder {
		return []byte(s), nil
	}
	if len(jwtSecret) >= 16 && !jwtSecretEphemeral {
		return jwtSecret, nil
	}
	return nil, fmt.Errorf("install state signing key unavailable — set OPEN_SERVICE_JWT_SECRET or stable JWT_SECRET")
}

func mintGitHubInstallState(org, proj, userID string) (string, error) {
	key, err := installStateSigningKey()
	if err != nil {
		return "", err
	}
	org = strings.TrimSpace(org)
	proj = strings.TrimSpace(proj)
	if org == "" {
		return "", fmt.Errorf("organization_id required for GitHub App install state")
	}
	if proj == "" {
		proj = defaultProjectID
	}
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": githubInstallStateAudience,
		"iss": "ora-api",
		"iat": now.Unix(),
		"exp": now.Add(30 * time.Minute).Unix(),
		"org": org,
		"proj": proj,
		"user": strings.TrimSpace(userID),
	})
	return tok.SignedString(key)
}

func parseGitHubInstallState(raw string) (*githubInstallState, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty install state")
	}
	key, err := installStateSigningKey()
	if err != nil {
		return nil, err
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	}, jwt.WithAudience(githubInstallStateAudience), jwt.WithIssuer("ora-api"))
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid install state")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid install state claims")
	}
	org := strings.TrimSpace(fmt.Sprint(claims["org"]))
	if org == "" {
		return nil, fmt.Errorf("install state missing org")
	}
	proj := strings.TrimSpace(fmt.Sprint(claims["proj"]))
	if proj == "" {
		proj = defaultProjectID
	}
	return &githubInstallState{
		OrganizationID: org,
		ProjectID:      proj,
		UserID:         strings.TrimSpace(fmt.Sprint(claims["user"])),
	}, nil
}
