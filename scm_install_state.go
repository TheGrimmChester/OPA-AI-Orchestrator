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

// installStatePreferredKey is used to mint new install state JWTs.
// Prefer a dedicated secret so peer OPEN_SERVICE_JWT_SECRET holders cannot forge binds.
func installStatePreferredKey() ([]byte, error) {
	if s := strings.TrimSpace(os.Getenv("OPA_GITHUB_INSTALL_STATE_SECRET")); len(s) >= 16 {
		return []byte(s), nil
	}
	if s := strings.TrimSpace(os.Getenv("JWT_SECRET")); len(s) >= 32 && s != jwtSecretPlaceholder {
		return []byte(s), nil
	}
	if len(jwtSecret) >= 16 && !jwtSecretEphemeral {
		return jwtSecret, nil
	}
	return nil, fmt.Errorf("install state signing key unavailable — set OPA_GITHUB_INSTALL_STATE_SECRET (≥16) or stable JWT_SECRET (≥32)")
}

// installStateVerifyKeys tries preferred key first, then legacy OPEN_SERVICE_JWT_SECRET
// so existing callbacks keep working until NAS rotates to the dedicated secret.
func installStateVerifyKeys() [][]byte {
	seen := map[string]bool{}
	var keys [][]byte
	add := func(b []byte) {
		if len(b) < 16 {
			return
		}
		k := string(b)
		if seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, b)
	}
	if k, err := installStatePreferredKey(); err == nil {
		add(k)
	}
	if s := strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")); len(s) >= 16 {
		add([]byte(s))
	}
	return keys
}

func mintGitHubInstallState(org, proj, userID string) (string, error) {
	key, err := installStatePreferredKey()
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
		"aud":  githubInstallStateAudience,
		"iss":  "ora-api",
		"iat":  now.Unix(),
		"exp":  now.Add(30 * time.Minute).Unix(),
		"org":  org,
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
	keys := installStateVerifyKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("install state signing key unavailable — set OPA_GITHUB_INSTALL_STATE_SECRET or stable JWT_SECRET")
	}
	var lastErr error
	for _, key := range keys {
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return key, nil
		}, jwt.WithAudience(githubInstallStateAudience), jwt.WithIssuer("ora-api"))
		if err != nil || !tok.Valid {
			lastErr = err
			continue
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			lastErr = fmt.Errorf("invalid install state claims")
			continue
		}
		org, _ := claims["org"].(string)
		proj, _ := claims["proj"].(string)
		user, _ := claims["user"].(string)
		org = strings.TrimSpace(org)
		if org == "" {
			lastErr = fmt.Errorf("install state missing org")
			continue
		}
		return &githubInstallState{
			OrganizationID: org,
			ProjectID:      strings.TrimSpace(proj),
			UserID:         strings.TrimSpace(user),
		}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("invalid install state")
	}
	return nil, fmt.Errorf("invalid install state")
}
