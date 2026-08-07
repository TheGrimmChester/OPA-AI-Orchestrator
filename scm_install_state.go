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

// installStateVerifyKeys returns keys accepted for callback state.
// When OPA_GITHUB_INSTALL_STATE_SECRET is set, only that key is used (peers
// holding OPEN_SERVICE_JWT_SECRET cannot forge binds). Legacy OPEN_SERVICE /
// JWT verification is opt-in via OPA_GITHUB_INSTALL_STATE_ACCEPT_LEGACY=1.
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

	dedicated := strings.TrimSpace(os.Getenv("OPA_GITHUB_INSTALL_STATE_SECRET"))
	if len(dedicated) >= 16 {
		add([]byte(dedicated))
		if !envTruthy("OPA_GITHUB_INSTALL_STATE_ACCEPT_LEGACY") {
			return keys
		}
	}
	if k, err := installStatePreferredKey(); err == nil {
		add(k)
	}
	if envTruthy("OPA_GITHUB_INSTALL_STATE_ACCEPT_LEGACY") || dedicated == "" {
		if s := strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")); len(s) >= 16 {
			add([]byte(s))
		}
	}
	return keys
}

func envTruthy(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func mintGitHubInstallState(org, proj, userID string) (string, error) {
	key, err := installStatePreferredKey()
	if err != nil {
		return "", err
	}
	org = strings.TrimSpace(org)
	proj = strings.TrimSpace(proj)
	userID = strings.TrimSpace(userID)
	// Org Open accounts bind by organization_id; personal Open accounts bind by
	// user_id with an empty org (same ownership model as personal PAT / import).
	if org == "" && userID == "" {
		return "", fmt.Errorf("organization_id or user_id required for GitHub App install state")
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
		"user": userID,
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
		user = strings.TrimSpace(user)
		if org == "" && user == "" {
			lastErr = fmt.Errorf("install state missing org or user")
			continue
		}
		return &githubInstallState{
			OrganizationID: org,
			ProjectID:      strings.TrimSpace(proj),
			UserID:         user,
		}, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("invalid install state")
	}
	return nil, fmt.Errorf("invalid install state")
}
