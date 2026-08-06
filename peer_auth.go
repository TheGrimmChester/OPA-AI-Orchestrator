package main

import (
	"fmt"
	"os"
	"strings"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// validatePeerAuthToken validates a service JWT for peer/internal routes and
// optionally requires a scope. Used by OAM→ORA connector BFF and peer SCM.
func validatePeerAuthToken(token, aud, scope string) (*openauth.ServiceClaims, error) {
	secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
	if len(secret) == 0 {
		return nil, fmt.Errorf("service auth disabled")
	}
	claims, err := openauth.ValidateServiceJWT(token, secret, aud)
	if err != nil {
		return nil, err
	}
	if scope != "" {
		if err := openauth.RequireScope(claims, scope); err != nil {
			return nil, err
		}
	}
	return claims, nil
}
