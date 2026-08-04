package main

import (
	"log"
	"net/http"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Thin product wiring around Open-Auth-Go. No local JWT/middleware copies.
// Gate.Middleware calls ApplyUserTenantHeaders then EnforceProjectACL
// (Open-Auth-Go #6 / project_ids). Trust hub-minted claims; role admin bypasses.

const jwtSecretPlaceholder = openauth.JWTSecretPlaceholder
const authCookieName = openauth.CookieName

var (
	jwtSecret          []byte
	jwtSecretEphemeral bool
	authGate           *openauth.Gate
	authMode           openauth.Mode
)

// Claims is the user JWT claims type used across the API.
type Claims = openauth.UserClaims

func authRequiredEnv() bool { return openauth.AuthRequiredEnv() }

func initAuthMode() {
	g, err := openauth.BootstrapFromEnv("ora-api", "ora-api")
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	authGate = g
	jwtSecret = g.Secret
	jwtSecretEphemeral = g.Ephemeral
	authMode = g.Mode
}

func registerLocalAuthMux(mux *http.ServeMux) {
	if authGate != nil {
		authGate.RegisterLocalAuth(mux)
	}
}

func AuthMiddleware(handler http.HandlerFunc, requiredRole string) http.HandlerFunc {
	return authGate.Middleware(requiredRole, handler)
}

// AuthUserOrServiceMiddleware accepts a user JWT or a short-lived service JWT
// (aud=ora-api). Service callers map to role=admin when org headers apply.
func AuthUserOrServiceMiddleware(handler http.HandlerFunc, requiredRole, requiredServiceScope string) http.HandlerFunc {
	return authGate.UserOrServiceMiddleware(requiredRole, requiredServiceScope, handler)
}

func hasPermission(userRole, requiredRole string) bool {
	return openauth.HasPermission(userRole, requiredRole)
}

// AuthHandler preserves call sites that verify tokens outside middleware.
type AuthHandler struct {
	queryClient *ClickHouseQuery
}

func (ah *AuthHandler) VerifyToken(tokenString string) (*Claims, error) {
	return authGate.ParseUser(tokenString)
}
