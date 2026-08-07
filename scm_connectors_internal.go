package main

import (
	"net/http"
	"os"
	"strings"

	openauth "github.com/TheGrimmChester/open-auth-go"
)

// Delegated actor headers set by oam-api when peaking ORA internal connector
// writes. Only honored on /api/internal/connectors/* after service JWT auth.
const (
	headerDelegatedUsername    = "X-Delegated-Username"
	headerDelegatedRole        = "X-Delegated-Role"
	headerDelegatedAccountType = "X-Delegated-Account-Type"
	headerDelegatedProjectID   = "X-Delegated-Project-ID"
)

// registerInternalConnectorsMux exposes OAM→ORA peer write/protocol helpers.
// Browser /api/connectors mutations stay refused when PEER_OAM_URL is set; these
// routes accept service JWT (aud=ora-api, iss=oam-api, scope connectors:write)
// and run the same handlers with a peer-write context bypass.
func registerInternalConnectorsMux(mux *http.ServeMux) {
	mux.HandleFunc("/api/internal/connectors/github/pat",
		requireORAServiceJWT(serviceScopeConnectorsWrite, handleInternalGitHubPAT))
	mux.HandleFunc("/api/internal/connectors/github/install-url",
		requireORAServiceJWT(serviceScopeConnectorsWrite, handleInternalInstallURL))
	mux.HandleFunc("/api/internal/connectors/github/finish-install",
		requireORAServiceJWT(serviceScopeConnectorsWrite, handleInternalFinishInstall))
	mux.HandleFunc("/api/internal/connectors/",
		requireORAServiceJWT(serviceScopeConnectorsWrite, handleInternalConnectorSub))
}

func requireORAServiceJWT(scope string, next func(http.ResponseWriter, *http.Request, *openauth.ServiceClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret := []byte(strings.TrimSpace(os.Getenv("OPEN_SERVICE_JWT_SECRET")))
		if len(secret) == 0 {
			http.Error(w, "service auth disabled", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		claims, err := validatePeerAuthToken(token, "ora-api", scope)
		if err != nil {
			if err == openauth.ErrMissingScope {
				http.Error(w, "missing scope", http.StatusForbidden)
				return
			}
			http.Error(w, "invalid service token", http.StatusUnauthorized)
			return
		}
		if iss := strings.TrimSpace(claims.Issuer); iss != "" && iss != "oam-api" {
			http.Error(w, "forbidden issuer", http.StatusForbidden)
			return
		}
		next(w, r, claims)
	}
}

// prepareInternalConnectorRequest injects delegated user identity from OAM and
// marks the request so refuseOAMLocalWrite allows the underlying handler.
func prepareInternalConnectorRequest(r *http.Request, claims *openauth.ServiceClaims) *http.Request {
	r = withPeerOAMWrite(r)
	if u := strings.TrimSpace(r.Header.Get(headerDelegatedUsername)); u != "" {
		r.Header.Set("X-User-Username", u)
	}
	if role := strings.TrimSpace(r.Header.Get(headerDelegatedRole)); role != "" {
		r.Header.Set("X-User-Role", role)
	} else {
		r.Header.Set("X-User-Role", "admin")
	}
	if proj := strings.TrimSpace(r.Header.Get(headerDelegatedProjectID)); proj != "" {
		r.Header.Set("X-Project-ID", proj)
	}
	personal := strings.EqualFold(
		strings.TrimSpace(r.Header.Get(headerDelegatedAccountType)),
		openauth.AccountTypePersonal,
	)
	if personal {
		// Personal Open sessions bind by user_id; do not inherit a service JWT org.
		r.Header.Del("X-Organization-ID")
	} else if org := strings.TrimSpace(r.Header.Get("X-Organization-ID")); org == "" && claims != nil {
		if co := strings.TrimSpace(claims.OrgID); co != "" {
			r.Header.Set("X-Organization-ID", co)
		}
	}
	return r
}

func handleInternalGitHubPAT(w http.ResponseWriter, r *http.Request, claims *openauth.ServiceClaims) {
	handleGitHubPATConnect(w, prepareInternalConnectorRequest(r, claims))
}

func handleInternalInstallURL(w http.ResponseWriter, r *http.Request, claims *openauth.ServiceClaims) {
	handleGitHubInstallURL(w, prepareInternalConnectorRequest(r, claims))
}

func handleInternalFinishInstall(w http.ResponseWriter, r *http.Request, claims *openauth.ServiceClaims) {
	handleGitHubFinishInstall(w, prepareInternalConnectorRequest(r, claims))
}

func handleInternalConnectorSub(w http.ResponseWriter, r *http.Request, claims *openauth.ServiceClaims) {
	r = prepareInternalConnectorRequest(r, claims)
	path := strings.TrimPrefix(r.URL.Path, "/api/internal/connectors/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" || parts[0] == "github" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPatch, http.MethodPut:
			handleConnectorPatch(w, r, id)
			return
		case http.MethodDelete:
			handleConnectorDelete(w, r, id)
			return
		case http.MethodGet:
			handleConnectorGet(w, r, id)
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
	if len(parts) >= 2 && parts[1] == "repos" && r.Method == http.MethodGet {
		handleConnectorRepos(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "permissions" && r.Method == http.MethodGet {
		handleConnectorPermissions(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "claim" && r.Method == http.MethodPost {
		handleConnectorClaim(w, r, id)
		return
	}
	if len(parts) >= 2 && parts[1] == "watched" {
		switch r.Method {
		case http.MethodGet:
			handleWatchedList(w, r, id)
		case http.MethodPut:
			handleWatchedPut(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}
