package main

import (
	"context"
	"fmt"
	"net/http"
)

const oamCredentialHomeMsg = "credentials and connector configuration are managed by OAM when PEER_OAM_URL is set — use OAM /api/credentials and /api/connectors"

type ctxKeyPeerOAMWrite struct{}

// withPeerOAMWrite marks a request as an OAM→ORA service peer write so
// refuseOAMLocalWrite allows the handler to run (browser PAT/patch/delete/claim
// stay refused when PEER_OAM_URL is set).
func withPeerOAMWrite(r *http.Request) *http.Request {
	if r == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), ctxKeyPeerOAMWrite{}, true))
}

func isPeerOAMConnectorWrite(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(ctxKeyPeerOAMWrite{}).(bool)
	return v
}

// localOAMWritesBlocked reports whether ORA must refuse local credential/connector
// writes that bypass the OAM account plane.
func localOAMWritesBlocked() bool {
	return peerProductConfigured("PEER_OAM_URL")
}

func errOAMCredentialHome() error {
	if localOAMWritesBlocked() {
		return fmt.Errorf("%s", oamCredentialHomeMsg)
	}
	return nil
}

// refuseOAMLocalWrite rejects browser-facing credential/connector writes when
// PEER_OAM_URL is set. Internal OAM peer paths (withPeerOAMWrite) are exempt.
func refuseOAMLocalWrite(w http.ResponseWriter, r *http.Request) bool {
	if !localOAMWritesBlocked() {
		return false
	}
	if isPeerOAMConnectorWrite(r) {
		return false
	}
	writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
		"ok":      false,
		"error":   "credentials_home_oam",
		"message": oamCredentialHomeMsg,
	})
	return true
}
