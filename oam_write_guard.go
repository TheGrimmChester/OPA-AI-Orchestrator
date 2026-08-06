package main

import (
	"fmt"
	"net/http"
)

const oamCredentialHomeMsg = "credentials and connector configuration are managed by OAM when PEER_OAM_URL is set — use OAM /api/credentials and /api/connectors"

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

func refuseOAMLocalWrite(w http.ResponseWriter) bool {
	if !localOAMWritesBlocked() {
		return false
	}
	writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{
		"ok":      false,
		"error":   "credentials_home_oam",
		"message": oamCredentialHomeMsg,
	})
	return true
}
