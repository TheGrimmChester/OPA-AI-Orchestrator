package main

import (
	"strings"
	"sync"
	"time"
)

// installIntent records that an Open user started a GitHub App install from
// install-url. When GitHub only delivers the installation webhook (Setup URL
// missing / callback never hit), the connector stays pending_claim and is
// invisible on lists. finish-install uses a recent intent (or an explicit
// installation_id) to bind that pending into the caller's Open tenant — no
// GitHub account↔Open OAuth link required.
type installIntent struct {
	Key       string
	OrgID     string
	ProjectID string
	UserID    string
	Personal  bool
	MintedAt  time.Time
	ExpiresAt time.Time
}

var (
	installIntentMu sync.Mutex
	installIntents  = map[string]installIntent{} // key → intent
)

const installIntentTTL = 45 * time.Minute

func installIntentKey(userID, orgID string, personal bool) string {
	userID = strings.TrimSpace(userID)
	orgID = strings.TrimSpace(orgID)
	if personal || orgID == "" {
		return "user:" + userID
	}
	return "org:" + orgID + "|user:" + userID
}

func rememberInstallIntent(orgID, projectID, userID string, personal bool) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return
	}
	orgID = strings.TrimSpace(orgID)
	projectID = strings.TrimSpace(projectID)
	if projectID == "" || projectID == tenantAll {
		projectID = defaultProjectID
	}
	if personal {
		orgID = ""
	}
	now := time.Now().UTC()
	key := installIntentKey(userID, orgID, personal)
	installIntentMu.Lock()
	defer installIntentMu.Unlock()
	pruneInstallIntentsLocked(now)
	installIntents[key] = installIntent{
		Key:       key,
		OrgID:     orgID,
		ProjectID: projectID,
		UserID:    userID,
		Personal:  personal,
		MintedAt:  now,
		ExpiresAt: now.Add(installIntentTTL),
	}
}

func pruneInstallIntentsLocked(now time.Time) {
	for k, intent := range installIntents {
		if !intent.ExpiresAt.After(now) {
			delete(installIntents, k)
		}
	}
}

func peekInstallIntent(userID, orgID string, personal bool) (installIntent, bool) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return installIntent{}, false
	}
	key := installIntentKey(userID, orgID, personal)
	installIntentMu.Lock()
	defer installIntentMu.Unlock()
	pruneInstallIntentsLocked(time.Now().UTC())
	intent, ok := installIntents[key]
	return intent, ok
}

func consumeInstallIntent(userID, orgID string, personal bool) (installIntent, bool) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return installIntent{}, false
	}
	key := installIntentKey(userID, orgID, personal)
	installIntentMu.Lock()
	defer installIntentMu.Unlock()
	pruneInstallIntentsLocked(time.Now().UTC())
	intent, ok := installIntents[key]
	if !ok {
		return installIntent{}, false
	}
	delete(installIntents, key)
	return intent, true
}
