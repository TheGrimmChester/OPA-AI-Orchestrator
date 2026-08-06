package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// Scoped secret persistence + fail-closed resolution for opa.scm_secrets.
//
// Job resolution order (documented for callers):
//  1. user-scoped secret for (org, userID) when userID is set
//  2. org-scoped secret for org
//  3. empty — fail closed
// Never: admin scope, process env API keys, or "any row" cross-tenant fallback.
//
// Admin-only resolution (WantAdminOnly): loads admin-scoped row only.

func ensureCredentialScopeColumns() {
	if queryClient == nil {
		return
	}
	for _, stmt := range []string{
		`ALTER TABLE opa.connectors ADD COLUMN IF NOT EXISTS scope LowCardinality(String) DEFAULT ''`,
		`ALTER TABLE opa.connectors ADD COLUMN IF NOT EXISTS user_id String DEFAULT ''`,
		`ALTER TABLE opa.scm_secrets ADD COLUMN IF NOT EXISTS scope LowCardinality(String) DEFAULT ''`,
		`ALTER TABLE opa.scm_secrets ADD COLUMN IF NOT EXISTS user_id String DEFAULT ''`,
	} {
		if err := queryClient.Execute(stmt); err != nil {
			log.Printf("[WARN] ensureCredentialScopeColumns: %v", err)
		}
	}
}

func persistSCMSecretScoped(org, proj, scope, userID, logicalKey, plaintext string, deleted bool) error {
	if err := errOAMCredentialHome(); err != nil {
		return err
	}
	if writer == nil {
		return nil
	}
	scope = inferLegacyScope(org, scope)
	if scope == credScopeUser && strings.TrimSpace(userID) == "" {
		return fmt.Errorf("user scope requires user_id")
	}
	storageKey := scmSecretStorageKey(logicalKey, scope, userID)
	ct := ""
	if !deleted && plaintext != "" {
		enc, err := encryptSecret(plaintext)
		if err != nil {
			return err
		}
		ct = enc
	}
	del := uint8(0)
	if deleted {
		del = 1
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	// Admin rows keep empty org/project so they never match tenant org queries.
	if scope == credScopeAdmin {
		org, proj, userID = "", "", ""
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"key": storageKey, "organization_id": org, "project_id": proj,
		"scope": scope, "user_id": userID,
		"ciphertext": ct, "updated_at": now, "deleted": del,
	})
	writer.insert("scm_secrets", append(payload, '\n'))
	return nil
}

// persistSCMSecret is the legacy org-scoped writer (compat for older call sites).
func persistSCMSecret(org, proj, key, plaintext string, deleted bool) error {
	return persistSCMSecretScoped(org, proj, credScopeOrg, "", key, plaintext, deleted)
}

type scmSecretHit struct {
	Plain string
	Scope string
	Org   string
	Proj  string
	User  string
}

func rowDeletedFlag(row map[string]interface{}) bool {
	switch v := row["deleted"].(type) {
	case uint8:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case bool:
		return v
	default:
		return false
	}
}

func decryptRowCiphertext(row map[string]interface{}) string {
	ct, _ := row["ciphertext"].(string)
	if !isEncryptedSecret(ct) {
		return ""
	}
	plain, err := decryptSecret(ct)
	if err != nil || plain == "" {
		return ""
	}
	return plain
}

// loadSCMSecretAtScope loads one exact scoped secret (no inheritance).
func loadSCMSecretAtScope(org, proj, scope, userID, logicalKey string) scmSecretHit {
	if queryClient == nil || logicalKey == "" {
		return scmSecretHit{}
	}
	scope = inferLegacyScope(org, scope)
	storageKey := scmSecretStorageKey(logicalKey, scope, userID)
	// Also accept legacy org rows stored under the bare logical key when scope=org.
	keys := []string{storageKey}
	if scope == credScopeOrg && storageKey == logicalKey {
		// already bare
	}
	q := fmt.Sprintf(`
		SELECT key, organization_id, project_id, scope, user_id, ciphertext, deleted
		FROM opa.scm_secrets
		WHERE key = '%s'
		ORDER BY updated_at DESC LIMIT 30`, escapeSQL(storageKey))
	rows, err := queryClient.Query(q)
	if err != nil || len(rows) == 0 {
		// Legacy: org secrets may exist without scope column / with bare key only.
		if scope == credScopeOrg {
			return loadLegacyOrgSecret(org, proj, logicalKey)
		}
		return scmSecretHit{}
	}
	// Newest matching row wins (ReplacingMergeTree may keep history). A tombstone
	// (deleted=1) must hide older ciphertext — do not fall through past deleted.
	for _, row := range rows {
		rowOrg, _ := row["organization_id"].(string)
		rowProj, _ := row["project_id"].(string)
		rowScope, _ := row["scope"].(string)
		rowUser, _ := row["user_id"].(string)
		rowKey, _ := row["key"].(string)
		logical, parsedScope, parsedUser := parseSCMSecretStorageKey(rowKey)
		if logical != "" && logical != logicalKey {
			continue
		}
		effScope := inferLegacyScope(rowOrg, nz(rowScope, parsedScope))
		effUser := nz(rowUser, parsedUser)
		if effScope != scope {
			continue
		}
		switch scope {
		case credScopeAdmin:
			// Admin rows must not be tenant-owned.
		case credScopeOrg:
			if org != "" && rowOrg != "" && rowOrg != org {
				continue
			}
			if proj != "" {
				if rowProj != "" && rowProj != proj {
					// Prefer exact project; allow org-wide (empty project) via second pass.
					continue
				}
			} else if rowProj != "" {
				// Org-wide lookup: ignore project-specific rows (including their tombstones).
				continue
			}
		case credScopeUser:
			if userID != "" && effUser != "" && effUser != userID {
				continue
			}
			if org != "" && rowOrg != "" && rowOrg != org {
				continue
			}
		}
		if rowDeletedFlag(row) {
			// Authoritative clear for this identity — do not resurrect older ciphertext.
			if scope == credScopeOrg && proj != "" && rowProj == proj {
				// Exact-project tombstone: still allow org-wide (empty project) fallback.
				return loadSCMSecretAtScope(org, "", scope, userID, logicalKey)
			}
			return scmSecretHit{}
		}
		if plain := decryptRowCiphertext(row); plain != "" {
			return scmSecretHit{Plain: plain, Scope: effScope, Org: rowOrg, Proj: rowProj, User: effUser}
		}
		// Undeleted but undecryptable — fail closed for this identity (don't resurrect older rows).
		return scmSecretHit{}
	}
	// Org: retry with project-agnostic match (org-wide defaults).
	if scope == credScopeOrg && proj != "" {
		return loadSCMSecretAtScope(org, "", scope, userID, logicalKey)
	}
	_ = keys
	return scmSecretHit{}
}

func loadLegacyOrgSecret(org, proj, logicalKey string) scmSecretHit {
	if queryClient == nil {
		return scmSecretHit{}
	}
	q := fmt.Sprintf(`
		SELECT key, organization_id, project_id, scope, user_id, ciphertext, deleted
		FROM opa.scm_secrets
		WHERE key = '%s'
		ORDER BY updated_at DESC LIMIT 30`, escapeSQL(logicalKey))
	rows, err := queryClient.Query(q)
	if err != nil || len(rows) == 0 {
		return scmSecretHit{}
	}
	pick := func(wantOrg, wantProj string) scmSecretHit {
		for _, row := range rows {
			rowOrg, _ := row["organization_id"].(string)
			rowProj, _ := row["project_id"].(string)
			rowScope, _ := row["scope"].(string)
			rowKey, _ := row["key"].(string)
			_, parsedScope, _ := parseSCMSecretStorageKey(rowKey)
			eff := inferLegacyScope(rowOrg, nz(rowScope, parsedScope))
			// Skip explicit admin/user rows when loading org legacy.
			if eff == credScopeAdmin || eff == credScopeUser {
				continue
			}
			if strings.Contains(rowKey, "#admin") || strings.Contains(rowKey, "#user:") {
				continue
			}
			if wantOrg != "" && rowOrg != "" && rowOrg != wantOrg {
				continue
			}
			if wantProj != "" && rowProj != "" && rowProj != wantProj {
				continue
			}
			// Newest matching identity wins — honor tombstones.
			if rowDeletedFlag(row) {
				return scmSecretHit{}
			}
			if plain := decryptRowCiphertext(row); plain != "" {
				return scmSecretHit{Plain: plain, Scope: credScopeOrg, Org: rowOrg, Proj: rowProj}
			}
			return scmSecretHit{}
		}
		return scmSecretHit{}
	}
	if org != "" {
		if h := pick(org, proj); h.Plain != "" {
			return h
		}
		if h := pick(org, ""); h.Plain != "" {
			return h
		}
	}
	// Fail closed: do NOT pick any org's legacy row when org is empty/unknown.
	return scmSecretHit{}
}

// resolveSCMSecret applies inheritance for tenant jobs.
// Returns plaintext + which scope won (user|org|"") — never admin.
func resolveSCMSecret(q credResolveQuery, logicalKey string) scmSecretHit {
	if q.WantAdminOnly {
		return loadSCMSecretAtScope("", "", credScopeAdmin, "", logicalKey)
	}
	if uid := strings.TrimSpace(q.UserID); uid != "" {
		if h := loadSCMSecretAtScope(q.OrganizationID, q.ProjectID, credScopeUser, uid, logicalKey); h.Plain != "" {
			return h
		}
	}
	if org := strings.TrimSpace(q.OrganizationID); org != "" {
		if h := loadSCMSecretAtScope(org, q.ProjectID, credScopeOrg, "", logicalKey); h.Plain != "" {
			return h
		}
	}
	return scmSecretHit{}
}

// loadSCMSecretPlain is the job-facing helper: user → org → fail closed.
func loadSCMSecretPlain(org, proj, key string) string {
	return resolveSCMSecret(credResolveQuery{OrganizationID: org, ProjectID: proj}, key).Plain
}

func loadSCMSecretPlainForActor(org, proj, userID, key string) string {
	return resolveSCMSecret(credResolveQuery{
		OrganizationID: org, ProjectID: proj, UserID: userID,
	}, key).Plain
}

// ensureOrgWideCLICursorKeys copies project-scoped org CLI keys to org-wide
// (empty project) rows when missing. Ciphertext is reused — no decrypt.
// Safe to run on every boot; ClickHouse ReplacingMergeTree keeps the newest.
func ensureOrgWideCLICursorKeys() int {
	if queryClient == nil || writer == nil {
		return 0
	}
	logical := scmCursorSecretKey
	rows, err := queryClient.Query(fmt.Sprintf(`
		SELECT organization_id, project_id, scope, user_id, ciphertext, deleted
		FROM opa.scm_secrets
		WHERE key = '%s'
		ORDER BY updated_at DESC LIMIT 200`, escapeSQL(logical)))
	if err != nil || len(rows) == 0 {
		return 0
	}
	type cand struct {
		org, ct string
	}
	haveWide := map[string]bool{}
	var projectKeys []cand
	for _, row := range rows {
		rowOrg, _ := row["organization_id"].(string)
		rowProj, _ := row["project_id"].(string)
		rowScope, _ := row["scope"].(string)
		rowUser, _ := row["user_id"].(string)
		ct, _ := row["ciphertext"].(string)
		if rowOrg == "" || ct == "" || rowDeletedFlag(row) {
			continue
		}
		eff := inferLegacyScope(rowOrg, rowScope)
		if eff == credScopeAdmin || eff == credScopeUser || strings.TrimSpace(rowUser) != "" {
			continue
		}
		if rowProj == "" {
			haveWide[rowOrg] = true
			continue
		}
		projectKeys = append(projectKeys, cand{org: rowOrg, ct: ct})
	}
	n := 0
	seeded := map[string]bool{}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	for _, c := range projectKeys {
		if haveWide[c.org] || seeded[c.org] {
			continue
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"key": logical, "organization_id": c.org, "project_id": "",
			"scope": credScopeOrg, "user_id": "",
			"ciphertext": c.ct, "updated_at": now, "deleted": uint8(0),
		})
		writer.insert("scm_secrets", append(payload, '\n'))
		seeded[c.org] = true
		haveWide[c.org] = true
		n++
		log.Printf("[INFO] boot: seeded org-wide CLI agent key for org=%s from project-scoped ciphertext", c.org)
	}
	return n
}
