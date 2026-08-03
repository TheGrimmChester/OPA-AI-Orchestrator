package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Roadmap generator + milestones-first publish (Projects v2 behind prefs flag).

func registerRoadmapMux(mux *http.ServeMux, authView, authAdmin func(string, http.HandlerFunc)) {
	authAdmin("/api/scm/roadmap/generate", handleRoadmapGenerate)
	authView("/api/scm/roadmap/runs", handleRoadmapRunsList)
	registerSCMAuthFlexible(mux, "/api/scm/roadmap/runs/", handleRoadmapRunSub)
	authAdmin("/api/scm/roadmap/publish", handleRoadmapPublish)
}

func handleRoadmapGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		RepoFullName  string   `json:"repo_full_name"`
		ConnectorID   string   `json:"connector_id"`
		Contexts      []string `json:"contexts"`
		Competitors   []string `json:"competitors"`
		AudienceNotes string   `json:"audience_notes"`
		Publish       bool     `json:"publish"`
	}
	if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.RepoFullName) == "" {
		http.Error(w, "repo_full_name required", 400)
		return
	}
	contexts := body.Contexts
	if len(contexts) == 0 {
		contexts = []string{"discovery", "features"}
	}
	job, err := enqueueRoadmapRun(body.RepoFullName, body.ConnectorID, contexts, body.Competitors, body.AudienceNotes, body.Publish, actorFromRequest(r).Username)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	go processSCMJob(job.ID)
	writeJSON(w, map[string]interface{}{"ok": true, "job_id": job.ID, "kind": job.Kind})
}

func handleRoadmapRunsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	out := []map[string]interface{}{}
	scmJobLive.Range(func(_, v interface{}) bool {
		j, ok := v.(*scmJob)
		if !ok || j == nil || agentKind(j.Kind) != kindRoadmapRun {
			return true
		}
		if repo != "" && !strings.EqualFold(j.RepoFullName, repo) {
			return true
		}
		out = append(out, map[string]interface{}{
			"id": j.ID, "repo_full_name": j.RepoFullName, "status": j.Status,
			"started_at": j.StartedAt, "finished_at": j.FinishedAt, "error": j.Error,
			"summary": roadmapSummaryPublic(j),
		})
		return true
	})
	writeJSON(w, map[string]interface{}{"ok": true, "runs": out})
}

func handleRoadmapRunSub(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/scm/roadmap/runs/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", 404)
		return
	}
	id := parts[0]
	job := getSCMJob(id)
	if job == nil || agentKind(job.Kind) != kindRoadmapRun {
		http.Error(w, "not found", 404)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, map[string]interface{}{
			"ok": true, "run": job, "artifacts": loadRoadmapArtifacts(job),
			"children": listRunChildren(job.ID),
		})
		return
	}
	http.Error(w, "not found", 404)
}

func handleRoadmapPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var body struct {
		JobID        string `json:"job_id"`
		RepoFullName string `json:"repo_full_name"`
		ConnectorID  string `json:"connector_id"`
	}
	if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.JobID) == "" {
		http.Error(w, "job_id required", 400)
		return
	}
	parent := getSCMJob(body.JobID)
	if parent == nil || agentKind(parent.Kind) != kindRoadmapRun {
		http.Error(w, "roadmap run not found", 404)
		return
	}
	prefs := agentPrefsFromSummary(parent)
	conn := getOrHydrateConnector(nz(body.ConnectorID, parent.ConnectorID))
	result, err := publishRoadmapToGitHub(parent, conn, prefs)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if parent.Summary == nil {
		parent.Summary = map[string]interface{}{}
	}
	parent.Summary["publish"] = result
	persistSCMJob(parent)
	writeJSON(w, map[string]interface{}{"ok": true, "publish": result})
}

func enqueueRoadmapRun(repo, connectorID string, contexts, competitors []string, audienceNotes string, autoPublish bool, actor string) (*scmJob, error) {
	repo = strings.TrimSpace(repo)
	wr, conn := findWatched(repo)
	if conn == nil && connectorID != "" {
		conn = getOrHydrateConnector(connectorID)
	}
	if wr == nil && conn == nil {
		return nil, fmt.Errorf("repo not watched and no connector")
	}
	org, proj, connID := "", "", ""
	if wr != nil {
		org, proj, connID = wr.OrganizationID, wr.ProjectID, wr.ConnectorID
	}
	if conn != nil {
		org, proj, connID = conn.OrganizationID, conn.ProjectID, conn.ID
	}
	prefs, sources := resolveAgentPrefs(org, proj, connID, repo)
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	id := loadID("scmjob", org, proj, repo, "roadmap", newRandomHex(6))
	parent := &scmJob{
		ID: id, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, Event: "manual.roadmap", Status: "queued",
		CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, ActorUserID: actor,
		Kind: string(kindRoadmapRun), RunID: id, ParentID: "", Attempt: 1,
	}
	parent.Summary["prefs"] = prefs
	parent.Summary["prefs_sources"] = sources
	parent.Summary["contexts"] = contexts
	parent.Summary["competitors"] = competitors
	parent.Summary["audience_notes"] = audienceNotes
	parent.Summary["auto_publish"] = autoPublish

	genID := loadID("scmjob", org, proj, repo, "roadmap_generate", id)
	gen := &scmJob{
		ID: genID, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
		RepoFullName: repo, Event: parent.Event, Status: "queued",
		CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
		StartedAt: now, FinishedAt: now, ActorUserID: actor,
		Kind: string(kindRoadmapGenerate), RunID: id, ParentID: id, Attempt: 1,
	}
	childIDs := []string{genID}
	scmJobLive.Store(genID, gen)
	persistSCMJob(gen)

	if autoPublish {
		pubID := loadID("scmjob", org, proj, repo, "roadmap_publish", id)
		pub := &scmJob{
			ID: pubID, OrganizationID: org, ProjectID: proj, ConnectorID: connID,
			RepoFullName: repo, Event: parent.Event, Status: "queued",
			CheckRunIDs: map[string]int64{}, Summary: map[string]interface{}{},
			StartedAt: now, FinishedAt: now, ActorUserID: actor,
			Kind: string(kindRoadmapPublish), RunID: id, ParentID: id, Attempt: 1,
		}
		scmJobLive.Store(pubID, pub)
		persistSCMJob(pub)
		childIDs = append(childIDs, pubID)
	}
	parent.Summary["child_ids"] = childIDs
	scmJobLive.Store(id, parent)
	persistSCMJob(parent)
	return parent, nil
}

func roadmapSummaryPublic(j *scmJob) map[string]interface{} {
	if j == nil || j.Summary == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	for _, k := range []string{"contexts", "publish", "roadmap", "discovery", "competitor_analysis", "auto_publish"} {
		if v, ok := j.Summary[k]; ok {
			out[k] = v
		}
	}
	return out
}

func roadmapArtifactsDir(job *scmJob) string {
	id := job.RunID
	if id == "" {
		id = job.ID
	}
	return filepath.Join(scmStateDir(), "roadmap-artifacts", id)
}

func loadRoadmapArtifacts(job *scmJob) map[string]interface{} {
	dir := roadmapArtifactsDir(job)
	out := map[string]interface{}{}
	for _, name := range []string{"roadmap_discovery.json", "competitor_analysis.json", "roadmap.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var obj interface{}
		if json.Unmarshal(raw, &obj) == nil {
			out[name] = obj
		} else {
			out[name] = string(raw)
		}
	}
	return out
}

func runRoadmapGenerateAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	parent := getSCMJob(job.RunID)
	contexts := []string{"discovery", "features"}
	competitors := []string{}
	audience := ""
	if parent != nil && parent.Summary != nil {
		if v, ok := parent.Summary["contexts"].([]interface{}); ok {
			contexts = nil
			for _, x := range v {
				if s, ok := x.(string); ok {
					contexts = append(contexts, s)
				}
			}
		} else if v, ok := parent.Summary["contexts"].([]string); ok {
			contexts = v
		}
		if v, ok := parent.Summary["competitors"].([]interface{}); ok {
			for _, x := range v {
				if s, ok := x.(string); ok {
					competitors = append(competitors, s)
				}
			}
		} else if v, ok := parent.Summary["competitors"].([]string); ok {
			competitors = v
		}
		audience = strFromAny(parent.Summary["audience_notes"])
	}

	conn := getOrHydrateConnector(job.ConnectorID)
	wtID := "roadmap-" + job.RunID
	abs, _, meta, err := prepareSCMWorktree(conn, job.RepoFullName, "", 0, wtID)
	if err != nil && !githubUseMockAPI(conn) {
		job.Summary["checkout_error"] = err.Error()
	}
	job.Summary["checkout_path"] = abs
	if meta != nil {
		job.Summary["worktree"] = meta
	}

	dir := roadmapArtifactsDir(job)
	_ = os.MkdirAll(dir, 0o700)

	wantCompetitor := false
	wantDiscovery := false
	wantFeatures := false
	wantAudience := audience != ""
	for _, c := range contexts {
		switch strings.ToLower(strings.TrimSpace(c)) {
		case "competitor", "competitors":
			wantCompetitor = true
		case "discovery":
			wantDiscovery = true
		case "features", "feature":
			wantFeatures = true
		case "audience":
			wantAudience = true
		}
	}
	if !wantDiscovery && !wantFeatures {
		wantDiscovery, wantFeatures = true, true
	}

	ctx := context.Background()
	credQ := credResolveQuery{OrganizationID: job.OrganizationID, ProjectID: job.ProjectID, UserID: job.ActorUserID}

	competitorObj := map[string]interface{}{}
	if wantCompetitor {
		prompt := buildCompetitorPrompt(job.RepoFullName, competitors, abs)
		res, cerr := CompleteFor(ctx, "roadmap_competitor", aiCompleteRequest{
			System: "OPA Roadmap Competitor Analyst. Return JSON only.",
			Prompt: prompt, MaxTokens: 4096,
		}, credQ)
		if cerr != nil {
			competitorObj = heuristicCompetitorAnalysis(job.RepoFullName, competitors)
			competitorObj["honesty"] = cerr.Error()
		} else {
			competitorObj = parseJSONObject(res.Text, heuristicCompetitorAnalysis(job.RepoFullName, competitors))
		}
		raw, _ := json.MarshalIndent(competitorObj, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "competitor_analysis.json"), raw, 0o600)
		job.Summary["competitor_analysis"] = competitorObj
	}

	discovery := map[string]interface{}{}
	if wantDiscovery || wantAudience {
		prompt := buildDiscoveryPrompt(job.RepoFullName, abs, audience, competitorObj)
		res, cerr := CompleteFor(ctx, "roadmap_discovery", aiCompleteRequest{
			System: "OPA Roadmap Discovery Agent. Return JSON only.",
			Prompt: prompt, MaxTokens: 4096,
		}, credQ)
		if cerr != nil {
			discovery = heuristicDiscovery(job.RepoFullName, audience)
			discovery["honesty"] = cerr.Error()
		} else {
			discovery = parseJSONObject(res.Text, heuristicDiscovery(job.RepoFullName, audience))
		}
		raw, _ := json.MarshalIndent(discovery, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "roadmap_discovery.json"), raw, 0o600)
		job.Summary["discovery"] = discovery
	}

	roadmap := map[string]interface{}{}
	if wantFeatures {
		prompt := buildFeaturesPrompt(job.RepoFullName, discovery, competitorObj)
		res, cerr := CompleteFor(ctx, "roadmap_features", aiCompleteRequest{
			System: "OPA Roadmap Features Agent. Return JSON only.",
			Prompt: prompt, MaxTokens: 6144,
		}, credQ)
		if cerr != nil {
			roadmap = heuristicRoadmap(job.RepoFullName, discovery)
			roadmap["honesty"] = cerr.Error()
		} else {
			roadmap = parseJSONObject(res.Text, heuristicRoadmap(job.RepoFullName, discovery))
		}
		if err := validateRoadmapJSON(roadmap); err != nil {
			job.Summary["roadmap_validation"] = err.Error()
			// Keep artifact but mark honesty.
			roadmap["validation_error"] = err.Error()
		}
		raw, _ := json.MarshalIndent(roadmap, "", "  ")
		_ = os.WriteFile(filepath.Join(dir, "roadmap.json"), raw, 0o600)
		job.Summary["roadmap"] = roadmap
	}

	persistSCMJob(job)
	if parent != nil {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		for _, k := range []string{"discovery", "competitor_analysis", "roadmap", "checkout_path"} {
			if v, ok := job.Summary[k]; ok {
				parent.Summary[k] = v
			}
		}
		persistSCMJob(parent)
	}
	return nil
}

func runRoadmapPublishAgent(job *scmJob) error {
	parent := getSCMJob(job.RunID)
	if parent == nil {
		parent = job
	}
	prefs := agentPrefsFromSummary(parent)
	conn := getOrHydrateConnector(job.ConnectorID)
	result, err := publishRoadmapToGitHub(parent, conn, prefs)
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["publish"] = result
	persistSCMJob(job)
	if parent != nil && parent.ID != job.ID {
		if parent.Summary == nil {
			parent.Summary = map[string]interface{}{}
		}
		parent.Summary["publish"] = result
		persistSCMJob(parent)
	}
	return err
}

func publishRoadmapToGitHub(parent *scmJob, conn *opaConnector, prefs agentPrefs) (map[string]interface{}, error) {
	if parent == nil {
		return nil, fmt.Errorf("missing roadmap run")
	}
	roadmap := map[string]interface{}{}
	if parent.Summary != nil {
		if r, ok := parent.Summary["roadmap"].(map[string]interface{}); ok {
			roadmap = r
		}
	}
	if len(roadmap) == 0 {
		arts := loadRoadmapArtifacts(parent)
		if r, ok := arts["roadmap.json"].(map[string]interface{}); ok {
			roadmap = r
		}
	}
	if len(roadmap) == 0 {
		return nil, fmt.Errorf("no roadmap.json artifact")
	}
	owner, repoName := splitOwnerRepo(parent.RepoFullName)
	gateLabels := prefs.AIIssueLabels
	if len(gateLabels) == 0 {
		gateLabels = []string{"AI"}
	}

	createdMilestones := []map[string]interface{}{}
	createdIssues := []map[string]interface{}{}

	phases, _ := roadmap["phases"].([]interface{})
	featuresByID := map[string]map[string]interface{}{}
	if feats, ok := roadmap["features"].([]interface{}); ok {
		for _, f := range feats {
			fm, ok := f.(map[string]interface{})
			if !ok {
				continue
			}
			id := strFromAny(fm["id"])
			if id == "" {
				id = strFromAny(fm["feature_id"])
			}
			if id != "" {
				featuresByID[id] = fm
			}
		}
	}

	for _, ph := range phases {
		pm, ok := ph.(map[string]interface{})
		if !ok {
			continue
		}
		phaseName := nz(strFromAny(pm["name"]), strFromAny(pm["id"]))
		msList, _ := pm["milestones"].([]interface{})
		if len(msList) == 0 {
			msList = []interface{}{map[string]interface{}{
				"title": phaseName, "description": strFromAny(pm["description"]),
				"features": pm["features"],
			}}
		}
		for _, msi := range msList {
			ms, ok := msi.(map[string]interface{})
			if !ok {
				continue
			}
			title := nz(strFromAny(ms["title"]), phaseName)
			desc := strFromAny(ms["description"])
			msMeta, err := githubFindOrCreateMilestone(conn, owner, repoName, title, desc)
			if err != nil {
				return nil, err
			}
			createdMilestones = append(createdMilestones, map[string]interface{}{
				"number": msMeta.Number, "title": msMeta.Title, "url": msMeta.HTMLURL,
			})
			featIDs := []string{}
			switch v := ms["features"].(type) {
			case []interface{}:
				for _, x := range v {
					featIDs = append(featIDs, fmt.Sprint(x))
				}
			case []string:
				featIDs = append(featIDs, v...)
			}
			for _, fid := range featIDs {
				fm := featuresByID[fid]
				if fm == nil {
					fm = map[string]interface{}{"id": fid, "title": fid, "description": ""}
				}
				ftitle := nz(strFromAny(fm["title"]), fid)
				fbody := formatRoadmapIssueBody(parent.ID, fid, fm)
				issue, err := githubCreateIssue(conn, owner, repoName, ftitle, fbody, gateLabels, msMeta.Number)
				if err != nil {
					return nil, err
				}
				createdIssues = append(createdIssues, map[string]interface{}{
					"number": issue.Number, "title": issue.Title, "url": issue.HTMLURL,
					"feature_id": fid, "milestone": msMeta.Number,
				})
			}
		}
	}

	result := map[string]interface{}{
		"milestones": createdMilestones,
		"issues":     createdIssues,
		"projects_v2": map[string]interface{}{
			"enabled": prefs.RoadmapProjectsV2,
			"status":  "skipped",
		},
	}
	if prefs.RoadmapProjectsV2 {
		projRes, perr := publishRoadmapProjectsV2(conn, owner, parent.RepoFullName, createdIssues)
		result["projects_v2"] = projRes
		if perr != nil {
			result["projects_v2_error"] = perr.Error()
		}
	}
	return result, nil
}

func formatRoadmapIssueBody(runID, featureID string, fm map[string]interface{}) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", strFromAny(fm["description"]))
	if ac, ok := fm["acceptance_criteria"].([]interface{}); ok && len(ac) > 0 {
		b.WriteString("## Acceptance criteria\n")
		for _, x := range ac {
			fmt.Fprintf(&b, "- %v\n", x)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "<!-- opa-roadmap run=%s feature=%s -->\n", runID, featureID)
	return b.String()
}

func parseJSONObject(text string, fallback map[string]interface{}) map[string]interface{} {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)
	var out map[string]interface{}
	if json.Unmarshal([]byte(text), &out) == nil && out != nil {
		return out
	}
	return fallback
}

func validateRoadmapJSON(rm map[string]interface{}) error {
	if rm == nil {
		return fmt.Errorf("nil roadmap")
	}
	if _, ok := rm["phases"]; !ok {
		return fmt.Errorf("roadmap missing phases")
	}
	return nil
}

func buildCompetitorPrompt(repo string, competitors []string, checkout string) string {
	return fmt.Sprintf(`Analyze competitors for repo %s.
Competitors: %v
Checkout: %s
Return JSON: {"competitors":[{"name":"...","strengths":[],"weaknesses":[],"gaps":[]}],"market_gaps":[],"differentiators":[]}
`, repo, competitors, checkout)
}

func buildDiscoveryPrompt(repo, checkout, audience string, competitor map[string]interface{}) string {
	compRaw, _ := json.Marshal(competitor)
	return fmt.Sprintf(`Discover product roadmap context for %s.
Audience notes: %s
Checkout: %s
Competitor analysis (may be empty): %s
Return JSON with project_name, project_type, tech_stack, target_audience, product_vision, current_state, competitive_context, constraints, created_at.
`, repo, audience, checkout, string(compRaw))
}

func buildFeaturesPrompt(repo string, discovery, competitor map[string]interface{}) string {
	dRaw, _ := json.Marshal(discovery)
	cRaw, _ := json.Marshal(competitor)
	return fmt.Sprintf(`Create a phased product roadmap for %s.
Discovery: %s
Competitor: %s
Return JSON:
{
  "id":"roadmap-...",
  "project_name":"...",
  "vision":"...",
  "phases":[{"id":"phase-1","name":"...","order":1,"features":["feature-1"],"milestones":[{"id":"m1","title":"...","features":["feature-1"]}]}],
  "features":[{"id":"feature-1","title":"...","description":"...","priority":"must|should|could","complexity":"low|medium|high","acceptance_criteria":[]}]
}
`, repo, string(dRaw), string(cRaw))
}

func heuristicCompetitorAnalysis(repo string, competitors []string) map[string]interface{} {
	list := []map[string]interface{}{}
	for _, c := range competitors {
		list = append(list, map[string]interface{}{
			"name": c, "strengths": []string{}, "weaknesses": []string{}, "gaps": []string{},
		})
	}
	if len(list) == 0 {
		list = append(list, map[string]interface{}{"name": "generic alternatives", "gaps": []string{"deeper automation"}})
	}
	return map[string]interface{}{
		"competitors": list, "market_gaps": []string{"autonomous issue→PR with approval gates"},
		"differentiators": []string{repo + " multi-tenant SCM orchestration"},
	}
}

func heuristicDiscovery(repo, audience string) map[string]interface{} {
	return map[string]interface{}{
		"project_name": repo,
		"project_type": "other",
		"tech_stack":   map[string]interface{}{"primary_language": "unknown", "frameworks": []string{}},
		"target_audience": map[string]interface{}{
			"primary_persona": nz(audience, "engineering teams"),
			"pain_points":     []string{"manual triage", "roadmap drift"},
		},
		"product_vision": map[string]interface{}{
			"one_liner": "Ship safer changes with AI-assisted planning and implementation",
		},
		"current_state": map[string]interface{}{"maturity": "mvp", "known_gaps": []string{}},
		"competitive_context": map[string]interface{}{
			"alternatives": []string{}, "competitor_analysis_available": false,
		},
		"constraints": map[string]interface{}{"technical": []string{}},
		"created_at":  time.Now().UTC().Format(time.RFC3339),
	}
}

func heuristicRoadmap(repo string, discovery map[string]interface{}) map[string]interface{} {
	vision := ""
	if pv, ok := discovery["product_vision"].(map[string]interface{}); ok {
		vision = strFromAny(pv["one_liner"])
	}
	return map[string]interface{}{
		"id":           "roadmap-" + time.Now().UTC().Format("20060102T150405Z"),
		"project_name": repo,
		"vision":       nz(vision, "Improve "+repo),
		"phases": []interface{}{
			map[string]interface{}{
				"id": "phase-1", "name": "Foundation", "order": 1,
				"features": []string{"feature-1"},
				"milestones": []interface{}{
					map[string]interface{}{
						"id": "milestone-1-1", "title": "MVP automation",
						"features": []string{"feature-1"},
					},
				},
			},
		},
		"features": []interface{}{
			map[string]interface{}{
				"id": "feature-1", "title": "AI-labelled issue investigate",
				"description": "Automatically investigate issues tagged AI and post a plan.",
				"priority":    "must", "complexity": "medium",
				"acceptance_criteria": []string{"Label AI enqueues investigate job", "Plan comment posted"},
			},
		},
	}
}
