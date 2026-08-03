package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	jobEvidenceSchemaVersion = 1
	jobEvidencePreviewBytes  = 12 * 1024
)

// JobEvidence is the versioned, structured contract for Dashboard / org / client views.
type JobEvidence struct {
	SchemaVersion int                    `json:"schema_version"`
	Identity      JobEvidenceIdentity    `json:"identity"`
	Status        JobEvidenceStatus      `json:"status"`
	Context       JobEvidenceContext     `json:"context"`
	Chat          JobEvidenceChat        `json:"chat"`
	Results       map[string]interface{} `json:"results"`
	Posts         []JobEvidencePost      `json:"posts"`
	Findings      []map[string]interface{} `json:"findings,omitempty"`
	AutoFixes     interface{}            `json:"auto_fixes,omitempty"`
	ArtifactRefs  []JobEvidenceArtifact  `json:"artifact_refs,omitempty"`
	Sections      JobEvidenceSections    `json:"sections"`
}

type JobEvidenceIdentity struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Attempt        int    `json:"attempt"`
	RunID          string `json:"run_id,omitempty"`
	ParentID       string `json:"parent_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	RepoFullName   string `json:"repo_full_name,omitempty"`
	PRNumber       int    `json:"pr_number,omitempty"`
	CommitSHA      string `json:"commit_sha,omitempty"`
}

type JobEvidenceStatus struct {
	Status     string   `json:"status"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Error      string   `json:"error,omitempty"`
	SkipReason string   `json:"skip_reason,omitempty"`
	Degraded   []string `json:"degraded,omitempty"`
	Honesty    string   `json:"honesty,omitempty"`
}

type JobEvidenceContext struct {
	Prefs           interface{}            `json:"prefs,omitempty"`
	PrefsSources    interface{}            `json:"prefs_sources,omitempty"`
	ReviewContexts  interface{}            `json:"review_contexts,omitempty"`
	CheckoutPath    string                 `json:"checkout_path,omitempty"`
	CheckoutRel     string                 `json:"checkout_rel,omitempty"`
	Worktree        interface{}            `json:"worktree,omitempty"`
	RelatedRepos    interface{}            `json:"related_repos,omitempty"`
	RelatedCheckouts interface{}           `json:"related_checkouts,omitempty"`
	BriefPreview    string                 `json:"brief_preview,omitempty"`
	BriefArtifact   string                 `json:"brief_artifact,omitempty"`
	Extra           map[string]interface{} `json:"extra,omitempty"`
}

type JobEvidenceChatPart struct {
	UnitID  string `json:"unit_id,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
}

type JobEvidenceChat struct {
	Model            string                `json:"model,omitempty"`
	PromptPreview    string                `json:"prompt_preview,omitempty"`
	Transcript       string                `json:"transcript,omitempty"`
	TranscriptArtifact string              `json:"transcript_artifact,omitempty"`
	Parts            []JobEvidenceChatPart `json:"parts,omitempty"`
	Usage            string                `json:"usage,omitempty"`
}

type JobEvidencePost struct {
	Type      string `json:"type"` // resume|inline|decision|suggest|check_run|other
	Target    string `json:"target,omitempty"`
	GitHubID  int64  `json:"github_id,omitempty"`
	URL       string `json:"url,omitempty"`
	Body      string `json:"body,omitempty"`
	BodyPreview string `json:"body_preview,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	Status    string `json:"status,omitempty"` // created|updated|resolved|skipped
	FindingKey string `json:"finding_key,omitempty"`
}

type JobEvidenceArtifact struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	Bytes int   `json:"bytes"`
	Kind string `json:"kind,omitempty"` // brief|transcript|post|checkup_stdout|other
}

type JobEvidenceSections struct {
	HasContext  bool `json:"has_context"`
	HasChat     bool `json:"has_chat"`
	HasResults  bool `json:"has_results"`
	HasPosts    bool `json:"has_posts"`
	HasFindings bool `json:"has_findings"`
	HasAutoFixes bool `json:"has_auto_fixes"`
	FindingCount int `json:"finding_count"`
	PostCount    int `json:"post_count"`
}

func jobArtifactsDir(jobID string) string {
	return filepath.Join(scmJobsStateDir(), strings.TrimSpace(jobID), "artifacts")
}

func ensureJobArtifactsDir(jobID string) (string, error) {
	dir := jobArtifactsDir(jobID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// writeJobArtifact stores a durable blob under scm-state/jobs/{id}/artifacts/.
func writeJobArtifact(jobID, name, kind, body string) (JobEvidenceArtifact, error) {
	ref := JobEvidenceArtifact{Name: name, Kind: kind}
	if strings.TrimSpace(jobID) == "" || strings.TrimSpace(name) == "" {
		return ref, fmt.Errorf("job id and artifact name required")
	}
	name = filepath.Base(name)
	dir, err := ensureJobArtifactsDir(jobID)
	if err != nil {
		return ref, err
	}
	path := filepath.Join(dir, name)
	data := []byte(body)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return ref, err
	}
	ref.Path = path
	ref.Bytes = len(data)
	return ref, nil
}

func copyFileToJobArtifact(jobID, name, kind, srcPath string) (JobEvidenceArtifact, error) {
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return JobEvidenceArtifact{}, err
	}
	return writeJobArtifact(jobID, name, kind, string(redactJobOutput(raw)))
}

func evidencePreview(s string) string {
	return truncateStr(s, jobEvidencePreviewBytes)
}

func loadEvidencePosts(job *scmJob) []JobEvidencePost {
	if job == nil || job.Summary == nil {
		return nil
	}
	raw, ok := job.Summary["evidence"]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var ev JobEvidence
	if json.Unmarshal(b, &ev) != nil {
		return nil
	}
	return ev.Posts
}

// appendEvidencePost records a GitHub (or mock) message onto the job evidence bag.
// Safe to call mid-run; finalizeJobEvidence merges these posts.
func appendEvidencePost(job *scmJob, post JobEvidencePost) {
	if job == nil {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	if post.CreatedAt == "" {
		post.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if post.Body != "" && post.BodyPreview == "" {
		post.BodyPreview = evidencePreview(post.Body)
	}
	// Persist full body as artifact when large.
	if len(post.Body) > jobEvidencePreviewBytes {
		safe := fmt.Sprintf("post-%s-%d.md", sanitizeArtifactName(post.Type), post.GitHubID)
		if post.GitHubID == 0 {
			safe = fmt.Sprintf("post-%s-%d.md", sanitizeArtifactName(post.Type), time.Now().UnixNano())
		}
		if ref, err := writeJobArtifact(job.ID, safe, "post", post.Body); err == nil {
			post.Body = evidencePreview(post.Body)
			_ = ref
		} else {
			post.Body = evidencePreview(post.Body)
		}
	}
	var posts []JobEvidencePost
	if raw, ok := job.Summary["evidence_posts"]; ok && raw != nil {
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &posts)
	}
	// Also merge from existing evidence.posts if evidence_posts missing.
	if len(posts) == 0 {
		posts = loadEvidencePosts(job)
	}
	posts = append(posts, post)
	job.Summary["evidence_posts"] = posts
}

func sanitizeArtifactName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "other"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "other"
	}
	return out
}

func degradedFromSummary(sum map[string]interface{}) []string {
	if sum == nil {
		return nil
	}
	switch v := sum["degraded"].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s := strFromAny(x); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func buildKindResults(job *scmJob) map[string]interface{} {
	if job == nil || job.Summary == nil {
		return map[string]interface{}{}
	}
	sum := job.Summary
	out := map[string]interface{}{"kind": job.Kind}
	switch agentKind(job.Kind) {
	case kindPrepare:
		for _, k := range []string{
			"checkout_path", "checkout_rel", "checkout_error", "checkout_fallback",
			"worktree", "related_checkouts", "related_repos", "sandbox_tree",
			"sandbox_file_count", "sandbox_fallback", "sandbox_tree_error",
		} {
			if v, ok := sum[k]; ok {
				out[k] = v
			}
		}
	case kindSecurity:
		if v, ok := sum["gate"]; ok {
			out["gate"] = v
		}
		if job.SecurityRunID != "" {
			out["security_run_id"] = job.SecurityRunID
		}
		if v, ok := sum["publish_refused"]; ok {
			out["publish_refused"] = v
		}
	case kindBugbot:
		if v, ok := sum["ai"]; ok {
			out["ai"] = v
		}
		if v, ok := sum["review_contexts"]; ok {
			out["review_contexts"] = v
		}
		if v, ok := sum["learned_rule_candidates"]; ok {
			out["learned_rule_candidates"] = v
		}
		if v, ok := sum["publish_refused"]; ok {
			out["publish_refused"] = v
		}
	case kindCheckup:
		if v, ok := sum["checkup"]; ok {
			out["checkup"] = v
		}
		if v, ok := sum["checkup_drops"]; ok {
			out["checkup_drops"] = v
		}
	case kindApproval:
		for _, k := range []string{
			"review_event", "risk_score", "risk_factors", "approval_reasons",
			"approval_honesty", "ledger", "pending_autofix", "approval_publish_error",
			"skip_reason",
		} {
			if v, ok := sum[k]; ok {
				out[k] = v
			}
		}
	case kindCloud:
		if v, ok := sum["cloud"]; ok {
			out["cloud"] = v
		}
		if v, ok := sum["cloud_rationale"]; ok {
			out["cloud_rationale"] = v
		}
		if v, ok := sum["skip_reason"]; ok {
			out["skip_reason"] = v
		}
		if v, ok := sum["publish_refused"]; ok {
			out["publish_refused"] = v
		}
	case kindRun:
		for _, k := range []string{"child_ids", "child_status", "prefs", "prefs_sources", "gate", "ai", "ledger", "auto_fixes"} {
			if v, ok := sum[k]; ok {
				out[k] = v
			}
		}
	default:
		// Copy a shallow subset of known keys for continuous/legacy.
		for _, k := range []string{"gate", "ai", "cloud", "checkup", "worktree"} {
			if v, ok := sum[k]; ok {
				out[k] = v
			}
		}
	}
	return out
}

func buildEvidenceChat(job *scmJob, refs *[]JobEvidenceArtifact) JobEvidenceChat {
	chat := JobEvidenceChat{}
	if job == nil || job.Summary == nil {
		return chat
	}
	sum := job.Summary
	if aiRaw, ok := sum["ai"]; ok && aiRaw != nil {
		b, _ := json.Marshal(aiRaw)
		var ai aiReviewResult
		if json.Unmarshal(b, &ai) == nil {
			chat.Model = ai.Model
			chat.Usage = evidencePreview(ai.Usage)
			if ai.Usage != "" {
				if ref, err := writeJobArtifact(job.ID, "transcript.txt", "transcript", ai.Usage); err == nil {
					chat.TranscriptArtifact = ref.Name
					chat.Transcript = evidencePreview(ai.Usage)
					*refs = append(*refs, ref)
				} else {
					chat.Transcript = evidencePreview(ai.Usage)
				}
			}
			for _, p := range ai.Parts {
				chat.Parts = append(chat.Parts, JobEvidenceChatPart{
					UnitID: p.UnitID, Kind: p.Kind, Summary: evidencePreview(p.Summary), Error: p.Error,
				})
			}
		}
	}
	if cloudRaw, ok := sum["cloud"]; ok && cloudRaw != nil {
		if m, ok := cloudRaw.(map[string]interface{}); ok {
			if u := strFromAny(m["cursor_usage"]); u != "" && chat.Usage == "" {
				chat.Usage = evidencePreview(u)
				chat.Transcript = evidencePreview(u)
			}
			if m := strFromAny(m["model"]); m != "" && chat.Model == "" {
				chat.Model = m
			}
		}
	}
	if brief := strFromAny(sum["brief_preview"]); brief != "" {
		chat.PromptPreview = evidencePreview(brief)
	}
	if art := strFromAny(sum["brief_artifact"]); art != "" {
		chat.PromptPreview = nz(chat.PromptPreview, "(see brief artifact)")
	}
	return chat
}

func buildEvidenceContext(job *scmJob, refs *[]JobEvidenceArtifact) JobEvidenceContext {
	ctx := JobEvidenceContext{}
	if job == nil || job.Summary == nil {
		return ctx
	}
	sum := job.Summary
	ctx.Prefs = sum["prefs"]
	ctx.PrefsSources = sum["prefs_sources"]
	ctx.ReviewContexts = sum["review_contexts"]
	ctx.CheckoutPath = strFromAny(sum["checkout_path"])
	ctx.CheckoutRel = strFromAny(sum["checkout_rel"])
	ctx.Worktree = sum["worktree"]
	ctx.RelatedRepos = sum["related_repos"]
	ctx.RelatedCheckouts = sum["related_checkouts"]
	if art := strFromAny(sum["brief_artifact"]); art != "" {
		ctx.BriefArtifact = art
	}
	if prev := strFromAny(sum["brief_preview"]); prev != "" {
		ctx.BriefPreview = evidencePreview(prev)
	}
	// Promote checkup stdout files into artifacts when present on disk.
	if checkout := ctx.CheckoutPath; checkout != "" {
		checkupDir := filepath.Join(checkout, ".opa-checkup")
		entries, err := os.ReadDir(checkupDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".stdout") {
					continue
				}
				src := filepath.Join(checkupDir, e.Name())
				if ref, err := copyFileToJobArtifact(job.ID, "checkup-"+e.Name(), "checkup_stdout", src); err == nil {
					*refs = append(*refs, ref)
				}
			}
		}
	}
	return ctx
}

// recordJobBrief copies an agent brief into durable job artifacts and summary pointers.
func recordJobBrief(job *scmJob, briefBody, filename string) {
	if job == nil || strings.TrimSpace(briefBody) == "" {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	name := filename
	if name == "" {
		name = "brief.md"
	}
	name = filepath.Base(name)
	job.Summary["brief_preview"] = evidencePreview(briefBody)
	if ref, err := writeJobArtifact(job.ID, name, "brief", briefBody); err == nil {
		job.Summary["brief_artifact"] = ref.Name
	}
}

// finalizeJobEvidence builds the typed evidence object from the job summary + posts.
func finalizeJobEvidence(job *scmJob) *JobEvidence {
	if job == nil {
		return nil
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	refs := []JobEvidenceArtifact{}
	ev := &JobEvidence{
		SchemaVersion: jobEvidenceSchemaVersion,
		Identity: JobEvidenceIdentity{
			ID: job.ID, Kind: job.Kind, Attempt: job.Attempt,
			RunID: job.RunID, ParentID: job.ParentID,
			OrganizationID: job.OrganizationID, ProjectID: job.ProjectID,
			RepoFullName: job.RepoFullName, PRNumber: job.PRNumber, CommitSHA: job.CommitSHA,
		},
		Status: JobEvidenceStatus{
			Status: job.Status, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
			Error: job.Error, SkipReason: strFromAny(job.Summary["skip_reason"]),
			Degraded: degradedFromSummary(job.Summary),
			Honesty:  strFromAny(job.Summary["approval_honesty"]),
		},
		Context: buildEvidenceContext(job, &refs),
		Chat:    buildEvidenceChat(job, &refs),
		Results: buildKindResults(job),
		Findings: scmJobFindings(job),
	}
	if h := strFromAny(job.Summary["inline_honesty"]); h != "" && ev.Status.Honesty == "" {
		ev.Status.Honesty = h
	}
	if cloud, ok := job.Summary["cloud"].(map[string]interface{}); ok {
		if h := strFromAny(cloud["honesty"]); h != "" {
			ev.Status.Honesty = h
		}
	}
	// Posts: prefer accumulating evidence_posts, else prior evidence.posts.
	var posts []JobEvidencePost
	if raw, ok := job.Summary["evidence_posts"]; ok && raw != nil {
		b, _ := json.Marshal(raw)
		_ = json.Unmarshal(b, &posts)
	}
	if len(posts) == 0 {
		posts = loadEvidencePosts(job)
	}
	ev.Posts = posts
	if fixes, ok := job.Summary["auto_fixes"]; ok {
		ev.AutoFixes = fixes
	}
	ev.ArtifactRefs = refs
	ev.Sections = JobEvidenceSections{
		HasContext: ev.Context.CheckoutPath != "" || ev.Context.Prefs != nil || ev.Context.BriefPreview != "" || ev.Context.ReviewContexts != nil,
		HasChat:    ev.Chat.Model != "" || ev.Chat.Transcript != "" || ev.Chat.PromptPreview != "" || len(ev.Chat.Parts) > 0,
		HasResults: len(ev.Results) > 1, // kind + at least one field
		HasPosts:   len(ev.Posts) > 0,
		HasFindings: len(ev.Findings) > 0,
		HasAutoFixes: ev.AutoFixes != nil,
		FindingCount: len(ev.Findings),
		PostCount:    len(ev.Posts),
	}
	job.Summary["evidence"] = ev
	return ev
}

func evidenceFromJob(job *scmJob) *JobEvidence {
	if job == nil {
		return nil
	}
	if job.Summary != nil {
		if raw, ok := job.Summary["evidence"]; ok && raw != nil {
			b, err := json.Marshal(raw)
			if err == nil {
				var ev JobEvidence
				if json.Unmarshal(b, &ev) == nil && ev.SchemaVersion > 0 {
					return &ev
				}
			}
		}
	}
	return finalizeJobEvidence(job)
}

// projectEvidence applies view=ops|org|client redaction for multi-audience display.
func projectEvidence(ev *JobEvidence, view string) *JobEvidence {
	if ev == nil {
		return nil
	}
	view = strings.ToLower(strings.TrimSpace(view))
	if view == "" || view == "ops" {
		return ev
	}
	// Deep-ish copy via JSON.
	b, err := json.Marshal(ev)
	if err != nil {
		return ev
	}
	var out JobEvidence
	if json.Unmarshal(b, &out) != nil {
		return ev
	}
	switch view {
	case "client":
		out.Chat.Transcript = evidencePreview(out.Chat.Transcript)
		if len(out.Chat.Transcript) > 2048 {
			out.Chat.Transcript = truncateStr(out.Chat.Transcript, 2048)
		}
		out.Chat.PromptPreview = truncateStr(out.Chat.PromptPreview, 1024)
		out.Chat.Usage = truncateStr(out.Chat.Usage, 512)
		out.Context.BriefPreview = truncateStr(out.Context.BriefPreview, 1024)
		out.Context.CheckoutPath = ""
		out.Context.RelatedCheckouts = nil
		for i := range out.Posts {
			out.Posts[i].Body = out.Posts[i].BodyPreview
			if out.Posts[i].Body == "" {
				out.Posts[i].Body = truncateStr(out.Posts[i].Body, 1500)
			}
		}
	case "org":
		out.Context.CheckoutPath = ""
		// keep findings/posts/results; trim raw transcript slightly
		out.Chat.Transcript = evidencePreview(out.Chat.Transcript)
	}
	return &out
}

func evidenceCompactSummary(job *scmJob) map[string]interface{} {
	ev := evidenceFromJob(job)
	if ev == nil {
		return map[string]interface{}{
			"id": job.ID, "kind": job.Kind, "status": job.Status, "attempt": job.Attempt,
		}
	}
	return map[string]interface{}{
		"id": ev.Identity.ID, "kind": ev.Identity.Kind, "status": ev.Status.Status,
		"attempt": ev.Identity.Attempt, "started_at": ev.Status.StartedAt, "finished_at": ev.Status.FinishedAt,
		"skip_reason": ev.Status.SkipReason, "sections": ev.Sections,
		"finding_count": ev.Sections.FindingCount, "post_count": ev.Sections.PostCount,
	}
}

func readJobArtifact(jobID, name string) ([]byte, error) {
	name = filepath.Base(strings.TrimSpace(name))
	if jobID == "" || name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid artifact")
	}
	path := filepath.Join(jobArtifactsDir(jobID), name)
	// Contain within artifacts dir.
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(jobArtifactsDir(jobID))+string(os.PathSeparator)) &&
		filepath.Clean(path) != filepath.Clean(jobArtifactsDir(jobID)) {
		return nil, fmt.Errorf("invalid artifact path")
	}
	return os.ReadFile(path)
}
