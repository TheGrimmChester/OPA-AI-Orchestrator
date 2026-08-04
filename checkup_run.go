package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// checkupStepResult is one executed step's outcome.
type checkupStepResult struct {
	ID            string `json:"id"`
	OK            bool   `json:"ok"`
	ExitOK        bool   `json:"exit_ok"`
	PostOK        bool   `json:"post_ok"`
	Error         string `json:"error,omitempty"`
	StdoutBytes   int    `json:"stdout_bytes"`
	DurationMS    int64  `json:"duration_ms"`
	PostKind      string `json:"post_kind,omitempty"`
	JUnitTests    int    `json:"junit_tests,omitempty"`
	DroppedReason string `json:"dropped_reason,omitempty"`
	// LogExcerpt is the step's captured output around the failure, so a reviewer
	// can see why a check failed without opening the job dashboard.
	LogExcerpt string `json:"log_excerpt,omitempty"`
}

// checkupLogExcerpt keeps the head and tail of captured output. Compile errors
// appear first, assertion failures last, so both ends matter.
func checkupLogExcerpt(out []byte, max int) string {
	s := strings.TrimSpace(string(out))
	if s == "" || len(s) <= max {
		return s
	}
	half := max / 2
	return s[:half] + "\n…\n" + s[len(s)-half:]
}

// checkupRunResult is the full checkup outcome recorded on the job summary.
// status=blocked means the workspace could not be prepared, so no step ran; it
// reports neutral, never failure — an unprepared runner is not a bad commit.
type checkupRunResult struct {
	Status      string                  `json:"status"` // passed|failed|skipped|refused|blocked
	Honesty     string                  `json:"honesty,omitempty"`
	PlanSource  string                  `json:"plan_source,omitempty"`
	Image       string                  `json:"image,omitempty"`
	Drops       []string                `json:"drops,omitempty"`
	Steps       []checkupStepResult     `json:"steps,omitempty"`
	Annotations int                     `json:"annotations,omitempty"`
	PlanDiff    string                  `json:"plan_diff,omitempty"`
	Workspace   *checkupWorkspaceReport `json:"workspace,omitempty"`
}

// FailingStep returns the first step that did not pass.
func (r checkupRunResult) FailingStep() (checkupStepResult, bool) {
	for _, s := range r.Steps {
		if !s.OK {
			return s, true
		}
	}
	return checkupStepResult{}, false
}

// evaluatePostCondition checks artifacts after a step. Exit 0 alone is
// insufficient when JUnit (or another artifact) was declared.
func evaluatePostCondition(pc checkupPostCondition, exitErr error, stdout []byte, workRoot string) (ok bool, detail string, junitN int) {
	exitOK := exitErr == nil
	switch pc.Kind {
	case "exit0":
		if !exitOK {
			return false, "nonzero exit", 0
		}
		return true, "", 0
	case "junit":
		if !exitOK {
			return false, "nonzero exit before junit check", 0
		}
		path := filepath.Join(workRoot, pc.Path)
		raw, err := os.ReadFile(path)
		if err != nil {
			return false, "junit artifact missing: " + pc.Path, 0
		}
		n := countJUnitTests(raw)
		min := pc.MinTests
		if min <= 0 {
			min = 1 // exit 0 with zero tests is a false green
		}
		if n < min {
			return false, fmt.Sprintf("junit testcase count %d < min %d", n, min), n
		}
		return true, "", n
	case "checkstyle":
		// Presence of parseable checkstyle is enough; failures become annotations.
		if !exitOK {
			return false, "nonzero exit", 0
		}
		return true, "", 0
	case "stdout_contains":
		if !exitOK {
			return false, "nonzero exit", 0
		}
		if !strings.Contains(string(stdout), pc.Contains) {
			return false, "stdout missing expected fragment", 0
		}
		return true, "", 0
	case "artifact_exists":
		if !exitOK {
			return false, "nonzero exit", 0
		}
		path := filepath.Join(workRoot, pc.Path)
		if !fileExists(path) {
			return false, "artifact missing: " + pc.Path, 0
		}
		return true, "", 0
	default:
		return false, "unknown post_condition " + pc.Kind, 0
	}
}

// runCheckupPlan executes an already-intersected plan inside the docker sandbox.
func runCheckupPlan(ctx context.Context, jobID, workRoot string, plan *checkupPlan) (checkupRunResult, []checkupAnnotation) {
	out := checkupRunResult{Status: "passed", PlanSource: "", Steps: nil}
	var anns []checkupAnnotation
	if plan == nil {
		out.Status = "skipped"
		out.Honesty = "empty plan"
		return out, nil
	}
	out.PlanSource = plan.Source
	out.Image = plan.Image
	if len(plan.Steps) == 0 {
		out.Status = "skipped"
		out.Honesty = "no checkup steps after policy intersection"
		return out, nil
	}
	if sandboxMode() != "docker" {
		out.Status = "refused"
		out.Honesty = "OPA_JOB_SANDBOX=docker required for capRunRepoCode checkup"
		return out, nil
	}
	if strings.TrimSpace(plan.Image) == "" {
		out.Status = "refused"
		out.Honesty = "no allowlisted image"
		return out, nil
	}
	if err := requireDockerCLI(); err != nil {
		out.Status = "refused"
		out.Honesty = err.Error()
		return out, nil
	}

	workRoot = filepath.Clean(workRoot)
	if workRoot == "" || !filepath.IsAbs(workRoot) {
		out.Status = "failed"
		out.Honesty = "work root must be absolute"
		return out, nil
	}

	svcRT, err := startCheckupServices(ctx, jobID, plan.Services)
	if err != nil {
		out.Status = "failed"
		out.Honesty = "services: " + err.Error()
		return out, nil
	}
	defer func() { _ = stopCheckupServices(context.Background(), svcRT) }()

	netName := ""
	if svcRT != nil {
		netName = svcRT.Network
	}
	if netName == "" && len(plan.Services) == 0 {
		// Install/test steps need package registries (npm, proxy.golang.org). Use
		// the shared allowlist egress proxy on an --internal net (same as AI).
		// Without proxy, fall back to a sealed internal network (offline only).
		if egressProxyEnabled() {
			netName = networkModeInternalProxy
		} else {
			netName, err = createJobInternalNetwork(ctx, jobID)
			if err != nil {
				out.Status = "failed"
				out.Honesty = "network: " + err.Error()
				return out, nil
			}
			defer func() { _ = removeJobInternalNetwork(context.Background(), jobID) }()
		}
	}

	// Clear state from an earlier attempt on this layout before anything runs.
	purgeCheckupState(workRoot)

	// Resolve go.mod filesystem replacements into the job layout. Without this a
	// family service cannot compile in its own isolated checkout.
	wsRep := prepareCheckupWorkspace(workRoot)
	if wsRep.SourceRoot != "" || len(wsRep.Required) > 0 {
		out.Workspace = &wsRep
	}
	if wsRep.Blocked() {
		out.Status = "blocked"
		out.Honesty = wsRep.Honesty()
		return out, nil
	}
	siblings := checkupModuleSiblingDirs(workRoot, wsRep)
	if note := wsRep.Honesty(); note != "" {
		out.Honesty = note
	}

	secrets := resolveCheckupSecrets(plan.Secrets)
	allOK := true
	for _, step := range plan.Steps {
		sr := runCheckupStep(ctx, jobID, workRoot, netName, plan.Image, plan.Env, secrets, step, siblings)
		out.Steps = append(out.Steps, sr)
		stepAnns := checkupAnnotationsFromStepOutput(step, nil, workRoot)
		// Re-read stdout is not retained; for checkstyle-from-stdout we keep empty here
		// unless the step runner stashed it — see runCheckupStep stash below via workRoot/.opa-out
		if step.PostCondition.Kind == "checkstyle" && step.PostCondition.Path == "" {
			if b, err := os.ReadFile(checkupStepStdoutPath(workRoot, step.ID)); err == nil {
				stepAnns = checkupAnnotationsFromStepOutput(step, b, workRoot)
			}
		} else if step.PostCondition.Kind == "junit" || step.PostCondition.Kind == "checkstyle" {
			stepAnns = checkupAnnotationsFromStepOutput(step, nil, workRoot)
		}
		anns = append(anns, stepAnns...)
		if !sr.OK {
			allOK = false
		}
	}
	out.Annotations = len(anns)
	if !allOK {
		out.Status = "failed"
	}
	return out, anns
}

func checkupStepStdoutPath(workRoot, stepID string) string {
	safe := sanitizeDockerName(stepID)
	return filepath.Join(workRoot, ".opa-checkup", safe+".stdout")
}

func runCheckupStep(ctx context.Context, jobID, workRoot, network, image string, planEnv map[string]string, secrets map[string]string, step checkupStep, siblingDirs []string) checkupStepResult {
	res := checkupStepResult{ID: step.ID, PostKind: step.PostCondition.Kind}
	start := time.Now()
	timeout := time.Duration(nzInt(step.TimeoutSec, checkupDefaultStepTimeoutSec)) * time.Second
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	extra := map[string]string{}
	for k, v := range planEnv {
		extra[k] = v
	}
	for k, v := range step.Env {
		extra[k] = v
	}

	// Secrets only for install-like steps that declared them; never for test steps
	// that already ran repo code in a prior box — first-slice: pass secrets only
	// when step id suggests install OR argv binary is composer/npm/yarn.
	stepSecrets := map[string]string{}
	bin := checkupArgvBinary(step.Argv[0])
	if bin == "composer" || bin == "npm" || bin == "yarn" {
		for k, v := range secrets {
			stepSecrets[k] = v
		}
	}

	// Bind leaf tree; layout id is the worktree parent (run id), while JobID is
	// the checkup child so cancel/teardown cannot touch sibling boxes.
	workRel := sandboxWorkRel(workRoot)
	layoutID := resolveSandboxJobID("", workRoot)

	out, err := runSandboxedArgv(stepCtx, sandboxExecSpec{
		Phase:       jobPhaseCheckup,
		JobID:       jobID,
		LayoutID:    layoutID,
		NetworkID:   jobID,
		HostWorkDir: workRoot,
		WorkRel:     workRel,
		Argv:        step.Argv,
		Secrets:     stepSecrets,
		ExtraEnv:    extra,
		ReadOnly:    false,
		Network:     nz(network, "none"),
		Timeout:     0,
		Image:       image,
		Ephemeral:   false,
		SiblingDirs: siblingDirs,
	})
	res.DurationMS = time.Since(start).Milliseconds()
	res.StdoutBytes = len(out)
	_ = os.MkdirAll(filepath.Dir(checkupStepStdoutPath(workRoot, step.ID)), 0o755)
	_ = os.WriteFile(checkupStepStdoutPath(workRoot, step.ID), out, 0o600)

	res.ExitOK = err == nil
	postOK, detail, jn := evaluatePostCondition(step.PostCondition, err, out, workRoot)
	res.PostOK = postOK
	res.JUnitTests = jn
	res.OK = postOK
	if !postOK {
		res.Error = detail
		if err != nil {
			res.Error = detail + ": " + err.Error()
		}
		res.LogExcerpt = checkupLogExcerpt(out, checkupLogExcerptMax)
	}
	return res
}

func resolveCheckupSecrets(names []string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		uk := strings.ToUpper(strings.TrimSpace(name))
		if !checkupGrantableSecrets[uk] {
			continue
		}
		if v := strings.TrimSpace(os.Getenv(uk)); v != "" {
			out[uk] = v
			continue
		}
		// Common aliases
		switch uk {
		case "NPM_AUTH", "NPM_TOKEN":
			if v := strings.TrimSpace(os.Getenv("NPM_TOKEN")); v != "" {
				out[uk] = v
			}
		case "COMPOSER_AUTH":
			if v := strings.TrimSpace(os.Getenv("COMPOSER_AUTH")); v != "" {
				out[uk] = v
			}
		}
	}
	return out
}

// runCheckupAgent is the kind=checkup child entrypoint.
func runCheckupAgent(job *scmJob) error {
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	prefs := agentPrefsFromSummary(getSCMJob(job.RunID))
	if !prefs.CheckupEnabled {
		job.Status = "skipped"
		job.Summary["skip_reason"] = "checkup_enabled=off"
		job.Summary["checkup"] = checkupRunResult{Status: "skipped", Honesty: "checkup_enabled=off"}
		persistSCMJob(job)
		return nil
	}
	if sandboxMode() != "docker" {
		job.Status = "skipped"
		job.Summary["skip_reason"] = "OPA_JOB_SANDBOX=docker required"
		job.Summary["checkup"] = checkupRunResult{
			Status: "refused", Honesty: "OPA_JOB_SANDBOX=docker required for capRunRepoCode",
		}
		persistSCMJob(job)
		return nil
	}

	wr, conn := findWatched(job.RepoFullName)
	_ = wr
	if conn == nil {
		conn = getOrHydrateConnector(job.ConnectorID)
	}
	owner, repoName := splitOwnerRepo(job.RepoFullName)
	absRoot := checkoutPathForRun(job)
	if absRoot == "" {
		job.Summary["checkup"] = checkupRunResult{Status: "failed", Honesty: "no checkout path"}
		return fmt.Errorf("checkup: no checkout path")
	}
	if !githubUseMockAPI(conn) {
		if err := ensureGitHubWriteAllowed(job, conn); err != nil {
			if job.Summary == nil {
				job.Summary = map[string]interface{}{}
			}
			job.Summary["publish_refused"] = err.Error()
			persistSCMJob(job)
			return err
		}
	}

	jobDashURL := scmJobDashboardURL(nz(job.RunID, job.ID))
	checkID, _ := githubCreateCheckRun(conn, owner, repoName, "OPA Checkup", job.CommitSHA, "in_progress", "",
		"Planning checkup…", checkRunSummaryWithJobLink("Deriving check plan from PR tree", nz(job.RunID, job.ID)), jobDashURL, nil)
	if job.CheckRunIDs == nil {
		job.CheckRunIDs = map[string]int64{}
	}
	job.CheckRunIDs["checkup"] = checkID
	persistSCMJob(job)

	rawPlan, err := deriveCheckupPlan(absRoot)
	if err != nil {
		rawPlan = &checkupPlan{Version: 1, Source: "error", Image: defaultCheckupImage()}
		job.Summary["checkup_plan_error"] = err.Error()
	}
	policed := intersectSpecWithPolicy(rawPlan)
	job.Summary["checkup_plan"] = policed.Plan
	job.Summary["checkup_drops"] = policed.Drops

	ctx := scmJobContext(job.ID)
	// Use the checkup child id — never the shared RunID — so stop/teardown
	// cannot docker-rm sibling review/scan boxes labeled with the run.
	result, anns := runCheckupPlan(ctx, job.ID, absRoot, policed.Plan)
	result.Drops = policed.Drops
	if note := phpstanNewErrorsHonesty(absRoot, policed.Plan); note != "" {
		if result.Honesty != "" {
			result.Honesty = result.Honesty + "\n" + note
		} else {
			result.Honesty = note
		}
	}
	job.Summary["checkup"] = result

	conclusion := "success"
	title := "OPA Checkup passed"
	switch result.Status {
	case "failed":
		conclusion = "failure"
		title = "OPA Checkup failed"
		// Name the step that failed so the check title is actionable.
		if s, ok := result.FailingStep(); ok {
			title = "OPA Checkup failed: " + s.ID
		}
	case "blocked":
		// The workspace could not be prepared, so nothing was verified. Neutral
		// keeps the pull request honest instead of blaming the commit.
		conclusion = "neutral"
		title = "OPA Checkup could not run"
	case "skipped", "refused":
		conclusion = "neutral"
		title = "OPA Checkup " + result.Status
	}
	summary := formatCheckupCheckSummary(result, policed.Drops)
	annMaps := checkupAnnotationsToMaps(anns)
	if checkID != 0 {
		_ = publishCheckupAnnotations(conn, owner, repoName, checkID, conclusion, title,
			checkRunSummaryWithJobLink(summary, nz(job.RunID, job.ID)), jobDashURL, annMaps)
	}
	persistSCMJob(job)
	if result.Status == "failed" {
		if s, ok := result.FailingStep(); ok {
			return fmt.Errorf("checkup failed: step %s: %s", s.ID, nz(s.Error, "post-condition not met"))
		}
		return fmt.Errorf("checkup failed: %s", nz(result.Honesty, "step post-condition"))
	}
	return nil
}

func formatCheckupCheckSummary(r checkupRunResult, drops []string) string {
	var b strings.Builder
	b.WriteString("status=" + r.Status)
	if r.Honesty != "" {
		b.WriteString("\n" + r.Honesty)
	}
	if r.PlanSource != "" {
		b.WriteString("\nplan_source=" + r.PlanSource)
	}
	if r.Image != "" {
		b.WriteString("\nimage=" + r.Image)
	}
	for _, d := range drops {
		b.WriteString("\ndrop: " + d)
	}
	if r.Status == "blocked" {
		b.WriteString("\n\nNo step ran, so this commit was not verified — this is a runner setup issue, not a test failure.")
		return truncateStr(b.String(), 60000)
	}
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "\nstep %s: ok=%v exit=%v post=%v %dms", s.ID, s.OK, s.ExitOK, s.PostOK, s.DurationMS)
		if s.Error != "" {
			b.WriteString("\n  reason: " + truncateStr(s.Error, 300))
		}
	}
	// Full excerpt for the first failing step: the reason alone rarely says which
	// assertion or package broke.
	if s, ok := r.FailingStep(); ok && s.LogExcerpt != "" {
		fmt.Fprintf(&b, "\n\nOutput from failing step %s:\n\n```\n%s\n```\n", s.ID, s.LogExcerpt)
	}
	return truncateStr(b.String(), 60000)
}

// publishCheckupAnnotations updates the check run, batching annotations in
// groups of 50 (GitHub truncates each request at 50).
func publishCheckupAnnotations(conn *opaConnector, owner, repo string, checkID int64, conclusion, title, summary, detailsURL string, anns []map[string]interface{}) error {
	if len(anns) == 0 {
		return githubUpdateCheckRun(conn, owner, repo, checkID, "completed", conclusion, title, summary, detailsURL, nil)
	}
	// Convert back to checkupAnnotation batches via chunking maps.
	var firstErr error
	for i := 0; i < len(anns); i += githubCheckAnnotationLimit {
		end := i + githubCheckAnnotationLimit
		if end > len(anns) {
			end = len(anns)
		}
		chunk := anns[i:end]
		status := "in_progress"
		conc := ""
		if end >= len(anns) {
			status = "completed"
			conc = conclusion
		}
		err := githubUpdateCheckRun(conn, owner, repo, checkID, status, conc, title, summary, detailsURL, chunk)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
