package main

// Agent taxonomy + capability profiles for sandboxed job runners.
//
// Invariant (enforced by assertNoConfusedProfile at init): every stage that
// executes attacker-influenced code holds no GitHub write token; every stage
// that writes to GitHub executes no untrusted code.

import (
	"fmt"
	"time"
)

type agentKind string

const (
	kindContinuous agentKind = "continuous" // push/cron monolithic scan+review
	kindRun        agentKind = "run"
	kindPrepare    agentKind = "prepare"
	kindSecurity   agentKind = "security"
	kindBugbot     agentKind = "bugbot"
	kindApproval   agentKind = "approval"
	kindCloud      agentKind = "cloud"
	kindCheckup    agentKind = "checkup"

	// AI Issues / roadmap (separate graphs from PR runs).
	kindIssueRun         agentKind = "issue_run"
	kindIssuePrepare     agentKind = "issue_prepare"
	kindIssueInvestigate agentKind = "issue_investigate"
	kindIssuePublish     agentKind = "issue_publish"
	kindIssueImplement   agentKind = "issue_implement"
	kindRoadmapRun       agentKind = "roadmap_run"
	kindRoadmapGenerate  agentKind = "roadmap_generate"
	kindRoadmapPublish    agentKind = "roadmap_publish"
)

var agentDependsOn = map[agentKind][]agentKind{
	kindPrepare:  nil,
	kindSecurity: {kindPrepare},
	kindBugbot:   {kindPrepare},
	kindCheckup:  {kindPrepare},
	// Approval waits for cloud so pending_autofix cannot race a premature COMMENT.
	// Checkup remains a sibling and does not gate approval.
	kindApproval: {kindBugbot, kindSecurity, kindCloud},
	kindCloud:    {kindBugbot, kindSecurity},

	kindIssuePrepare:     nil,
	kindIssueInvestigate: {kindIssuePrepare},
	kindIssuePublish:     {kindIssueInvestigate},
	kindIssueImplement:   {kindIssuePublish},

	kindRoadmapGenerate: nil,
	kindRoadmapPublish:  {kindRoadmapGenerate},
}

type agentCaps uint16

const (
	capExecUntrusted agentCaps = 1 << iota // runs repo- or model-authored code
	capWritableTree
	capRunRepoCode // pinned SANDBOX_REQUIRED=1 always (later increments)
	capGitHubWrite
	capGitPush
	capClickHouseWrite
)

// agentStage is one executable profile in the capability matrix.
type agentStage struct {
	Name     string
	Kind     agentKind
	Phase    jobPhase
	Caps     agentCaps
	Timeout  time.Duration
	CheckRun string // GitHub check-run name (legacy names preserved)
}

// agentStageRegistry is the load-bearing design document for least-privilege.
// Adding a stage that sets both capExecUntrusted and a GitHub write cap fails
// init via assertNoConfusedProfile.
var agentStageRegistry = []agentStage{
	{Name: "prepare", Kind: kindPrepare, Phase: "", Caps: 0, Timeout: 300 * time.Second, CheckRun: ""},
	{Name: "bugbot.review", Kind: kindBugbot, Phase: jobPhaseReview, Caps: capExecUntrusted, Timeout: 900 * time.Second, CheckRun: "OPA Review"},
	{Name: "bugbot.publish", Kind: kindBugbot, Phase: "", Caps: capGitHubWrite | capClickHouseWrite, Timeout: 120 * time.Second, CheckRun: "OPA Review"},
	{Name: "security.scan", Kind: kindSecurity, Phase: jobPhaseScan, Caps: capExecUntrusted, Timeout: 600 * time.Second, CheckRun: "OPA AppSec Gate"},
	{Name: "security.publish", Kind: kindSecurity, Phase: "", Caps: capGitHubWrite | capClickHouseWrite, Timeout: 120 * time.Second, CheckRun: "OPA AppSec Gate"},
	{Name: "approval.decide", Kind: kindApproval, Phase: "", Caps: capGitHubWrite, Timeout: 60 * time.Second, CheckRun: "OPA Review"},
	{Name: "cloud.patch", Kind: kindCloud, Phase: jobPhaseAutofix, Caps: capExecUntrusted | capWritableTree, Timeout: 1200 * time.Second, CheckRun: "OPA Auto-fix"},
	{Name: "cloud.verify", Kind: kindCloud, Phase: jobPhaseAutofix, Caps: capExecUntrusted | capWritableTree | capRunRepoCode, Timeout: 1800 * time.Second, CheckRun: "OPA Auto-fix"},
	{Name: "cloud.land", Kind: kindCloud, Phase: "", Caps: capGitHubWrite | capGitPush, Timeout: 300 * time.Second, CheckRun: "OPA Auto-fix"},
	// checkup.run executes repo tests under docker sandbox; publish is in-process Go.
	{Name: "checkup.run", Kind: kindCheckup, Phase: jobPhaseCheckup, Caps: capExecUntrusted | capWritableTree | capRunRepoCode, Timeout: 1800 * time.Second, CheckRun: "OPA Checkup"},
	{Name: "checkup.publish", Kind: kindCheckup, Phase: "", Caps: capGitHubWrite, Timeout: 120 * time.Second, CheckRun: "OPA Checkup"},
	{Name: "issue.prepare", Kind: kindIssuePrepare, Phase: "", Caps: 0, Timeout: 300 * time.Second, CheckRun: ""},
	{Name: "issue.investigate", Kind: kindIssueInvestigate, Phase: jobPhaseAITask, Caps: capExecUntrusted, Timeout: 900 * time.Second, CheckRun: "OPA Issue"},
	{Name: "issue.publish", Kind: kindIssuePublish, Phase: "", Caps: capGitHubWrite, Timeout: 120 * time.Second, CheckRun: "OPA Issue"},
	{Name: "issue.implement", Kind: kindIssueImplement, Phase: jobPhaseAutofix, Caps: capExecUntrusted | capWritableTree, Timeout: 1800 * time.Second, CheckRun: "OPA Issue Implement"},
	{Name: "issue.implement.land", Kind: kindIssueImplement, Phase: "", Caps: capGitHubWrite | capGitPush, Timeout: 300 * time.Second, CheckRun: "OPA Issue Implement"},
	{Name: "roadmap.generate", Kind: kindRoadmapGenerate, Phase: jobPhaseAITask, Caps: capExecUntrusted, Timeout: 1200 * time.Second, CheckRun: "OPA Roadmap"},
	{Name: "roadmap.publish", Kind: kindRoadmapPublish, Phase: "", Caps: capGitHubWrite, Timeout: 300 * time.Second, CheckRun: "OPA Roadmap"},
}

func init() {
	assertNoConfusedProfile(agentStageRegistry)
}

// assertNoConfusedProfile panics if any stage both executes untrusted code and
// holds a GitHub write/push capability. That conjunction is the exploit class
// this taxonomy exists to make inexpressible.
func assertNoConfusedProfile(stages []agentStage) {
	for _, s := range stages {
		execs := s.Caps&capExecUntrusted != 0
		writes := s.Caps&(capGitHubWrite|capGitPush) != 0
		if execs && writes {
			panic(fmt.Sprintf("confused agent profile %q: capExecUntrusted combined with GitHub write/push", s.Name))
		}
	}
}

func agentStageByName(name string) (agentStage, bool) {
	for _, s := range agentStageRegistry {
		if s.Name == name {
			return s, true
		}
	}
	return agentStage{}, false
}

func defaultTimeoutForPhase(phase jobPhase) time.Duration {
	switch phase {
	case jobPhaseReview, jobPhaseContext:
		return 900 * time.Second
	case jobPhaseScan:
		return 600 * time.Second
	case jobPhaseAutofix:
		return 1200 * time.Second
	case jobPhaseCheckup:
		return 1800 * time.Second
	case jobPhaseAITask:
		return 300 * time.Second
	default:
		return 600 * time.Second
	}
}
