package main

import "strings"

// Action / task → agent key. This mapping is ORA's and lives here on purpose.
//
// OAM stores per-agent model bindings under a canonical agent key. OPM's
// agent_keys.go explicitly excludes deep review / auto-fix — those keys are
// owned here and published via publishAgentCatalog.
const (
	agentKeyReview           = "review"
	agentKeyAutoFix          = "auto_fix"
	agentKeyCloud            = "cloud"
	agentKeyContextGenerate  = "context_generate"
	agentKeyIssueInvestigate = "issue_investigate"
	agentKeyIssueImplement   = "issue_implement"
)

// agentKeyForTaskKind maps CompleteFor / ResolveProvider task kinds onto ORA
// catalog keys. Empty means "no AI credential for this kind under OAM".
func agentKeyForTaskKind(taskKind string) string {
	switch strings.ToLower(strings.TrimSpace(taskKind)) {
	case "opa_review", "cli":
		return agentKeyReview
	case "auto_fix":
		return agentKeyAutoFix
	case "context_generate":
		return agentKeyContextGenerate
	case "issue_investigate":
		return agentKeyIssueInvestigate
	case "issue_implement":
		return agentKeyIssueImplement
	default:
		return ""
	}
}

// agentCatalogEntry is one row ORA publishes to OAM so the console can render a
// model picker per agent without OAM hardcoding ORA's action list.
type agentCatalogEntry struct {
	AgentKey string `json:"agent_key"`
	Label    string `json:"label"`
	TierHint string `json:"tier_hint"`
}

// agentCatalog is what ORA declares about itself.
//
// tier_hint is only a hint for the console's default suggestion — it does not
// select a model. The family default is provider cli_cursor with model `auto`.
func agentCatalog() []agentCatalogEntry {
	return []agentCatalogEntry{
		{AgentKey: agentKeyReview, Label: "OPA Review", TierHint: "strong"},
		{AgentKey: agentKeyAutoFix, Label: "Auto-fix", TierHint: "strong"},
		{AgentKey: agentKeyCloud, Label: "Cloud autofix", TierHint: "strong"},
		{AgentKey: agentKeyContextGenerate, Label: "Context generate", TierHint: "light"},
		{AgentKey: agentKeyIssueInvestigate, Label: "Issue investigate", TierHint: "light"},
		{AgentKey: agentKeyIssueImplement, Label: "Issue implement", TierHint: "strong"},
	}
}
