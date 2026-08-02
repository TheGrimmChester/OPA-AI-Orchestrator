package main

import "testing"

func TestAssertNoConfusedProfileAcceptsRegistry(t *testing.T) {
	// init() already ran assertNoConfusedProfile; re-run to keep the test explicit.
	assertNoConfusedProfile(agentStageRegistry)
}

func TestAssertNoConfusedProfileRejectsUnion(t *testing.T) {
	bad := []agentStage{{
		Name: "confused",
		Caps: capExecUntrusted | capGitHubWrite,
	}}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for confused profile")
		}
	}()
	assertNoConfusedProfile(bad)
}

func TestAgentDependsOnCoversAllNonRootKinds(t *testing.T) {
	for _, s := range agentStageRegistry {
		if s.Kind == kindLegacy || s.Kind == kindRun || s.Kind == "" {
			continue
		}
		if _, ok := agentDependsOn[s.Kind]; !ok {
			t.Fatalf("agentDependsOn missing kind %q (stage %s)", s.Kind, s.Name)
		}
	}
}

func TestExecStagesHoldNoGitHubWrite(t *testing.T) {
	for _, s := range agentStageRegistry {
		if s.Caps&capExecUntrusted == 0 {
			continue
		}
		if s.Caps&(capGitHubWrite|capGitPush) != 0 {
			t.Fatalf("stage %s executes untrusted code and writes to GitHub", s.Name)
		}
	}
}
