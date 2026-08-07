package main

// Thin wrappers over open-job-env-go so call sites keep local names.
// Agents — child-process environments constructed from an EMPTY slice.
// THIS FILE MUST NEVER CALL os.Environ() for untrusted tool children.

import (
	"sort"

	openjobenv "github.com/TheGrimmChester/open-job-env-go"
)

type jobPhase = openjobenv.Phase

const (
	jobPhaseReview  jobPhase = openjobenv.PhaseReview
	jobPhaseContext jobPhase = openjobenv.PhaseContext
	jobPhaseScan    jobPhase = openjobenv.PhaseScan
	jobPhaseAutofix jobPhase = openjobenv.PhaseAutofix
	jobPhaseAITask  jobPhase = openjobenv.PhaseAITask
	jobPhaseCheckup jobPhase = openjobenv.PhaseCheckup
)

type jobEnvSpec struct {
	Phase        jobPhase
	WorktreeRoot string
	Secrets      map[string]string
	Extra        map[string]string
}

func jobEnv(spec jobEnvSpec) []string {
	return openjobenv.JobEnv(openjobenv.Spec{
		Phase:        openjobenv.Phase(spec.Phase),
		WorktreeRoot: spec.WorktreeRoot,
		Secrets:      spec.Secrets,
		Extra:        spec.Extra,
	})
}

func hostToolEnv(extra ...string) []string {
	return openjobenv.HostToolEnv(extra...)
}

func envNameLooksSecret(name string) bool {
	return openjobenv.EnvNameLooksSecret(name)
}

// envSliceSorted turns a map into sorted KEY=VAL lines for sandbox env files.
func envSliceSorted(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}
