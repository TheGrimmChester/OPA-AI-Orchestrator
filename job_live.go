package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	livePersistInterval = 1500 * time.Millisecond
	livePersistBytes    = 4096
	liveTailBytes       = 6144
)

// liveOutputSink tees agent stdout/stderr into artifacts/live.log and a
// throttled job.Summary["live"] snapshot for dashboard soft-polling.
type liveOutputSink struct {
	jobID    string
	phase    string
	unit     string
	artifact string
	secrets  []string

	mu           sync.Mutex
	file         *os.File
	unitFile     *os.File
	total        int
	sincePersist int
	lastPersist  time.Time
	closed       bool
}

type liveSummarySnap struct {
	jobID string
	live  map[string]interface{}
}

func phaseWantsLiveCapture(phase jobPhase) bool {
	switch phase {
	case jobPhaseReview, jobPhaseContext, jobPhaseAutofix, jobPhaseAITask:
		return true
	default:
		return false
	}
}

func liveSinkForSpec(spec sandboxExecSpec) *liveOutputSink {
	if !phaseWantsLiveCapture(spec.Phase) {
		return nil
	}
	jobID := strings.TrimSpace(spec.JobID)
	if jobID == "" || jobID == "anon" {
		return nil
	}
	phase := strings.TrimSpace(spec.LivePhase)
	if phase == "" {
		phase = string(spec.Phase)
	}
	return newLiveOutputSink(jobID, phase, spec.LiveUnit, secretValues(spec.Secrets)...)
}

func sanitizeLiveUnit(unit string) string {
	unit = strings.TrimSpace(unit)
	if unit == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range unit {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}

func newLiveOutputSink(jobID, phase, unit string, secrets ...string) *liveOutputSink {
	jobID = strings.TrimSpace(jobID)
	phase = strings.TrimSpace(phase)
	unit = sanitizeLiveUnit(unit)
	artifact := "live.log"
	if unit != "" {
		artifact = "live-" + unit + ".log"
	}
	s := &liveOutputSink{
		jobID:       jobID,
		phase:       phase,
		unit:        unit,
		artifact:    artifact,
		secrets:     secrets,
		lastPersist: time.Now(), // avoid persist-on-every-Write while zero
	}
	dir, err := ensureJobArtifactsDir(jobID)
	if err != nil {
		return s
	}
	f, err := os.OpenFile(filepath.Join(dir, "live.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		s.file = f
	}
	if unit != "" {
		uf, uerr := os.OpenFile(filepath.Join(dir, artifact), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if uerr == nil {
			s.unitFile = uf
		}
	}
	header := "=== live phase=" + phase
	if unit != "" {
		header += " unit=" + unit
	}
	header += " started=" + time.Now().UTC().Format(time.RFC3339) + " ===\n"
	_, _ = s.Write([]byte(header))
	return s
}

func (s *liveOutputSink) Write(p []byte) (int, error) {
	if s == nil || len(p) == 0 {
		return len(p), nil
	}
	redacted := redactJobOutput(append([]byte(nil), p...), s.secrets...)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return len(p), nil
	}
	n := len(redacted)
	if s.file != nil {
		_, _ = s.file.Write(redacted)
	}
	if s.unitFile != nil {
		_, _ = s.unitFile.Write(redacted)
	}
	s.total += n
	s.sincePersist += n
	var snap *liveSummarySnap
	if s.sincePersist >= livePersistBytes || time.Since(s.lastPersist) >= livePersistInterval {
		snap = s.takeSnapLocked()
	}
	s.mu.Unlock()
	applyLiveSummarySnap(snap)
	return len(p), nil
}

func (s *liveOutputSink) Flush(force bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed && !force {
		s.mu.Unlock()
		return
	}
	snap := s.takeSnapLocked()
	s.mu.Unlock()
	applyLiveSummarySnap(snap)
}

func (s *liveOutputSink) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	snap := s.takeSnapLocked()
	s.closed = true
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
	if s.unitFile != nil {
		_ = s.unitFile.Close()
		s.unitFile = nil
	}
	s.mu.Unlock()
	applyLiveSummarySnap(snap)
}

// takeSnapLocked builds a summary snapshot and resets throttle counters.
// Caller must hold s.mu. Does not call persistSCMJob (avoids holding the
// stdout tee lock across disk/CH I/O and blocking the agent pipe).
func (s *liveOutputSink) takeSnapLocked() *liveSummarySnap {
	if s.jobID == "" {
		return nil
	}
	if s.file != nil {
		_ = s.file.Sync()
	}
	if s.unitFile != nil {
		_ = s.unitFile.Sync()
	}
	tail := s.readTailLocked()
	live := map[string]interface{}{
		"artifact":   "live.log",
		"bytes":      s.total,
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"tail":       string(tail),
		"phase":      s.phase,
	}
	if s.unit != "" {
		live["unit"] = s.unit
		live["unit_artifact"] = s.artifact
	}
	s.sincePersist = 0
	s.lastPersist = time.Now()
	return &liveSummarySnap{jobID: s.jobID, live: live}
}

func applyLiveSummarySnap(snap *liveSummarySnap) {
	if snap == nil || snap.jobID == "" {
		return
	}
	job := getSCMJob(snap.jobID)
	if job == nil {
		return
	}
	if job.Summary == nil {
		job.Summary = map[string]interface{}{}
	}
	job.Summary["live"] = snap.live
	persistSCMJob(job)
}

func (s *liveOutputSink) readTailLocked() []byte {
	path := filepath.Join(jobArtifactsDir(s.jobID), "live.log")
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil
	}
	if len(raw) <= liveTailBytes {
		return raw
	}
	return raw[len(raw)-liveTailBytes:]
}
