package web

import (
	"context"
	"sync"
	"time"
)

// JobKind names a long-running pipeline step. One in-flight job per
// (caseID, kind) is allowed; trying to start a duplicate returns the
// existing job's status without starting a new goroutine.
type JobKind string

const (
	JobParse      JobKind = "parse"
	JobAnalyze    JobKind = "analyze"
	JobSynthesize JobKind = "synthesize"
	JobReport     JobKind = "report"
	JobAutopilot  JobKind = "autopilot" // Wave 33: end-to-end chain via `tlvb run`
)

// JobStatus is what /api/cases/:id/<kind>/status returns.
type JobStatus struct {
	CaseID     string    `json:"case_id"`
	Kind       JobKind   `json:"kind"`
	State      string    `json:"state"` // idle | running | succeeded | failed
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Message    string    `json:"message,omitempty"`
	Error      string    `json:"error,omitempty"`
	Progress   string    `json:"progress,omitempty"` // free-form text from the job (e.g. "tier1.persistence ok")
	// Subkind disambiguates analyze runs (e.g. "all" or a single tactic name).
	Subkind string `json:"subkind,omitempty"`

	// Structured progress (added so the UI can render a real bar + ETA
	// instead of just a status string).
	Current        int `json:"current,omitempty"`         // items completed so far
	Total          int `json:"total,omitempty"`           // total items expected
	ETASeconds     int `json:"eta_seconds,omitempty"`     // estimated remaining wall time
	ElapsedSeconds int `json:"elapsed_seconds,omitempty"` // computed at read-time from StartedAt
}

// JobsManager is an in-memory tracker. Keyed by (caseID, kind). A second
// start for the same key while running returns the running status; once
// finished, a new start replaces the entry.
type JobsManager struct {
	mu   sync.Mutex
	jobs map[string]*jobEntry // key = caseID + "|" + kind
}

type jobEntry struct {
	status JobStatus
	cancel context.CancelFunc
}

func newJobsManager() *JobsManager {
	return &JobsManager{jobs: map[string]*jobEntry{}}
}

func key(caseID string, kind JobKind) string {
	return caseID + "|" + string(kind)
}

// Status returns the latest status (or an "idle" zero-value if no job has
// ever run). ElapsedSeconds is derived live from StartedAt so callers always
// see fresh wall-clock time without the job having to push updates.
func (m *JobsManager) Status(caseID string, kind JobKind) JobStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.jobs[key(caseID, kind)]; ok {
		s := e.status
		if !s.StartedAt.IsZero() {
			endAt := s.FinishedAt
			if s.State == "running" {
				endAt = time.Now().UTC()
			}
			if !endAt.IsZero() {
				s.ElapsedSeconds = int(endAt.Sub(s.StartedAt).Seconds())
			}
		}
		return s
	}
	return JobStatus{CaseID: caseID, Kind: kind, State: "idle"}
}

// IsRunning is a fast-path check.
func (m *JobsManager) IsRunning(caseID string, kind JobKind) bool {
	return m.Status(caseID, kind).State == "running"
}

// updateProgress mutates the job entry's Progress text in-place so
// long-running tasks can report partial progress visible to status pollers.
func (m *JobsManager) updateProgress(caseID string, kind JobKind, progress string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.jobs[key(caseID, kind)]; ok {
		e.status.Progress = progress
	}
}

// updateStatusFn applies fn to the live JobStatus under lock. Used by jobs
// that need to update Current/Total/ETA atomically along with Progress.
func (m *JobsManager) updateStatusFn(caseID string, kind JobKind, fn func(*JobStatus)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.jobs[key(caseID, kind)]; ok {
		fn(&e.status)
	}
}

// Reporter is what a job receives to push progress updates. It bundles the
// existing free-form text callback with structured counter / ETA helpers
// so a job can call .Counter(2, 11) and .ETA(180) without locking itself.
type Reporter struct {
	Text    func(string)
	updater func(func(*JobStatus))
}

// SetCounter records "current / total" without touching the text. The UI
// can render a percentage from these.
func (r *Reporter) SetCounter(current, total int) {
	if r.updater == nil {
		return
	}
	r.updater(func(s *JobStatus) { s.Current = current; s.Total = total })
}

// SetETA records seconds remaining. 0 clears it.
func (r *Reporter) SetETA(secs int) {
	if r.updater == nil {
		return
	}
	r.updater(func(s *JobStatus) { s.ETASeconds = secs })
}

// SetAll updates text + counter + ETA in one lock acquisition.
func (r *Reporter) SetAll(text string, current, total, etaSecs int) {
	if r.updater == nil {
		return
	}
	r.updater(func(s *JobStatus) {
		s.Progress = text
		s.Current = current
		s.Total = total
		s.ETASeconds = etaSecs
	})
}

// Start launches fn in a goroutine and tracks its lifecycle. The returned
// status is the initial "running" snapshot. If a job for this key is
// already running, Start returns the running status without launching a
// duplicate (idempotent UI clicks are safe).
//
// fn receives the cancellation context and a progress callback. Returning
// (msg, nil) sets State=succeeded with Message=msg; returning (_, err)
// sets State=failed with Error=err.Error().
//
// Backward-compat: existing handlers pass `func(string)`. New handlers
// that want structured progress (counter / ETA) should use StartWithReporter.
func (m *JobsManager) Start(
	caseID string, kind JobKind, subkind string,
	fn func(ctx context.Context, progress func(string)) (string, error),
) JobStatus {
	return m.StartWithReporter(caseID, kind, subkind,
		func(ctx context.Context, r *Reporter) (string, error) {
			return fn(ctx, r.Text)
		})
}

// StartWithReporter is the structured-progress variant. The job receives
// a *Reporter that exposes both .Text and .SetCounter / .SetETA / .SetAll.
func (m *JobsManager) StartWithReporter(
	caseID string, kind JobKind, subkind string,
	fn func(ctx context.Context, r *Reporter) (string, error),
) JobStatus {
	m.mu.Lock()
	if e, ok := m.jobs[key(caseID, kind)]; ok && e.status.State == "running" {
		s := e.status
		m.mu.Unlock()
		return s
	}

	ctx, cancel := context.WithCancel(context.Background())
	entry := &jobEntry{
		status: JobStatus{
			CaseID:    caseID,
			Kind:      kind,
			Subkind:   subkind,
			State:     "running",
			StartedAt: time.Now().UTC(),
		},
		cancel: cancel,
	}
	m.jobs[key(caseID, kind)] = entry
	m.mu.Unlock()

	reporter := &Reporter{
		Text:    func(p string) { m.updateProgress(caseID, kind, p) },
		updater: func(updFn func(*JobStatus)) { m.updateStatusFn(caseID, kind, updFn) },
	}

	go func() {
		msg, err := fn(ctx, reporter)
		m.mu.Lock()
		defer m.mu.Unlock()
		entry.status.FinishedAt = time.Now().UTC()
		entry.status.ETASeconds = 0 // clear stale ETA on completion
		// Distinguish "examiner pressed Cancel" from a real failure
		// (Issue #8). When the parent ctx is canceled, fn typically
		// returns ctx.Err() ("context canceled") or wraps it; either
		// way, ctx.Err() != nil tells us the cancel button was the cause.
		if err != nil && ctx.Err() != nil {
			entry.status.State = "canceled"
			entry.status.Error = "" // not a failure, examiner-initiated
			entry.status.Message = "canceled by examiner"
		} else if err != nil {
			entry.status.State = "failed"
			entry.status.Error = err.Error()
		} else {
			entry.status.State = "succeeded"
			entry.status.Message = msg
			// On success bump counter to total so the UI bar shows 100%.
			if entry.status.Total > 0 {
				entry.status.Current = entry.status.Total
			}
		}
	}()
	return entry.status
}

// Cancel signals the job for (caseID, kind) to stop. Returns true if a
// running job was found and canceled, false if there was nothing
// running. The actual termination is asynchronous: the job's context
// goroutine will exit when fn observes ctx.Done() or its child
// subprocess gets killed by exec.CommandContext (Issue #8).
func (m *JobsManager) Cancel(caseID string, kind JobKind) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.jobs[key(caseID, kind)]
	if !ok || e.status.State != "running" || e.cancel == nil {
		return false
	}
	e.cancel()
	// Don't flip state here — let the job goroutine observe ctx.Done()
	// and update state under lock the normal way (above).
	return true
}
