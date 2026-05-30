package agents

import (
	"os"
	"strconv"
	"time"
)

// ComputeTimeout returns a wall-clock budget for one Tactic Agent or
// anomaly_hunter run. The formula scales linearly with ``maxEvents``
// (the upper bound of the SQL prefilter), clamped to a ``[floor,
// ceiling]`` band. anomaly_hunter gets a multiplier because it
// processes 6 anomaly lenses + a summary of prior tactic findings,
// roughly 1.5× the prompt of a regular Tactic Agent.
//
// Wave 20a — designed after observing on a real SRL-2018 / TANAKA case
// that anomaly_hunter with 100 events completed in ~163 s using
// claude-haiku-4-5 (i.e. ~1.6 s/event). We default to 5 s/event for
// generous safety margin (3× the observed rate) and clamp the result
// into a sensible band. Tunable via env vars so an operator on a
// slower model (Opus) or a busier API endpoint can extend without a
// rebuild.
//
// Env vars:
//
//	TLVB_LLM_TIMEOUT_PER_EVENT_SEC   default 5     (≥1; cost per event in seconds)
//	TLVB_LLM_TIMEOUT_BUFFER_SEC      default 300   (≥0; constant overhead — startup, JSON validation, prompt cache miss)
//	TLVB_LLM_TIMEOUT_FLOOR_SEC       default 600   (≥0; minimum wall-clock = 10 min — small cases still get breathing room)
//	TLVB_LLM_TIMEOUT_CEILING_SEC     default 3600  (≥0; absolute cap   = 60 min — runaway protection)
//	TLVB_LLM_TIMEOUT_ANOMALY_MULT    default 1.5   (>0; anomaly_hunter scale factor)
//
// Example sizing for default values (per_event=5, buffer=300, floor=600,
// ceiling=3600, anomaly_mult=1.5):
//
//	maxEvents  Tactic Agent           anomaly_hunter
//	      50  600s  (floor)         900s  (floor in tactic terms, 1.5× of 9m)
//	     100  800s  → floor=600s    1200s (= 20 min, matches Wave 19 manual setting)
//	     200  1300s (= ~22 min)     1950s (= ~33 min)
//	     500  2800s (= ~47 min)     3600s (ceiling)
//	    1000  3600s (ceiling)       3600s (ceiling)
func ComputeTimeout(tactic string, maxEvents int) time.Duration {
	perEvent := envIntOr("TLVB_LLM_TIMEOUT_PER_EVENT_SEC", 5)
	buffer := envIntOr("TLVB_LLM_TIMEOUT_BUFFER_SEC", 300)
	floor := envIntOr("TLVB_LLM_TIMEOUT_FLOOR_SEC", 600)
	ceiling := envIntOr("TLVB_LLM_TIMEOUT_CEILING_SEC", 3600)
	mult := envFloatOr("TLVB_LLM_TIMEOUT_ANOMALY_MULT", 1.5)

	if maxEvents < 0 {
		maxEvents = 0
	}
	base := maxEvents*perEvent + buffer
	if tactic == "anomaly_hunter" && mult > 0 {
		base = int(float64(base) * mult)
	}
	if base < floor {
		base = floor
	}
	if ceiling > 0 && base > ceiling {
		base = ceiling
	}
	return time.Duration(base) * time.Second
}

// envIntOr reads a strictly-positive integer from ``name``; on missing
// / unparseable / non-positive values it falls back to ``def`` so a
// fat-fingered env var can never produce a zero-or-negative budget.
func envIntOr(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envFloatOr is the float counterpart of envIntOr.
func envFloatOr(name string, def float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}
