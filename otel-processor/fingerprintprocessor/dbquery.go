package fingerprintprocessor

import (
	"crypto/sha1"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ── SQL normalisation ─────────────────────────────────────────────────────────

var (
	// Replace quoted strings: 'value' → ?
	_reLitStr = regexp.MustCompile(`'[^']*'`)
	// Replace numeric literals: WHERE id = 42 → WHERE id = ?
	_reLitNum = regexp.MustCompile(`\b\d+\b`)
	// Replace IN (...) lists: IN (1,2,3) → IN (?)
	_reInList = regexp.MustCompile(`(?i)\bIN\s*\([^)]+\)`)
	// Collapse whitespace
	_reWS = regexp.MustCompile(`\s+`)
)

// normalizeQuery converts a raw SQL / query string into a stable template by
// stripping literal values.  The result is used as the fingerprint key so that
// the same logical query with different parameter values maps to one entry.
//
//	SELECT * FROM owners WHERE id = 42      → SELECT * FROM owners WHERE id = ?
//	SELECT * FROM owners WHERE name = 'foo' → SELECT * FROM owners WHERE name = ?
//	INSERT INTO pets (name) VALUES ('Fluffy')→ INSERT INTO pets (name) VALUES (?)
func normalizeQuery(q string) string {
	q = _reInList.ReplaceAllString(q, "IN (?)")
	q = _reLitStr.ReplaceAllString(q, "?")
	q = _reLitNum.ReplaceAllString(q, "?")
	q = _reWS.ReplaceAllString(strings.TrimSpace(q), " ")
	return strings.ToUpper(q)
}

// queryHash returns a short stable hash for a (service, dbSystem, template) tuple.
func queryHash(service, dbSystem, template string) string {
	h := sha1.Sum([]byte(service + "\x00" + dbSystem + "\x00" + template))
	return fmt.Sprintf("%x", h[:8])
}

// ── per-query sliding window ──────────────────────────────────────────────────

type queryWindow struct {
	// latency
	latencySamples []latencySample
	baselineMean   float64
	baselineStddev float64 // stored as M2 during learn phase, converted at detection
	baselineCount  int
	// plan / template tracking: first time seen, fires a new-query-plan event
	firstSeenAt time.Time
}

// ── dbQueryTracker ────────────────────────────────────────────────────────────

// dbQueryTracker observes DB spans (those with db.statement or db.operation
// attributes) and detects:
//
//  1. NEW_QUERY_PLAN  — a normalised query template seen for the first time
//     after warmup (potential schema change or new code path hitting the DB)
//  2. SLOW_QUERY      — current mean latency deviates by > zScore stddevs above
//     the learned baseline for this template (same algorithm as latency tracker)
//
// The tracker shares the emitter and Config with the parent processor.
type dbQueryTracker struct {
	mu        sync.Mutex
	windows   map[string]*queryWindow // key: queryHash(svc, dbSystem, template)
	emitter   *emitter
	cfg       *Config
	logger    *zap.Logger
	inWarmup  func() bool
	causality *causalityTracker
}

func newDbQueryTracker(cfg *Config, emit *emitter, inWarmup func() bool) *dbQueryTracker {
	return &dbQueryTracker{
		windows:  make(map[string]*queryWindow),
		emitter:  emit,
		cfg:      cfg,
		logger:   zap.NewNop(),
		inWarmup: inWarmup,
	}
}

func (d *dbQueryTracker) withLogger(l *zap.Logger) *dbQueryTracker {
	d.logger = l
	return d
}

// observe processes all spans from a flushed trace and checks for DB anomalies.
func (d *dbQueryTracker) observe(spans []spanInfo, env string) {
	if d.cfg.DbQueryLatencyWindow == 0 {
		return
	}

	now := time.Now()

	// Aggregate per (service, dbSystem, template) within this trace
	type qStats struct {
		totalDurNs float64
		count      int
	}
	type qKey struct{ svc, dbSystem, template, hash string }
	agg := make(map[qKey]*qStats)

	for _, s := range spans {
		stmt := s.tags["db.statement"]
		dbOp := s.tags["db.operation"]
		dbSys := s.tags["db.system"]
		if stmt == "" && dbOp == "" {
			continue // not a DB span
		}
		if s.durationNs == 0 {
			continue
		}
		raw := stmt
		if raw == "" {
			raw = dbOp
		}
		tmpl := normalizeQuery(raw)
		if tmpl == "" {
			continue
		}
		if dbSys == "" {
			dbSys = "unknown"
		}
		h := queryHash(s.service, dbSys, tmpl)
		k := qKey{svc: s.service, dbSystem: dbSys, template: tmpl, hash: h}
		st, ok := agg[k]
		if !ok {
			st = &qStats{}
			agg[k] = st
		}
		st.totalDurNs += float64(s.durationNs)
		st.count++
	}

	if len(agg) == 0 {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for k, st := range agg {
		w, exists := d.windows[k.hash]
		if !exists {
			w = &queryWindow{firstSeenAt: now}
			d.windows[k.hash] = w
			// New query plan — emit event if past warmup
			if !d.inWarmup() {
				d.logger.Info("new db query plan detected",
					zap.String("service", k.svc),
					zap.String("db_system", k.dbSystem),
					zap.String("template", truncate(k.template, 200)),
					zap.String("hash", k.hash),
					zap.String("environment", env),
				)
				if err := d.emitter.emitNewQueryPlan(env, k.svc, k.dbSystem, k.template, k.hash); err != nil {
					d.logger.Warn("failed to emit new query plan event", zap.Error(err))
				}
			}
		}

		avgLatNs := st.totalDurNs / float64(st.count)

		// Append latency sample and prune old ones
		w.latencySamples = append(w.latencySamples, latencySample{ts: now, value: avgLatNs})
		cutoff := now.Add(-d.cfg.DbQueryLatencyWindow)
		for len(w.latencySamples) > 0 && w.latencySamples[0].ts.Before(cutoff) {
			w.latencySamples = w.latencySamples[1:]
		}

		// Learn phase: build baseline
		if w.baselineCount < d.cfg.DbQueryLearnMinSamples {
			w.baselineCount++
			delta := avgLatNs - w.baselineMean
			w.baselineMean += delta / float64(w.baselineCount)
			delta2 := avgLatNs - w.baselineMean
			w.baselineStddev += delta * delta2 // stored as M2
			continue
		}

		// Detection phase
		currentMean := windowMean(w.latencySamples)
		if currentMean <= w.baselineMean {
			continue // only care about slowdowns
		}

		m2 := w.baselineStddev
		stddev := 0.0
		if w.baselineCount >= 2 {
			variance := m2 / float64(w.baselineCount)
			if variance > 0 {
				stddev = math.Sqrt(variance)
			}
		}
		if stddev < 1 {
			stddev = 1
		}

		zScore := (currentMean - w.baselineMean) / stddev
		if zScore >= d.cfg.DbQueryLatencyZScore {
			d.logger.Info("slow db query detected",
				zap.String("service", k.svc),
				zap.String("db_system", k.dbSystem),
				zap.String("template", truncate(k.template, 200)),
				zap.String("current_mean_ms", fmt.Sprintf("%.1f", currentMean/1e6)),
				zap.String("baseline_mean_ms", fmt.Sprintf("%.1f", w.baselineMean/1e6)),
				zap.String("z_score", fmt.Sprintf("%.2f", zScore)),
				zap.String("environment", env),
			)
			if err := d.emitter.emitSlowQuery(env, k.svc, k.dbSystem, k.template, k.hash,
				currentMean, w.baselineMean, stddev, zScore); err != nil {
				d.logger.Warn("failed to emit slow query event", zap.Error(err))
			} else if d.causality != nil {
				d.causality.record(k.svc, "SLOW_QUERY", time.Now())
			}
		}
	}
}

// knownTemplates returns a sorted snapshot of known query hashes (for debug/status).
func (d *dbQueryTracker) knownTemplates() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.windows))
	for k := range d.windows {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

