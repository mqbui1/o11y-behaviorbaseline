package fingerprintprocessor

import (
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// seasonalSlot holds a Welford online mean/variance accumulator for one
// hour-of-day × day-of-week bucket (168 slots total: 7 days × 24 hours).
type seasonalSlot struct {
	mean  float64
	m2    float64 // sum of squared deviations (Welford)
	count int
}

func (s *seasonalSlot) update(x float64) {
	s.count++
	delta := x - s.mean
	s.mean += delta / float64(s.count)
	s.m2 += delta * (x - s.mean)
}

func (s *seasonalSlot) stddev() float64 {
	if s.count < 2 {
		return 0
	}
	return math.Sqrt(s.m2 / float64(s.count))
}

// seasonalKey returns the index into a 168-slot array for a given time.
func seasonalKey(t time.Time) int {
	return int(t.Weekday())*24 + t.Hour()
}

// throughputWindow tracks request rate per root_op for drop detection.
type throughputWindow struct {
	// samples holds per-trace timestamps (one per observed trace for this root_op)
	samples      []time.Time
	baselineRate float64 // traces/min learned from first ThroughputLearnMinSamples
	learnCount   int
	dropEmitted  bool // true if we already fired a drop event this silence period
}

// metricWindow holds a rolling window of latency samples and error/total counts
// for a single (service, operation) pair.
type metricWindow struct {
	// latency samples (nanoseconds), oldest first
	latencySamples []latencySample
	// flat baseline: mean and stddev computed from the learn phase (legacy / fallback)
	baselineMean   float64
	baselineStddev float64
	baselineCount  int
	// seasonal baseline: 168 slots (weekday×hour), populated in parallel with flat baseline
	seasonal [168]seasonalSlot
	// error rate tracking
	errorBuckets []errorBucket // per-second buckets
	// when baseline was last updated
	baselineUpdatedAt time.Time
}

type latencySample struct {
	ts    time.Time
	value float64 // nanoseconds
}

type errorBucket struct {
	ts    time.Time
	errors int
	total  int
}

// spanRateBucket is a one-second span-count bucket for throughput estimation.
type spanRateBucket struct {
	ts    time.Time
	count int
}

// metricsTracker tracks per-(service,operation) latency and error rate,
// compares against a rolling baseline, and emits anomaly events.
type metricsTracker struct {
	mu      sync.Mutex
	windows map[string]*metricWindow // key: "service:operation"

	// spanRates tracks recent span throughput per service for user impact estimation.
	// key: service name, value: sliding window of 1s buckets over last 2 minutes.
	spanRates map[string][]spanRateBucket

	// throughput tracks per-root_op request rate for drop detection.
	throughput map[string]*throughputWindow // key: root_op

	emitter     *emitter
	cfg         *Config
	logger      *zap.Logger
	selfMetrics *selfMetrics
	causality   *causalityTracker
}

func newMetricsTracker(cfg *Config, emit *emitter) *metricsTracker {
	return &metricsTracker{
		windows:    make(map[string]*metricWindow),
		spanRates:  make(map[string][]spanRateBucket),
		throughput: make(map[string]*throughputWindow),
		emitter:    emit,
		cfg:        cfg,
		logger:     zap.NewNop(), // replaced by setLogger after construction
	}
}

// spansPerMin returns the estimated spans/min for a service over the last 2 minutes.
// Called with mu held.
func (m *metricsTracker) spansPerMin(service string, now time.Time) float64 {
	cutoff := now.Add(-2 * time.Minute)
	buckets := m.spanRates[service]
	total := 0
	for _, b := range buckets {
		if b.ts.After(cutoff) {
			total += b.count
		}
	}
	return float64(total) / 2.0 // spans per minute over last 2 min
}

func (m *metricsTracker) withLogger(l *zap.Logger) *metricsTracker {
	m.logger = l
	return m
}

func metricKey(service, operation string) string {
	return service + ":" + operation
}

// observe processes all spans from a flushed trace buffer.
// For each span it records latency and error status, then checks for anomalies.
func (m *metricsTracker) observe(spans []spanInfo, env string) {
	if m.cfg.LatencyAnomalyWindow == 0 && m.cfg.ErrorRateAnomalyWindow == 0 {
		return
	}

	now := time.Now()

	// Aggregate per (service, operation) within this trace
	type spanStats struct {
		totalDurationNs float64
		count           int
		errors          int
	}
	agg := make(map[string]*spanStats)

	for _, s := range spans {
		if s.service == "" || s.operation == "" || s.durationNs == 0 {
			continue
		}
		if isNoiseOperation(s.operation) {
			continue
		}
		key := metricKey(s.service, s.operation)
		st, ok := agg[key]
		if !ok {
			st = &spanStats{}
			agg[key] = st
		}
		st.totalDurationNs += float64(s.durationNs)
		st.count++
		if s.isError {
			st.errors++
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update per-service span rate buckets (for impact estimation)
	spanRateCutoff := now.Add(-2 * time.Minute)
	svcSpans := make(map[string]int)
	for key, st := range agg {
		svc, _ := splitKey(key)
		svcSpans[svc] += st.count
	}
	for svc, cnt := range svcSpans {
		buckets := m.spanRates[svc]
		// Prune old buckets
		pruned := buckets[:0]
		for _, b := range buckets {
			if b.ts.After(spanRateCutoff) {
				pruned = append(pruned, b)
			}
		}
		m.spanRates[svc] = append(pruned, spanRateBucket{ts: now, count: cnt})
	}

	for key, st := range agg {
		w, ok := m.windows[key]
		if !ok {
			w = &metricWindow{}
			m.windows[key] = w
		}

		avgLatency := st.totalDurationNs / float64(st.count)

		// ── Latency tracking ──────────────────────────────────────────────
		if m.cfg.LatencyAnomalyWindow > 0 {
			// Append sample and prune old ones
			w.latencySamples = append(w.latencySamples, latencySample{ts: now, value: avgLatency})
			cutoff := now.Add(-m.cfg.LatencyAnomalyWindow)
			for len(w.latencySamples) > 0 && w.latencySamples[0].ts.Before(cutoff) {
				w.latencySamples = w.latencySamples[1:]
			}

			// Always update seasonal slot (even during learn phase)
			slot := &w.seasonal[seasonalKey(now)]
			slot.update(avgLatency)

			// Build flat baseline from first LearnWindow samples before detecting
			if w.baselineCount < m.cfg.LatencyLearnMinSamples {
				w.baselineCount++
				// Update running mean and M2 for Welford's online algorithm
				delta := avgLatency - w.baselineMean
				w.baselineMean += delta / float64(w.baselineCount)
				delta2 := avgLatency - w.baselineMean
				// Store M2 in baselineStddev temporarily, convert at detection time
				w.baselineStddev += delta * delta2
				w.baselineUpdatedAt = now
			} else {
				// Compute current window mean
				currentMean := windowMean(w.latencySamples)

				// Prefer seasonal baseline when the current slot has enough samples,
				// otherwise fall back to the flat baseline.
				baselineMean := w.baselineMean
				var stddev float64
				if slot.count >= m.cfg.LatencyLearnMinSamples {
					baselineMean = slot.mean
					stddev = slot.stddev()
				} else {
					// Convert stored M2 to stddev
					stddev = math.Sqrt(w.baselineStddev / float64(w.baselineCount))
				}
				if stddev < 1 {
					stddev = 1 // avoid division by zero / noise
				}
				// Anomaly: current mean deviates by more than threshold stddevs
				// AND is above baseline (we only care about slowdowns, not speedups)
				zScore := (currentMean - baselineMean) / stddev
				if zScore >= m.cfg.LatencyAnomalyZScore && currentMean > baselineMean {
					svc, op := splitKey(key)
					seasonal := slot.count >= m.cfg.LatencyLearnMinSamples
					spMin := m.spansPerMin(svc, now)
					m.logger.Info("latency anomaly detected",
						zap.String("service", svc),
						zap.String("operation", op),
						zap.String("current_mean_ms", fmt.Sprintf("%.1f", currentMean/1e6)),
						zap.String("baseline_mean_ms", fmt.Sprintf("%.1f", baselineMean/1e6)),
						zap.String("stddev_ms", fmt.Sprintf("%.1f", stddev/1e6)),
						zap.String("z_score", fmt.Sprintf("%.2f", zScore)),
						zap.String("seasonal_baseline", fmt.Sprintf("%v", seasonal)),
						zap.String("spans_per_min", fmt.Sprintf("%.0f", spMin)),
						zap.String("environment", env),
					)
					if err := m.emitter.emitLatencyAnomaly(env, svc, op,
						currentMean, baselineMean, stddev, zScore); err == nil && m.selfMetrics != nil {
						m.selfMetrics.LatencyEvents.Add(1)
					}
				}
			}
		}

		// ── Error rate tracking ───────────────────────────────────────────
		if m.cfg.ErrorRateAnomalyWindow > 0 {
			// Append bucket and prune
			w.errorBuckets = append(w.errorBuckets, errorBucket{
				ts: now, errors: st.errors, total: st.count,
			})
			cutoff := now.Add(-m.cfg.ErrorRateAnomalyWindow)
			for len(w.errorBuckets) > 0 && w.errorBuckets[0].ts.Before(cutoff) {
				w.errorBuckets = w.errorBuckets[1:]
			}

			// Need at least MinErrorRateSamples before alerting
			if len(w.errorBuckets) < m.cfg.MinErrorRateSamples {
				continue
			}

			totalSpans, totalErrors := 0, 0
			for _, b := range w.errorBuckets {
				totalSpans += b.total
				totalErrors += b.errors
			}
			if totalSpans == 0 {
				continue
			}
			errorRate := float64(totalErrors) / float64(totalSpans)
			if errorRate >= m.cfg.ErrorRateAnomalyThreshold {
				svc, op := splitKey(key)
				spMin := m.spansPerMin(svc, now)
				m.logger.Info("error rate anomaly detected",
					zap.String("service", svc),
					zap.String("operation", op),
					zap.String("error_rate", fmt.Sprintf("%.3f", errorRate)),
					zap.String("error_pct", fmt.Sprintf("%.1f%%", errorRate*100)),
					zap.Int("error_count", totalErrors),
					zap.Int("total_count", totalSpans),
					zap.String("spans_per_min", fmt.Sprintf("%.0f", spMin)),
					zap.String("environment", env),
				)
				if err := m.emitter.emitErrorRateAnomaly(env, svc, op,
				errorRate, totalErrors, totalSpans); err == nil && m.selfMetrics != nil {
				m.selfMetrics.ErrorRateEvents.Add(1)
			}
			}
		}
	}
}

// observeRootOp records a trace arrival for throughput drop detection.
// Called once per flushed trace from analyzeTrace (with the resolved rootOp).
func (m *metricsTracker) observeRootOp(rootOp, env string, inWarmup bool) {
	if m.cfg.ThroughputDropWindow == 0 || inWarmup {
		return
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	tw, ok := m.throughput[rootOp]
	if !ok {
		tw = &throughputWindow{}
		m.throughput[rootOp] = tw
	}

	tw.samples = append(tw.samples, now)

	// Prune samples outside the window
	cutoff := now.Add(-m.cfg.ThroughputDropWindow)
	keep := 0
	for keep < len(tw.samples) && tw.samples[keep].Before(cutoff) {
		keep++
	}
	tw.samples = tw.samples[keep:]

	windowMins := m.cfg.ThroughputDropWindow.Minutes()
	currentRate := float64(len(tw.samples)) / windowMins

	// Learn phase: accumulate until we have enough samples
	if tw.learnCount < m.cfg.ThroughputLearnMinSamples {
		tw.learnCount++
		// Update rolling baseline rate using EWMA (α=0.1 after learn phase)
		if tw.baselineRate == 0 {
			tw.baselineRate = currentRate
		} else {
			tw.baselineRate = 0.9*tw.baselineRate + 0.1*currentRate
		}
		tw.dropEmitted = false
		return
	}

	// Detection: rate dropped below threshold fraction of baseline
	if tw.baselineRate > 0 {
		ratio := currentRate / tw.baselineRate
		if ratio < (1-m.cfg.ThroughputDropThreshold) && !tw.dropEmitted {
			m.logger.Info("throughput drop detected",
				zap.String("root_op", rootOp),
				zap.String("current_rate_pm", fmt.Sprintf("%.2f", currentRate)),
				zap.String("baseline_rate_pm", fmt.Sprintf("%.2f", tw.baselineRate)),
				zap.String("drop_pct", fmt.Sprintf("%.1f%%", (1-ratio)*100)),
				zap.String("environment", env),
			)
			tw.dropEmitted = true
			if err := m.emitter.emitThroughputDrop(env, rootOp, currentRate, tw.baselineRate); err == nil {
				if m.selfMetrics != nil {
					m.selfMetrics.ThroughputEvents.Add(1)
				}
				if m.causality != nil {
					m.causality.record(rootService(rootOp), "THROUGHPUT_DROP", time.Now())
				}
			}
		} else if ratio >= (1-m.cfg.ThroughputDropThreshold/2) {
			// Rate recovered to within half the threshold — reset so we can fire again
			tw.dropEmitted = false
			// Slowly update baseline with recovered rate
			tw.baselineRate = 0.95*tw.baselineRate + 0.05*currentRate
		}
	}
}

// windowMean computes the arithmetic mean of latency samples in the window.
func windowMean(samples []latencySample) float64 {
	if len(samples) == 0 {
		return 0
	}
	sum := 0.0
	for _, s := range samples {
		sum += s.value
	}
	return sum / float64(len(samples))
}

// splitKey splits "service:operation" back into its parts.
func splitKey(key string) (string, string) {
	for i, c := range key {
		if c == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

// formatNs formats nanoseconds as a human-readable string.
func formatNs(ns float64) string {
	ms := ns / 1e6
	if ms >= 1000 {
		return fmt.Sprintf("%.2fs", ms/1000)
	}
	return fmt.Sprintf("%.1fms", ms)
}
