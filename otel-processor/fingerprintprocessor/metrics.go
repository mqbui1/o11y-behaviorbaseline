package fingerprintprocessor

import (
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// metricWindow holds a rolling window of latency samples and error/total counts
// for a single (service, operation) pair.
type metricWindow struct {
	// latency samples (nanoseconds), oldest first
	latencySamples []latencySample
	// baseline: mean and stddev computed from the learn phase
	baselineMean   float64
	baselineStddev float64
	baselineCount  int
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

// metricsTracker tracks per-(service,operation) latency and error rate,
// compares against a rolling baseline, and emits anomaly events.
type metricsTracker struct {
	mu      sync.Mutex
	windows map[string]*metricWindow // key: "service:operation"

	emitter *emitter
	cfg     *Config
	logger  *zap.Logger
}

func newMetricsTracker(cfg *Config, emit *emitter) *metricsTracker {
	return &metricsTracker{
		windows: make(map[string]*metricWindow),
		emitter: emit,
		cfg:     cfg,
		logger:  zap.NewNop(), // replaced by setLogger after construction
	}
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

			// Build baseline from first LearnWindow samples before detecting
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
				// Convert stored M2 to stddev
				stddev := math.Sqrt(w.baselineStddev / float64(w.baselineCount))
				if stddev < 1 {
					stddev = 1 // avoid division by zero / noise
				}
				// Anomaly: current mean deviates by more than threshold stddevs
				// AND is above baseline (we only care about slowdowns, not speedups)
				zScore := (currentMean - w.baselineMean) / stddev
				if zScore >= m.cfg.LatencyAnomalyZScore && currentMean > w.baselineMean {
					svc, op := splitKey(key)
					m.logger.Info("latency anomaly detected",
						zap.String("service", svc),
						zap.String("operation", op),
						zap.String("current_mean_ms", fmt.Sprintf("%.1f", currentMean/1e6)),
						zap.String("baseline_mean_ms", fmt.Sprintf("%.1f", w.baselineMean/1e6)),
						zap.String("stddev_ms", fmt.Sprintf("%.1f", stddev/1e6)),
						zap.String("z_score", fmt.Sprintf("%.2f", zScore)),
						zap.String("environment", env),
					)
					_ = m.emitter.emitLatencyAnomaly(env, svc, op,
						currentMean, w.baselineMean, stddev, zScore)
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
				m.logger.Info("error rate anomaly detected",
					zap.String("service", svc),
					zap.String("operation", op),
					zap.String("error_rate", fmt.Sprintf("%.3f", errorRate)),
					zap.String("error_pct", fmt.Sprintf("%.1f%%", errorRate*100)),
					zap.Int("error_count", totalErrors),
					zap.Int("total_count", totalSpans),
					zap.String("environment", env),
				)
				_ = m.emitter.emitErrorRateAnomaly(env, svc, op,
					errorRate, totalErrors, totalSpans)
			}
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
