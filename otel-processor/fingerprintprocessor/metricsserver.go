package fingerprintprocessor

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"time"
)

// MetricsSnapshot is the JSON shape returned by GET /metrics.
// It contains a point-in-time view of every (service, operation) window
// so the topology server can drive per-service sparklines without any
// log scraping or Splunk queries.
type MetricsSnapshot struct {
	Timestamp   int64                      `json:"timestamp_ms"`
	Environment string                     `json:"environment"`
	Uptime      int64                      `json:"uptime_s"`
	Services    map[string]*ServiceMetrics `json:"services"`
	Summary     EnvSummary                 `json:"summary"`
}

// ServiceMetrics aggregates all operations for one service.
type ServiceMetrics struct {
	Service     string               `json:"service"`
	SpansPerMin float64              `json:"spans_per_min"`
	Operations  []*OperationMetrics  `json:"operations"`
	// Rolled-up across all operations for this service
	LatencyMeanMs   float64 `json:"latency_mean_ms"`
	BaselineMeanMs  float64 `json:"baseline_mean_ms"`
	ErrorRatePct    float64 `json:"error_rate_pct"`
	ZScore          float64 `json:"z_score"`
	Status          string  `json:"status"` // "ok" | "warn" | "anomaly"
}

// OperationMetrics is the per-(service,operation) view.
type OperationMetrics struct {
	Operation       string  `json:"operation"`
	LatencyMeanMs   float64 `json:"latency_mean_ms"`
	BaselineMeanMs  float64 `json:"baseline_mean_ms"`
	BaselineStddevMs float64 `json:"baseline_stddev_ms"`
	ZScore          float64 `json:"z_score"`
	ErrorRatePct    float64 `json:"error_rate_pct"`
	ErrorCount      int     `json:"error_count"`
	TotalCount      int     `json:"total_count"`
	SampleCount     int     `json:"sample_count"`
	LearnProgress   float64 `json:"learn_progress"` // 0–1, fraction of learn phase complete
	Status          string  `json:"status"`          // "learning" | "ok" | "warn" | "anomaly"
}

// EnvSummary is the environment-wide rollup shown in the top bar.
type EnvSummary struct {
	TotalServices    int     `json:"total_services"`
	ServicesAnomaly  int     `json:"services_anomaly"`
	ServicesWarn     int     `json:"services_warn"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	AvgErrorRatePct  float64 `json:"avg_error_rate_pct"`
	TotalSpansPerMin float64 `json:"total_spans_per_min"`
}

// startMetricsServer starts a lightweight HTTP server on addr (e.g. ":9090")
// that serves GET /metrics as a MetricsSnapshot JSON dump.
// It runs in a background goroutine and stops when stopCh is closed.
func (p *fingerprintProcessor) startMetricsServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		snapshot := p.buildMetricsSnapshot()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(snapshot)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ok":true}`)
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.logger.Sugar().Warnf("metrics server: could not bind %s: %v", addr, err)
		return
	}
	p.logger.Sugar().Infof("metrics server listening on %s", addr)

	srv := &http.Server{Handler: mux}
	go func() {
		<-p.stopCh
		_ = srv.Close()
	}()
	go func() {
		_ = srv.Serve(ln)
	}()
}

// buildMetricsSnapshot takes a point-in-time snapshot of metricsTracker state.
func (p *fingerprintProcessor) buildMetricsSnapshot() MetricsSnapshot {
	now := time.Now()

	p.metrics.mu.Lock()
	defer p.metrics.mu.Unlock()

	services := make(map[string]*ServiceMetrics)

	for key, w := range p.metrics.windows {
		svc, op := splitKey(key)
		if svc == "" {
			continue
		}

		sm, ok := services[svc]
		if !ok {
			sm = &ServiceMetrics{
				Service:    svc,
				Operations: make([]*OperationMetrics, 0),
			}
			services[svc] = sm
		}

		om := buildOperationMetrics(op, w, p.cfg.LatencyLearnMinSamples, p.cfg.LatencyAnomalyZScore, p.cfg.MinErrorRateSamples)
		sm.Operations = append(sm.Operations, om)
	}

	// Compute per-service span rates and roll up metrics
	for svc, sm := range services {
		sm.SpansPerMin = p.metrics.spansPerMin(svc, now)

		// Roll up: prefer the worst-status operation for the summary fields so the
		// service card reflects the most urgent signal. Tie-break by highest z-score.
		var bestOp *OperationMetrics
		for _, op := range sm.Operations {
			if bestOp == nil {
				bestOp = op
				continue
			}
			rankA := map[string]int{"learning": 0, "ok": 1, "warn": 2, "anomaly": 3}
			if rankA[op.Status] > rankA[bestOp.Status] ||
				(op.Status == bestOp.Status && op.ZScore > bestOp.ZScore) {
				bestOp = op
			}
		}
		if bestOp != nil {
			sm.LatencyMeanMs = bestOp.LatencyMeanMs
			sm.BaselineMeanMs = bestOp.BaselineMeanMs
			sm.ZScore = bestOp.ZScore
			sm.Status = bestOp.Status
		}

		// Error rate: aggregate across all operations
		var totalErrors, totalSpans int
		for _, op := range sm.Operations {
			totalErrors += op.ErrorCount
			totalSpans += op.TotalCount
		}
		if totalSpans > 0 {
			sm.ErrorRatePct = float64(totalErrors) / float64(totalSpans) * 100
		}

		// Sort operations by sample count descending
		sort.Slice(sm.Operations, func(i, j int) bool {
			return sm.Operations[i].SampleCount > sm.Operations[j].SampleCount
		})

		// Promote status: worst operation wins
		for _, op := range sm.Operations {
			sm.Status = worstStatus(sm.Status, op.Status)
		}
	}

	// Environment summary
	var summary EnvSummary
	summary.TotalServices = len(services)
	var latSum, errSum, spanSum float64
	for _, sm := range services {
		spanSum += sm.SpansPerMin
		if sm.BaselineMeanMs > 0 {
			latSum += sm.LatencyMeanMs
			errSum += sm.ErrorRatePct
		}
		switch sm.Status {
		case "anomaly":
			summary.ServicesAnomaly++
		case "warn":
			summary.ServicesWarn++
		}
	}
	if summary.TotalServices > 0 {
		summary.AvgLatencyMs = latSum / float64(summary.TotalServices)
		summary.AvgErrorRatePct = errSum / float64(summary.TotalServices)
	}
	summary.TotalSpansPerMin = spanSum

	return MetricsSnapshot{
		Timestamp:   now.UnixMilli(),
		Environment: p.cfg.Environment,
		Uptime:      int64(time.Since(p.startTime).Seconds()),
		Services:    services,
		Summary:     summary,
	}
}

// buildOperationMetrics computes the OperationMetrics for one metricWindow.
func buildOperationMetrics(op string, w *metricWindow, learnMin int, zThreshold float64, minErrSamples int) *OperationMetrics {
	om := &OperationMetrics{
		Operation: op,
	}

	// Current latency: mean of rolling window samples
	if len(w.latencySamples) > 0 {
		om.LatencyMeanMs = windowMean(w.latencySamples) / 1e6
	}
	om.SampleCount = w.baselineCount

	// Learn progress (0–1)
	if learnMin > 0 {
		om.LearnProgress = math.Min(1.0, float64(w.baselineCount)/float64(learnMin))
	}

	if w.baselineCount >= learnMin {
		// Baseline established — compute stddev from stored M2
		baselineMean := w.baselineMean
		stddev := math.Sqrt(w.baselineStddev / float64(w.baselineCount))
		if stddev < 1 {
			stddev = 1
		}
		om.BaselineMeanMs = baselineMean / 1e6
		om.BaselineStddevMs = stddev / 1e6

		if om.LatencyMeanMs > 0 {
			om.ZScore = (w.baselineMean/1e6 + om.LatencyMeanMs - om.BaselineMeanMs) // approximate
			om.ZScore = (om.LatencyMeanMs - om.BaselineMeanMs) / om.BaselineStddevMs
		}

		switch {
		case om.ZScore >= zThreshold:
			om.Status = "anomaly"
		case om.ZScore >= zThreshold*0.6:
			om.Status = "warn"
		default:
			om.Status = "ok"
		}
	} else {
		om.Status = "learning"
	}

	// Error rate: aggregate buckets
	var totalErrors, totalSpans int
	for _, b := range w.errorBuckets {
		totalErrors += b.errors
		totalSpans += b.total
	}
	om.ErrorCount = totalErrors
	om.TotalCount = totalSpans
	if totalSpans > 0 {
		om.ErrorRatePct = float64(totalErrors) / float64(totalSpans) * 100
		// Only upgrade status based on error rate once we have enough samples —
		// avoids false anomalies from long-lived streaming ops or sparse early data.
		if totalSpans >= minErrSamples {
			if om.ErrorRatePct >= 5.0 && om.Status != "anomaly" {
				om.Status = "anomaly"
			} else if om.ErrorRatePct >= 1.0 && om.Status == "ok" {
				om.Status = "warn"
			}
		}
	}

	return om
}

// worstStatus returns the more severe of two status strings.
func worstStatus(a, b string) string {
	rank := map[string]int{"learning": 0, "ok": 1, "warn": 2, "anomaly": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
