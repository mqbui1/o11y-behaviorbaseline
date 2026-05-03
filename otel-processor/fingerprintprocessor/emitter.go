package fingerprintprocessor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type splunkEvent struct {
	EventType  string            `json:"eventType"`
	Category   string            `json:"category"`
	Dimensions map[string]string `json:"dimensions"`
	Properties map[string]string `json:"properties"`
	Timestamp  int64             `json:"timestamp"`
}

type emitter struct {
	ingestURL string
	token     string // token for /v2/event — ingest token works, API token does not
	client    *http.Client
}

func newEmitter(ingestURL, apiToken, fallbackToken string) *emitter {
	token := apiToken
	if token == "" {
		token = fallbackToken
	}
	return &emitter{
		ingestURL: ingestURL,
		token:     token,
		client:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (e *emitter) emitTraceDrift(env, traceID string, fp *traceFingerprint) error {
	// EventType matches what correlate.py queries: TIER_EVENT_MAP["trace.path.drift"] = "tier2"
	return e.send(splunkEvent{
		EventType: "trace.path.drift",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "NEW_FINGERPRINT",
			// root_operation used by correlate.py._infer_service_from_event() to extract
			// service name when no explicit "service" dimension is present.
			"root_operation": fp.rootOp,
			"service":        rootService(fp.rootOp),
			"fp_hash":        fp.hash,
		},
		Properties: map[string]string{
			"trace_id":    traceID,
			"root_op":     fp.rootOp,
			"hash":        fp.hash,
			"path":        fp.path,
			"services":    joinStrings(fp.services),
			"span_count":  fmt.Sprintf("%d", fp.spanCount),
			"edge_count":  fmt.Sprintf("%d", fp.edgeCount),
			"detector":    "otel-collector-edge",
			"environment": env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitErrorDrift(env, traceID string, sig errorSignature) error {
	// EventType matches what correlate.py queries: TIER_EVENT_MAP["error.signature.drift"] = "tier3"
	return e.send(splunkEvent{
		EventType: "error.signature.drift",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "NEW_ERROR_SIGNATURE",
			"service":        sig.service,
			"error_type":     sig.errorType,
			"sig_hash":       sig.hash,
		},
		Properties: map[string]string{
			"trace_id":    traceID,
			"service":     sig.service,
			"error_type":  sig.errorType,
			"http_status": sig.httpStatus,
			"operation":   sig.operation,
			"call_path":   sig.callPath,
			"hash":        sig.hash,
			"detector":    "otel-collector-edge",
			"environment": env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitMissingService(env, rootOp string, missingServices []string, lastSeenSec int64) error {
	// Emits trace.path.drift with anomaly_type=MISSING_SERVICE so correlate.py
	// picks it up as tier2 — same event type as NEW_FINGERPRINT drift.
	return e.send(splunkEvent{
		EventType: "trace.path.drift",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "MISSING_SERVICE",
			"root_operation": rootOp,
			"service":        rootService(rootOp),
		},
		Properties: map[string]string{
			"root_op":          rootOp,
			"missing_services": joinStrings(missingServices),
			"last_seen_sec":    fmt.Sprintf("%d", lastSeenSec),
			"detector":         "otel-collector-edge",
			"environment":      env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitTraceRestored(env string, fp *traceFingerprint) error {
	return e.send(splunkEvent{
		EventType: "trace.path.restored",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "TRACE_RESTORED",
			"root_operation": fp.rootOp,
			"service":        rootService(fp.rootOp),
			"fp_hash":        fp.hash,
		},
		Properties: map[string]string{
			"root_op":     fp.rootOp,
			"hash":        fp.hash,
			"path":        fp.path,
			"detector":    "otel-collector-edge",
			"environment": env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitErrorRateSpike(env string, sig errorSignature, ratePerMin, baselinePerMin float64) error {
	return e.send(splunkEvent{
		EventType: "error.signature.spike",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "ERROR_RATE_SPIKE",
			"service":        sig.service,
			"error_type":     sig.errorType,
			"sig_hash":       sig.hash,
		},
		Properties: map[string]string{
			"service":              sig.service,
			"error_type":           sig.errorType,
			"operation":            sig.operation,
			"hash":                 sig.hash,
			"rate_per_min":         fmt.Sprintf("%.2f", ratePerMin),
			"baseline_rate_per_min": fmt.Sprintf("%.2f", baselinePerMin),
			"detector":             "otel-collector-edge",
			"environment":          env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitTopologyEdge(env string, edge topologyEdge) error {
	return e.send(splunkEvent{
		EventType: "service.topology.edge",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"caller":         edge.Caller,
			"callee":         edge.Callee,
		},
		Properties: map[string]string{
			"caller":      edge.Caller,
			"callee":      edge.Callee,
			"first_seen":  fmt.Sprintf("%d", edge.FirstSeen.UnixMilli()),
			"detector":    "otel-collector-edge",
			"environment": env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitPromotion(env, hash, rootOp, kind string, detections int) error {
	return e.send(splunkEvent{
		EventType: "trace.fingerprint.promoted",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"kind":           kind, // "trace" or "error"
			"service":        rootService(rootOp),
		},
		Properties: map[string]string{
			"hash":        hash,
			"root_op":     rootOp,
			"kind":        kind,
			"detections":  fmt.Sprintf("%d", detections),
			"detector":    "otel-collector-edge",
			"environment": env,
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) send(evt splunkEvent) error {
	payload, err := json.Marshal([]splunkEvent{evt})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", e.ingestURL+"/v2/event", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SF-Token", e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("splunk ingest returned %d", resp.StatusCode)
	}
	return nil
}

func (e *emitter) emitLatencyAnomaly(env, service, operation string, currentMeanNs, baselineMeanNs, stddevNs, zScore float64) error {
	return e.send(splunkEvent{
		EventType: "service.latency.anomaly",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"sf_service":     service,
			"sf_operation":   operation,
			"anomaly_type":   "LATENCY_ANOMALY",
		},
		Properties: map[string]string{
			"service":          service,
			"operation":        operation,
			"environment":      env,
			"current_mean_ms":  fmt.Sprintf("%.1f", currentMeanNs/1e6),
			"baseline_mean_ms": fmt.Sprintf("%.1f", baselineMeanNs/1e6),
			"stddev_ms":        fmt.Sprintf("%.1f", stddevNs/1e6),
			"z_score":          fmt.Sprintf("%.2f", zScore),
			"detector":         "otel-latency-anomaly",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitErrorRateAnomaly(env, service, operation string, errorRate float64, errorCount, totalCount int) error {
	return e.send(splunkEvent{
		EventType: "service.error.rate.anomaly",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"sf_service":     service,
			"sf_operation":   operation,
			"anomaly_type":   "ERROR_RATE_ANOMALY",
		},
		Properties: map[string]string{
			"service":     service,
			"operation":   operation,
			"environment": env,
			"error_rate":  fmt.Sprintf("%.3f", errorRate),
			"error_pct":   fmt.Sprintf("%.1f%%", errorRate*100),
			"error_count": fmt.Sprintf("%d", errorCount),
			"total_count": fmt.Sprintf("%d", totalCount),
			"detector":    "otel-error-rate-anomaly",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitThroughputDrop(env, rootOp string, currentRate, baselineRate float64) error {
	dropPct := 0.0
	if baselineRate > 0 {
		dropPct = (1 - currentRate/baselineRate) * 100
	}
	return e.send(splunkEvent{
		EventType: "service.throughput.drop",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "THROUGHPUT_DROP",
			"service":        rootService(rootOp),
			"root_operation": rootOp,
		},
		Properties: map[string]string{
			"root_op":           rootOp,
			"service":           rootService(rootOp),
			"environment":       env,
			"current_rate_pm":   fmt.Sprintf("%.2f", currentRate),
			"baseline_rate_pm":  fmt.Sprintf("%.2f", baselineRate),
			"drop_pct":          fmt.Sprintf("%.1f%%", dropPct),
			"detector":          "otel-throughput-drop",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitTopologyDrift(env, caller, callee string) error {
	return e.send(splunkEvent{
		EventType: "topology.edge.drift",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "NEW_TOPOLOGY_EDGE",
			"caller":         caller,
			"callee":         callee,
		},
		Properties: map[string]string{
			"caller":      caller,
			"callee":      callee,
			"environment": env,
			"detector":    "otel-topology-drift",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitBaselineStale(env, baselinePath string, ageSecs int64, promotionsSinceLoad int) error {
	return e.send(splunkEvent{
		EventType: "baseline.stale",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"anomaly_type":   "BASELINE_STALE",
		},
		Properties: map[string]string{
			"baseline_path":         baselinePath,
			"age_hours":             fmt.Sprintf("%.1f", float64(ageSecs)/3600),
			"promotions_since_load": fmt.Sprintf("%d", promotionsSinceLoad),
			"environment":           env,
			"detector":              "otel-baseline-staleness",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitBootstrapComplete(env string, fingerprintCount, errorSigCount int) error {
	return e.send(splunkEvent{
		EventType: "baseline.bootstrap.complete",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
		},
		Properties: map[string]string{
			"fingerprint_count": fmt.Sprintf("%d", fingerprintCount),
			"error_sig_count":   fmt.Sprintf("%d", errorSigCount),
			"environment":       env,
			"detector":          "otel-bootstrap",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitNewQueryPlan(env, service, dbSystem, template, hash string) error {
	tmplTrunc := template
	if len(tmplTrunc) > 300 {
		tmplTrunc = tmplTrunc[:300] + "..."
	}
	return e.send(splunkEvent{
		EventType: "db.query.new_plan",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"sf_service":     service,
			"anomaly_type":   "NEW_QUERY_PLAN",
		},
		Properties: map[string]string{
			"service":     service,
			"environment": env,
			"db_system":   dbSystem,
			"template":    tmplTrunc,
			"hash":        hash,
			"detector":    "otel-db-query",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func (e *emitter) emitSlowQuery(env, service, dbSystem, template, hash string,
	currentMeanNs, baselineMeanNs, stddevNs, zScore float64) error {
	tmplTrunc := template
	if len(tmplTrunc) > 300 {
		tmplTrunc = tmplTrunc[:300] + "..."
	}
	return e.send(splunkEvent{
		EventType: "db.query.slow",
		Category:  "USER_DEFINED",
		Dimensions: map[string]string{
			"sf_environment": env,
			"sf_service":     service,
			"anomaly_type":   "SLOW_QUERY",
		},
		Properties: map[string]string{
			"service":          service,
			"environment":      env,
			"db_system":        dbSystem,
			"template":         tmplTrunc,
			"hash":             hash,
			"current_mean_ms":  fmt.Sprintf("%.1f", currentMeanNs/1e6),
			"baseline_mean_ms": fmt.Sprintf("%.1f", baselineMeanNs/1e6),
			"stddev_ms":        fmt.Sprintf("%.1f", stddevNs/1e6),
			"z_score":          fmt.Sprintf("%.2f", zScore),
			"detector":         "otel-db-query",
		},
		Timestamp: time.Now().UnixMilli(),
	})
}

func rootService(rootOp string) string {
	if idx := strings.Index(rootOp, ":"); idx >= 0 {
		return rootOp[:idx]
	}
	return rootOp
}

func joinStrings(ss []string) string {
	return strings.Join(ss, ",")
}
