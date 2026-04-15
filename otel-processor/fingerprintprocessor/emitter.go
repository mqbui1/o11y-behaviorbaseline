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
	token     string // ingest token for /v2/event
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

func rootService(rootOp string) string {
	if idx := strings.Index(rootOp, ":"); idx >= 0 {
		return rootOp[:idx]
	}
	return rootOp
}

func joinStrings(ss []string) string {
	return strings.Join(ss, ",")
}
