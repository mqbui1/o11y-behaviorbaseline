package fingerprintprocessor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// selfMetrics tracks internal processor counters and periodically sends them
// as Splunk custom events (datapoints) so the processor is observable via
// dashboards without log scraping.
//
// Counters are all atomic int64 — increment with Add, never reset.
// A snapshot is taken every ReportInterval and the delta since the last
// snapshot is emitted as a gauge.
type selfMetrics struct {
	// Cumulative counters
	TracesProcessed   atomic.Int64 // total trace buffers flushed
	FingerprintsKnown atomic.Int64 // traces matching baseline
	DriftEvents       atomic.Int64 // NEW_FINGERPRINT events emitted
	ErrorEvents       atomic.Int64 // NEW_ERROR_SIGNATURE events emitted
	MissingEvents     atomic.Int64 // MISSING_SERVICE events emitted
	LatencyEvents     atomic.Int64 // LATENCY_ANOMALY events emitted
	ErrorRateEvents   atomic.Int64 // ERROR_RATE_ANOMALY events emitted
	ThroughputEvents  atomic.Int64 // THROUGHPUT_DROP events emitted
	TopologyDrifts    atomic.Int64 // topology.edge.drift events emitted
	Promotions        atomic.Int64 // auto-promotions (trace + error)
	PartialTraces     atomic.Int64 // traces skipped by partial-trace guard

	// previous snapshot values (for delta computation)
	prev selfMetricsSnapshot

	ingestURL  string
	token      string
	environment string
	client     *http.Client
}

type selfMetricsSnapshot struct {
	TracesProcessed  int64
	DriftEvents      int64
	ErrorEvents      int64
	MissingEvents    int64
	LatencyEvents    int64
	ErrorRateEvents  int64
	ThroughputEvents int64
	TopologyDrifts   int64
	Promotions       int64
	PartialTraces    int64
}

func newSelfMetrics(ingestURL, token, environment string) *selfMetrics {
	return &selfMetrics{
		ingestURL:   ingestURL,
		token:       token,
		environment: environment,
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

// Run starts the periodic reporting loop. Stops when stopCh is closed.
func (sm *selfMetrics) Run(stopCh <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sm.report()
		case <-stopCh:
			sm.report() // final flush
			return
		}
	}
}

type sfDatapoint struct {
	Metric     string            `json:"metric"`
	Value      int64             `json:"value"`
	Dimensions map[string]string `json:"dimensions"`
	Timestamp  int64             `json:"timestamp"`
}

func (sm *selfMetrics) report() {
	now := time.Now()
	ts := now.UnixMilli()

	cur := selfMetricsSnapshot{
		TracesProcessed:  sm.TracesProcessed.Load(),
		DriftEvents:      sm.DriftEvents.Load(),
		ErrorEvents:      sm.ErrorEvents.Load(),
		MissingEvents:    sm.MissingEvents.Load(),
		LatencyEvents:    sm.LatencyEvents.Load(),
		ErrorRateEvents:  sm.ErrorRateEvents.Load(),
		ThroughputEvents: sm.ThroughputEvents.Load(),
		TopologyDrifts:   sm.TopologyDrifts.Load(),
		Promotions:       sm.Promotions.Load(),
		PartialTraces:    sm.PartialTraces.Load(),
	}

	dims := map[string]string{
		"sf_environment": sm.environment,
		"component":      "otelcol-fingerprint",
	}

	dps := []sfDatapoint{
		{Metric: "otelcol.fingerprint.traces_processed", Value: cur.TracesProcessed - sm.prev.TracesProcessed, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.drift_events", Value: cur.DriftEvents - sm.prev.DriftEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.error_events", Value: cur.ErrorEvents - sm.prev.ErrorEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.missing_events", Value: cur.MissingEvents - sm.prev.MissingEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.latency_events", Value: cur.LatencyEvents - sm.prev.LatencyEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.error_rate_events", Value: cur.ErrorRateEvents - sm.prev.ErrorRateEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.throughput_events", Value: cur.ThroughputEvents - sm.prev.ThroughputEvents, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.topology_drifts", Value: cur.TopologyDrifts - sm.prev.TopologyDrifts, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.promotions", Value: cur.Promotions - sm.prev.Promotions, Dimensions: dims, Timestamp: ts},
		{Metric: "otelcol.fingerprint.partial_traces_skipped", Value: cur.PartialTraces - sm.prev.PartialTraces, Dimensions: dims, Timestamp: ts},
	}
	sm.prev = cur

	sm.sendDatapoints(dps)
}

func (sm *selfMetrics) sendDatapoints(dps []sfDatapoint) {
	if sm.ingestURL == "" || sm.token == "" {
		return
	}
	// Send as Splunk custom events (reuse /v2/event with eventType=processor.metrics)
	type metricEvent struct {
		EventType  string            `json:"eventType"`
		Category   string            `json:"category"`
		Dimensions map[string]string `json:"dimensions"`
		Properties map[string]string `json:"properties"`
		Timestamp  int64             `json:"timestamp"`
	}
	props := make(map[string]string, len(dps))
	for _, dp := range dps {
		props[dp.Metric] = fmt.Sprintf("%d", dp.Value)
	}
	evt := metricEvent{
		EventType:  "processor.metrics",
		Category:   "USER_DEFINED",
		Dimensions: dps[0].Dimensions,
		Properties: props,
		Timestamp:  dps[0].Timestamp,
	}
	payload, err := json.Marshal([]metricEvent{evt})
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", sm.ingestURL+"/v2/event", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SF-Token", sm.token)
	resp, err := sm.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
