package fingerprintprocessor

import (
	"time"

	"go.opentelemetry.io/collector/component"
)

// Config is the configuration for the fingerprint processor.
type Config struct {
	// TraceBufferTimeout is how long to wait for all spans of a trace before
	// flushing. Longer = more complete traces, higher latency. Default: 10s.
	TraceBufferTimeout time.Duration `mapstructure:"trace_buffer_timeout"`

	// BaselinePath is the path to the baseline JSON file mounted into the
	// collector pod (e.g. /baseline/baseline.json).
	BaselinePath string `mapstructure:"baseline_path"`

	// ErrorBaselinePath is the path to the error baseline JSON file.
	ErrorBaselinePath string `mapstructure:"error_baseline_path"`

	// Environment is the deployment.environment value for this collector
	// instance (e.g. "bdf-7fdc-workshop"). Used as a dimension on emitted events.
	Environment string `mapstructure:"environment"`

	// SplunkIngestURL is the Splunk ingest endpoint (e.g. https://ingest.us1.signalfx.com).
	SplunkIngestURL string `mapstructure:"splunk_ingest_url"`

	// SplunkAccessToken is the ingest token for trace/metric forwarding.
	SplunkAccessToken string `mapstructure:"splunk_access_token"`

	// SplunkApiToken is the API token for emitting custom events to /v2/event.
	// If unset, falls back to SplunkAccessToken.
	SplunkApiToken string `mapstructure:"splunk_api_token"`

	// MinSpans is the minimum number of spans required to fingerprint a trace.
	// Traces with fewer spans are skipped. Default: 2.
	MinSpans int `mapstructure:"min_spans"`

	// MinBaselineOccurrences is how many times a fingerprint must appear in
	// the baseline to be considered "established". Default: 2.
	MinBaselineOccurrences int `mapstructure:"min_baseline_occurrences"`

	// BaselineReloadInterval controls how often the baseline file is re-read
	// from disk (to pick up updates from the Python learn cycle). Default: 60s.
	BaselineReloadInterval time.Duration `mapstructure:"baseline_reload_interval"`

	// PartialTraceThreshold is the minimum fraction of the baseline's expected
	// span count that must be present before a trace is fingerprinted. Traces
	// below this fraction are silently skipped — they are likely incomplete
	// because spans arrived at a different collector node.
	// Range: 0.0–1.0. Default: 0.7. Set to 0.0 to disable.
	PartialTraceThreshold float64 `mapstructure:"partial_trace_threshold"`

	// PromotionThreshold is how many times a new fingerprint or error signature
	// must be detected (across all traces, since processor start) before it is
	// automatically promoted into the baseline. Once promoted the processor stops
	// alerting on that hash and writes the updated baseline back to disk so other
	// collector pods pick it up on their next reload cycle.
	// Default: 10. Set to 0 to disable auto-promotion.
	PromotionThreshold int `mapstructure:"promotion_threshold"`

	// PromotionWriteback controls whether the promoted baseline is written back
	// to BaselinePath / ErrorBaselinePath on disk. Requires the paths to be
	// writable by the collector process (e.g. an emptyDir volume, not a read-only
	// ConfigMap mount). Default: true.
	PromotionWriteback bool `mapstructure:"promotion_writeback"`

	// WarmupDuration is how long after startup the processor suppresses drift
	// events. During warm-up, new root ops are logged and auto-promoted but no
	// events are emitted to Splunk. Prevents false positives while spans from
	// a fresh deploy finish arriving. Default: 2m. Set to 0 to disable.
	WarmupDuration time.Duration `mapstructure:"warmup_duration"`

	// SpanCountPercentileGuard enables a smarter partial-trace filter: instead
	// of a fixed PartialTraceThreshold ratio, uses the 10th percentile of
	// observed span counts for each root op stored in the baseline.
	// Default: true.
	SpanCountPercentileGuard bool `mapstructure:"span_count_percentile_guard"`

	// ErrorRateWindow is the rolling window for tracking known error-signature
	// fire rates. Used to detect sudden spikes in recurring error patterns.
	// Default: 5m. Set to 0 to disable error rate tracking.
	ErrorRateWindow time.Duration `mapstructure:"error_rate_window"`

	// ErrorRateSpikeMultiplier: a known error signature firing this many times
	// above its baseline rate within ErrorRateWindow triggers an
	// error.signature.spike event. Default: 5.0.
	ErrorRateSpikeMultiplier float64 `mapstructure:"error_rate_spike_multiplier"`

	// MissingServiceCheckInterval controls how often the processor checks for
	// baseline root_ops that have gone completely silent. When a root_op with
	// established baseline fingerprints has not been seen for longer than this
	// interval, a trace.path.drift event with anomaly_type=MISSING_SERVICE is
	// emitted. Default: 30s. Set to 0 to disable.
	MissingServiceCheckInterval time.Duration `mapstructure:"missing_service_check_interval"`

	// ── Metric anomaly detection ───────────────────────────────────────────

	// LatencyAnomalyWindow is the rolling window over which current mean latency
	// is computed and compared against the learned baseline. Default: 2m.
	// Set to 0 to disable latency anomaly detection.
	LatencyAnomalyWindow time.Duration `mapstructure:"latency_anomaly_window"`

	// LatencyLearnMinSamples is how many trace samples must be collected before
	// latency anomaly detection activates. During this period the processor
	// builds a baseline mean/stddev using Welford's online algorithm.
	// Default: 30.
	LatencyLearnMinSamples int `mapstructure:"latency_learn_min_samples"`

	// LatencyAnomalyZScore is the number of standard deviations above the
	// baseline mean that triggers a service.latency.anomaly event. Higher = fewer
	// false positives. Default: 3.0 (3-sigma rule).
	LatencyAnomalyZScore float64 `mapstructure:"latency_anomaly_z_score"`

	// ErrorRateAnomalyWindow is the rolling window for error rate calculation.
	// Default: 2m. Set to 0 to disable error rate anomaly detection.
	ErrorRateAnomalyWindow time.Duration `mapstructure:"error_rate_anomaly_window"`

	// ErrorRateAnomalyThreshold is the fraction of spans that must be errors
	// to trigger a service.error.rate.anomaly event. Default: 0.05 (5%).
	ErrorRateAnomalyThreshold float64 `mapstructure:"error_rate_anomaly_threshold"`

	// MinErrorRateSamples is the minimum number of trace observations required
	// before error rate anomaly detection activates. Default: 10.
	MinErrorRateSamples int `mapstructure:"min_error_rate_samples"`

	// ── Throughput drop detection ──────────────────────────────────────────

	// ThroughputDropWindow is the rolling window for measuring current request
	// rate per root_op. Default: 2m. Set to 0 to disable.
	ThroughputDropWindow time.Duration `mapstructure:"throughput_drop_window"`

	// ThroughputDropThreshold is the fractional drop (0–1) in request rate
	// relative to the rolling baseline that triggers a throughput.drop event.
	// e.g. 0.5 = 50% drop. Default: 0.5.
	ThroughputDropThreshold float64 `mapstructure:"throughput_drop_threshold"`

	// ThroughputLearnMinSamples is how many trace observations to collect
	// before activating throughput drop detection. Default: 20.
	ThroughputLearnMinSamples int `mapstructure:"throughput_learn_min_samples"`

	// ── Topology drift detection ───────────────────────────────────────────

	// TopologyDriftEnabled controls whether new topology edges (service calls
	// not seen during baseline) are emitted as topology.edge.drift events.
	// Default: true.
	TopologyDriftEnabled bool `mapstructure:"topology_drift_enabled"`

	// ── Baseline staleness detection ──────────────────────────────────────

	// BaselineStalenessThreshold is how long a baseline file can go without
	// changing (while the processor has promoted entries) before a
	// baseline.stale warning event is emitted. Default: 24h. Set to 0 to disable.
	BaselineStalenessThreshold time.Duration `mapstructure:"baseline_staleness_threshold"`

	// ── Bootstrap learning mode ────────────────────────────────────────────

	// BootstrapDuration is how long the processor will run in "learning mode"
	// when it starts with an empty baseline. During this period all fingerprints
	// are collected and at the end a bootstrap baseline is written to disk.
	// Default: 5m. Set to 0 to disable auto-bootstrap.
	BootstrapDuration time.Duration `mapstructure:"bootstrap_duration"`

	// ── Database query fingerprinting ─────────────────────────────────────

	// DbQueryLatencyWindow is the rolling window for DB query latency tracking.
	// When a normalised query template's mean latency deviates by more than
	// DbQueryLatencyZScore stddevs above its baseline, a db.query.slow event
	// is emitted.  Set to 0 to disable DB query tracking entirely.  Default: 5m.
	DbQueryLatencyWindow time.Duration `mapstructure:"db_query_latency_window"`

	// DbQueryLearnMinSamples is the number of observations required before
	// slow-query detection activates for a given template.  Default: 10.
	DbQueryLearnMinSamples int `mapstructure:"db_query_learn_min_samples"`

	// DbQueryLatencyZScore is the z-score threshold for slow query detection.
	// Default: 3.0.
	DbQueryLatencyZScore float64 `mapstructure:"db_query_latency_z_score"`

	// DbQuerySlowCooldown is the minimum time between repeated db.query.slow
	// events for the same query template. Without this, a template whose
	// latency stays above baseline re-fires on every trace flush that
	// contains it, flooding the event stream for the duration of the
	// slowdown. Set to 0 to disable (fire on every detection). Default: 5m.
	DbQuerySlowCooldown time.Duration `mapstructure:"db_query_slow_cooldown"`

	// ErrorSignatureDriftCooldown is the minimum time between repeated
	// error.signature.drift events for the same error signature hash.
	// Without this, a new signature that hasn't yet reached
	// PromotionThreshold re-fires on every trace flush that contains it
	// (tryClaimEvent only dedups across pods, not within the same pod),
	// flooding the event stream until the signature is promoted into the
	// baseline. Set to 0 to disable (fire on every detection). Default: 5m.
	ErrorSignatureDriftCooldown time.Duration `mapstructure:"error_signature_drift_cooldown"`

	// ── Multi-pod deduplication ────────────────────────────────────────────

	// DeduplicateEvents controls whether the processor uses a claim-file on the
	// shared /baseline volume to deduplicate events across DaemonSet pods.
	// Only one pod will emit an event for a given (event_type, hash) within
	// DeduplicateTTL. Default: true.
	DeduplicateEvents bool `mapstructure:"deduplicate_events"`

	// DeduplicateTTL is how long a claim is held before another pod may emit
	// the same event. Should be longer than the promotion threshold window.
	// Default: 2m.
	DeduplicateTTL time.Duration `mapstructure:"deduplicate_ttl"`

	// ── Root-cause / causality-chain correlation ───────────────────────────

	// CausalityChainEnabled controls whether the processor correlates active
	// anomalies across the service topology to identify a likely root cause
	// and emits service.causality.chain events. Default: true.
	CausalityChainEnabled bool `mapstructure:"causality_chain_enabled"`

	// CausalityAnomalyTTL is how long an anomaly stays "active" for root-cause
	// correlation purposes before it is expired and no longer considered when
	// computing the causality chain. Default: 5m.
	CausalityAnomalyTTL time.Duration `mapstructure:"causality_anomaly_ttl"`

	// ── Metrics HTTP server ────────────────────────────────────────────────

	// MetricsAddr is the TCP address the in-process metrics HTTP server listens
	// on (e.g. ":9090"). When set, GET /metrics returns a JSON snapshot of all
	// per-(service,operation) latency and error-rate windows so the topology
	// server can drive live charts without log scraping or Splunk queries.
	// Set to "" to disable. Default: ":9090".
	MetricsAddr string `mapstructure:"metrics_addr"`
}

func createDefaultConfig() component.Config {
	return &Config{
		TraceBufferTimeout:          10 * time.Second,
		MinSpans:                    2,
		MinBaselineOccurrences:      2,
		BaselineReloadInterval:      60 * time.Second,
		SplunkIngestURL:             "https://ingest.us1.signalfx.com",
		PartialTraceThreshold:       0.7,
		PromotionThreshold:          10,
		PromotionWriteback:          true,
		WarmupDuration:              2 * time.Minute,
		SpanCountPercentileGuard:    true,
		ErrorRateWindow:             5 * time.Minute,
		ErrorRateSpikeMultiplier:    5.0,
		MissingServiceCheckInterval: 30 * time.Second,
		LatencyAnomalyWindow:        2 * time.Minute,
		LatencyLearnMinSamples:      30,
		LatencyAnomalyZScore:        3.0,
		ErrorRateAnomalyWindow:      2 * time.Minute,
		ErrorRateAnomalyThreshold:   0.05,
		MinErrorRateSamples:         10,
		ThroughputDropWindow:        2 * time.Minute,
		ThroughputDropThreshold:     0.5,
		ThroughputLearnMinSamples:   20,
		TopologyDriftEnabled:        true,
		BaselineStalenessThreshold:  24 * time.Hour,
		BootstrapDuration:           5 * time.Minute,
		DeduplicateEvents:           true,
		DeduplicateTTL:              2 * time.Minute,
		DbQueryLatencyWindow:        5 * time.Minute,
		DbQueryLearnMinSamples:      10,
		DbQueryLatencyZScore:        3.0,
		DbQuerySlowCooldown:         5 * time.Minute,
		ErrorSignatureDriftCooldown: 5 * time.Minute,
		CausalityChainEnabled:       true,
		CausalityAnomalyTTL:         5 * time.Minute,
		MetricsAddr:                 ":9090",
	}
}
