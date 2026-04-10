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
}

func createDefaultConfig() component.Config {
	return &Config{
		TraceBufferTimeout:     10 * time.Second,
		MinSpans:               2,
		MinBaselineOccurrences: 2,
		BaselineReloadInterval: 60 * time.Second,
		SplunkIngestURL:        "https://ingest.us1.signalfx.com",
		PartialTraceThreshold:  0.7,
	}
}
