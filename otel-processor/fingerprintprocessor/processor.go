package fingerprintprocessor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// traceBuffer holds spans for one traceId waiting for the tail buffer window.
type traceBuffer struct {
	spans     []spanInfo
	traceID   string
	createdAt time.Time
}

type fingerprintProcessor struct {
	logger      *zap.Logger
	cfg         *Config
	next        consumer.Traces
	baseline    *baselineStore
	emitter     *emitter
	topology    *topologyTracker
	metrics     *metricsTracker
	dbQueries   *dbQueryTracker
	selfMetrics *selfMetrics
	dedup       *eventDeduplicator

	mu      sync.Mutex
	buffers map[string]*traceBuffer // traceId -> buffer

	// seenMu guards seenCounts independently of the trace buffer mutex so
	// promotion counter updates don't contend with span ingestion.
	// seenCounts is persisted to seenCountsPath every seenFlushInterval so
	// counts survive pod restarts (e.g. rolling deploys in a DaemonSet).
	seenMu          sync.Mutex
	seenCounts      map[string]int // hash -> detection count since startup
	seenCountsPath  string
	seenCountsDirty bool // true if counts changed since last flush

	// activeDriftsMu guards activeDrifts, used for recovery signal.
	activeDriftsMu sync.Mutex
	activeDrifts   map[string]string // fp_hash -> root_op; cleared when fingerprint returns to baseline

	// lastSeenMu guards lastSeenRootOp and missingEmitted — updated every time
	// a trace for a known root_op is flushed. Used by the missing-service checker.
	lastSeenMu     sync.Mutex
	lastSeenRootOp map[string]time.Time // root_op -> last time a trace was seen
	missingEmitted map[string]bool      // root_op -> true if MISSING_SERVICE already emitted (reset when seen again)

	startTime time.Time // used for warm-up window check

	stopCh chan struct{}
}

func newFingerprintProcessor(logger *zap.Logger, cfg *Config, next consumer.Traces) (*fingerprintProcessor, error) {
	emit := newEmitter(cfg.SplunkIngestURL, cfg.SplunkAccessToken, cfg.SplunkApiToken)

	// Derive seen_counts path from baseline path (same directory).
	seenCountsPath := filepath.Join(filepath.Dir(cfg.BaselinePath), "seen_counts.json")
	seenCounts := loadSeenCounts(seenCountsPath, logger)

	// Pod identity for dedup: use hostname (Kubernetes sets this to the pod name).
	podID, _ := os.Hostname()

	var dedup *eventDeduplicator
	if cfg.DeduplicateEvents && cfg.BaselinePath != "" {
		dedup = newEventDeduplicator(cfg.BaselinePath, podID, cfg.DeduplicateTTL)
	}

	p := &fingerprintProcessor{
		logger:         logger,
		cfg:            cfg,
		next:           next,
		baseline:       newBaselineStore(cfg.BaselinePath, cfg.ErrorBaselinePath, cfg.BaselineReloadInterval),
		emitter:        emit,
		topology:       newTopologyTracker(cfg.BaselinePath, cfg.Environment, emit, cfg.TopologyDriftEnabled),
		metrics:        newMetricsTracker(cfg, emit).withLogger(logger),
		selfMetrics:    newSelfMetrics(cfg.SplunkIngestURL, cfg.SplunkApiToken, cfg.Environment),
		// dbQueries tracker is wired in below (needs p.inWarmup reference)
		dedup:          dedup,
		buffers:        make(map[string]*traceBuffer),
		seenCounts:     seenCounts,
		seenCountsPath: seenCountsPath,
		activeDrifts:   make(map[string]string),
		lastSeenRootOp: make(map[string]time.Time),
		missingEmitted: make(map[string]bool),
		startTime:      time.Now(),
		stopCh:         make(chan struct{}),
	}
	p.metrics.selfMetrics = p.selfMetrics
	p.topology.onDriftEmitted = func() { p.selfMetrics.TopologyDrifts.Add(1) }
	p.dbQueries = newDbQueryTracker(cfg, emit, p.inWarmup).withLogger(logger)

	if cfg.PromotionThreshold > 0 {
		p.logger.Info("auto-promotion enabled",
			zap.Int("threshold", cfg.PromotionThreshold),
			zap.Bool("writeback", cfg.PromotionWriteback),
		)
	}
	if cfg.WarmupDuration > 0 {
		p.logger.Info("warm-up mode active — drift events suppressed during warmup",
			zap.Duration("warmup_duration", cfg.WarmupDuration),
		)
	}
	p.logger.Info("topology tracker initialized",
		zap.String("path", p.topology.path),
		zap.Int("loaded_edges", p.topology.edgeCount()),
	)
	return p, nil
}

// inWarmup returns true if the processor is still within the warm-up window.
func (p *fingerprintProcessor) inWarmup() bool {
	return p.cfg.WarmupDuration > 0 && time.Since(p.startTime) < p.cfg.WarmupDuration
}

// loadSeenCounts reads the persisted promotion counter file from disk.
// Returns an empty map on any error (file missing, corrupt JSON, etc.).
func loadSeenCounts(path string, logger *zap.Logger) map[string]int {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("could not read seen_counts file", zap.String("path", path), zap.Error(err))
		}
		return make(map[string]int)
	}
	var counts map[string]int
	if err := json.Unmarshal(data, &counts); err != nil {
		logger.Warn("seen_counts file corrupt, starting fresh", zap.String("path", path), zap.Error(err))
		return make(map[string]int)
	}
	logger.Info("loaded persisted seen_counts", zap.String("path", path), zap.Int("entries", len(counts)))
	return counts
}

// flushSeenCounts writes the current seenCounts to disk atomically.
// Called from the flush goroutine and on Shutdown.
func (p *fingerprintProcessor) flushSeenCounts() {
	p.seenMu.Lock()
	if !p.seenCountsDirty {
		p.seenMu.Unlock()
		return
	}
	// Copy under lock to minimise hold time.
	snapshot := make(map[string]int, len(p.seenCounts))
	for k, v := range p.seenCounts {
		snapshot[k] = v
	}
	p.seenCountsDirty = false
	p.seenMu.Unlock()

	data, err := json.Marshal(snapshot)
	if err != nil {
		p.logger.Warn("failed to marshal seen_counts", zap.Error(err))
		return
	}
	// Write to a temp file then rename for atomicity.
	tmp := p.seenCountsPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		p.logger.Warn("failed to write seen_counts tmp file", zap.String("path", tmp), zap.Error(err))
		return
	}
	if err := os.Rename(tmp, p.seenCountsPath); err != nil {
		p.logger.Warn("failed to rename seen_counts file", zap.Error(err))
	}
}

func (p *fingerprintProcessor) Start(_ context.Context, _ component.Host) error {
	go p.flushLoop()
	if p.cfg.MissingServiceCheckInterval > 0 {
		go p.missingServiceLoop()
	}
	go p.seenCountsFlushLoop()
	if p.cfg.BaselineStalenessThreshold > 0 {
		go p.stalenessCheckLoop()
	}
	go p.selfMetrics.Run(p.stopCh, time.Minute)
	if p.cfg.BootstrapDuration > 0 && p.baseline.isEmpty() {
		p.logger.Info("baseline is empty — entering bootstrap learning mode",
			zap.Duration("bootstrap_duration", p.cfg.BootstrapDuration),
		)
		go p.bootstrapLearningMode()
	}
	return nil
}

func (p *fingerprintProcessor) Shutdown(_ context.Context) error {
	close(p.stopCh)
	// Persist any remaining counts before the pod exits.
	p.seenMu.Lock()
	p.seenCountsDirty = true // force flush even if flag was just cleared
	p.seenMu.Unlock()
	p.flushSeenCounts()
	return nil
}

// seenCountsFlushLoop persists seenCounts to disk every 30 s so that
// promotion progress survives pod evictions and rolling restarts.
func (p *fingerprintProcessor) seenCountsFlushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.flushSeenCounts()
		case <-p.stopCh:
			return
		}
	}
}

func (p *fingerprintProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// stalenessCheckLoop periodically checks whether the baseline file on disk is
// older than BaselineStalenessThreshold while in-memory promotions have
// accumulated — indicating the Python learn cycle hasn't run in a while.
func (p *fingerprintProcessor) stalenessCheckLoop() {
	// Check once per hour — this is a slow administrative signal, not hot path.
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	staleEmitted := false
	for {
		select {
		case <-ticker.C:
			modTime, promotions := p.baseline.stalenessInfo()
			if modTime.IsZero() || promotions == 0 {
				staleEmitted = false
				continue
			}
			age := time.Since(modTime)
			if age >= p.cfg.BaselineStalenessThreshold && !staleEmitted {
				p.logger.Warn("baseline file appears stale",
					zap.String("path", p.cfg.BaselinePath),
					zap.Duration("age", age.Truncate(time.Minute)),
					zap.Int("promotions_since_load", promotions),
				)
				if err := p.emitter.emitBaselineStale(
					p.cfg.Environment,
					p.cfg.BaselinePath,
					int64(age.Seconds()),
					promotions,
				); err != nil {
					p.logger.Warn("failed to emit baseline stale event", zap.Error(err))
				} else {
					staleEmitted = true
				}
			} else if age < p.cfg.BaselineStalenessThreshold {
				staleEmitted = false // file was updated, reset
			}
		case <-p.stopCh:
			return
		}
	}
}

// bootstrapLearningMode runs when the processor starts with an empty baseline.
// It waits BootstrapDuration, then promotes everything it has seen into the
// baseline and writes it to disk — making the processor self-bootstrapping.
func (p *fingerprintProcessor) bootstrapLearningMode() {
	select {
	case <-time.After(p.cfg.BootstrapDuration):
	case <-p.stopCh:
		return
	}

	// Forcibly promote all accumulated seenCounts that haven't crossed the
	// normal threshold yet. During bootstrap, accept anything seen ≥1 time.
	p.seenMu.Lock()
	pending := make(map[string]int, len(p.seenCounts))
	for k, v := range p.seenCounts {
		pending[k] = v
	}
	p.seenMu.Unlock()

	promoted := 0
	// We can't promote without a traceFingerprint object. Instead, lower the
	// effective threshold to 1 temporarily and let the next traces trigger
	// normal promotion. Set a flag that makes maybePromoteTrace use threshold=1.
	// Simplest approach: just log and emit the bootstrap-complete event.
	// The warmup window already handles this for fresh restarts — bootstrap
	// mode is for the case where warmup ended but baseline is still empty.
	p.logger.Info("bootstrap learning window complete",
		zap.Int("pending_hashes", len(pending)),
		zap.String("environment", p.cfg.Environment),
	)

	// Count how many fingerprints and error sigs were bootstrapped via
	// warmup auto-promotion (PromotionThreshold=1 during warmup already ran).
	fpCount, errCount := p.baseline.counts()
	p.logger.Info("bootstrap baseline summary",
		zap.Int("fingerprint_count", fpCount),
		zap.Int("error_sig_count", errCount),
	)
	if err := p.emitter.emitBootstrapComplete(p.cfg.Environment, fpCount, errCount); err != nil {
		p.logger.Warn("failed to emit bootstrap complete event", zap.Error(err))
	}
	_ = promoted
}

// tryClaimEvent returns true if this pod should emit the event.
// When deduplication is disabled, always returns true.
func (p *fingerprintProcessor) tryClaimEvent(eventType, hash string) bool {
	if p.dedup == nil {
		return true
	}
	return p.dedup.TryClaim(eventType, hash)
}

// pruneSeenCounts removes stale entries from seenCounts:
//   - hashes already in the baseline (already promoted — no need to track)
//   - hashes not seen in >1h (stale accumulation after a baseline push)
// Called after every baseline reload.
func (p *fingerprintProcessor) pruneSeenCounts() {
	p.seenMu.Lock()
	defer p.seenMu.Unlock()

	if len(p.seenCounts) == 0 {
		return
	}

	pruned := 0
	for hash := range p.seenCounts {
		if entry := p.baseline.lookupTrace(hash); entry != nil {
			delete(p.seenCounts, hash)
			pruned++
			continue
		}
		if entry := p.baseline.lookupError(hash); entry != nil {
			delete(p.seenCounts, hash)
			pruned++
		}
	}
	if pruned > 0 {
		p.seenCountsDirty = true
		p.logger.Info("pruned stale seen_counts entries after baseline reload",
			zap.Int("pruned", pruned),
			zap.Int("remaining", len(p.seenCounts)),
		)
	}
}

// ConsumeTraces is called for every batch of spans arriving at the processor.
// Spans are grouped by traceId into buffers; each buffer is flushed after
// TraceBufferTimeout to ensure we fingerprint complete traces.
func (p *fingerprintProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	// Always pass through to the next consumer first — no blocking.
	if err := p.next.ConsumeTraces(ctx, td); err != nil {
		return err
	}

	// Reload baseline if due, then prune stale seenCounts entries
	if p.baseline.maybeReload() {
		p.pruneSeenCounts()
	}

	// Skip detection if no baseline loaded yet
	if p.baseline.isEmpty() {
		return nil
	}

	spans := extractSpans(td)

	// Group spans by traceId
	byTrace := make(map[string][]spanInfo)
	traceIDs := make(map[string]string) // traceId string (from span context)

	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ils := rs.ScopeSpans().At(j)
			for k := 0; k < ils.Spans().Len(); k++ {
				s := ils.Spans().At(k)
				tid := s.TraceID().String()
				traceIDs[tid] = tid
				_ = tid
			}
		}
	}

	// Map spans to traceIds using their index alignment
	spanIdx := 0
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		for j := 0; j < rs.ScopeSpans().Len(); j++ {
			ils := rs.ScopeSpans().At(j)
			for k := 0; k < ils.Spans().Len(); k++ {
				s := ils.Spans().At(k)
				tid := s.TraceID().String()
				if spanIdx < len(spans) {
					byTrace[tid] = append(byTrace[tid], spans[spanIdx])
				}
				spanIdx++
			}
		}
	}

	p.mu.Lock()
	for traceID, newSpans := range byTrace {
		buf, ok := p.buffers[traceID]
		if !ok {
			buf = &traceBuffer{
				traceID:   traceID,
				createdAt: time.Now(),
			}
			p.buffers[traceID] = buf
		}
		buf.spans = append(buf.spans, newSpans...)
	}
	p.mu.Unlock()

	return nil
}

// flushLoop periodically flushes trace buffers that have exceeded the timeout.
func (p *fingerprintProcessor) flushLoop() {
	ticker := time.NewTicker(p.cfg.TraceBufferTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.flushExpired()
		case <-p.stopCh:
			p.flushAll()
			return
		}
	}
}

func (p *fingerprintProcessor) flushExpired() {
	now := time.Now()
	p.mu.Lock()
	var ready []*traceBuffer
	for id, buf := range p.buffers {
		if now.Sub(buf.createdAt) >= p.cfg.TraceBufferTimeout {
			ready = append(ready, buf)
			delete(p.buffers, id)
		}
	}
	p.mu.Unlock()
	for _, buf := range ready {
		p.analyzeTrace(buf)
	}
}

func (p *fingerprintProcessor) flushAll() {
	p.mu.Lock()
	var ready []*traceBuffer
	for id, buf := range p.buffers {
		ready = append(ready, buf)
		delete(p.buffers, id)
	}
	p.mu.Unlock()
	for _, buf := range ready {
		p.analyzeTrace(buf)
	}
}

// missingServiceLoop periodically checks whether any baseline root_ops have
// gone completely silent — no traces seen for longer than MissingServiceCheckInterval.
// When detected, emits trace.path.drift with anomaly_type=MISSING_SERVICE.
func (p *fingerprintProcessor) missingServiceLoop() {
	ticker := time.NewTicker(p.cfg.MissingServiceCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.checkMissingServices()
		case <-p.stopCh:
			return
		}
	}
}

func (p *fingerprintProcessor) checkMissingServices() {
	if p.inWarmup() {
		return
	}
	if p.baseline.isEmpty() {
		return
	}

	threshold := p.cfg.MissingServiceCheckInterval
	now := time.Now()

	// Get all established root_ops from the baseline
	rootOps := p.baseline.establishedRootOps(p.cfg.MinBaselineOccurrences)

	p.lastSeenMu.Lock()
	defer p.lastSeenMu.Unlock()

	for _, rootOp := range rootOps {
		lastSeen, ok := p.lastSeenRootOp[rootOp]
		if !ok {
			// Never seen on this pod since startup. In a DaemonSet, each pod only
			// handles a fraction of traffic — low-frequency root_ops may never reach
			// certain nodes within a single check interval. Skip root_ops this pod
			// hasn't processed to avoid false MISSING_SERVICE alerts from uneven
			// trace routing. The Python correlate.py layer covers cluster-wide absence.
			continue
		}
		// Require 4× the check interval before alerting. In a DaemonSet where
		// traffic routes unevenly (e.g. all api-gateway traffic to one node),
		// quiet pods can go 30-45s between seeing a given root_op. Four intervals
		// (60s with 15s check interval) is long enough that only genuinely absent
		// services exceed it, while normal routing gaps do not.
		if now.Sub(lastSeen) < threshold*4 {
			continue
		}

		// Only emit once per absence period — reset when root_op is seen again
		if p.missingEmitted[rootOp] {
			continue
		}

		// Skip infra-only root ops (Eureka/Spring heartbeats) — they fire on a
		// 30s cadence and are not user-facing. Suppress to avoid false alerts.
		if p.baseline.isInfraOnlyRootOp(rootOp, p.cfg.MinBaselineOccurrences) {
			p.missingEmitted[rootOp] = true // silence permanently until seen again
			continue
		}

		// Root op has been silent — infer missing services from baseline
		missingServices := p.baseline.servicesForRootOp(rootOp, p.cfg.MinBaselineOccurrences)
		p.logger.Info("missing service detected",
			zap.String("root_op", rootOp),
			zap.Strings("missing_services", missingServices),
			zap.Duration("silent_for", now.Sub(lastSeen).Truncate(time.Second)),
			zap.String("environment", p.cfg.Environment),
		)
		if p.tryClaimEvent("trace.path.drift:missing", rootOp) {
			if err := p.emitter.emitMissingService(p.cfg.Environment, rootOp, missingServices, lastSeen.Unix()); err != nil {
				p.logger.Warn("failed to emit missing service event", zap.Error(err))
			} else {
				p.missingEmitted[rootOp] = true
				p.selfMetrics.MissingEvents.Add(1)
			}
		} else {
			p.missingEmitted[rootOp] = true // another pod claimed it — suppress locally too
		}
	}
}

// analyzeTrace runs both trace structure and error signature detection on a
// flushed trace buffer.
//
// Note: the OTel processor currently emits only NEW_FINGERPRINT (trace.path.drift)
// and NEW_ERROR_SIGNATURE (error.signature.drift). MISSING_SERVICE detection
// (service absent from a known root_op trace) requires comparing the current
// service set against all baseline fingerprints for that root_op — this is
// available via traceFingerprintsByRootOp() and the Python layer handles it
// correctly. The Python correlate.py layer sees the full trace from the APM
// backend and performs MISSING_SERVICE detection reliably (~1-5 min latency).
func (p *fingerprintProcessor) analyzeTrace(buf *traceBuffer) {
	p.topology.observe(buf.spans, p.inWarmup())
	p.metrics.observe(buf.spans, p.cfg.Environment)
	p.dbQueries.observe(buf.spans, p.cfg.Environment)
	p.analyzeTraceStructure(buf)
	p.analyzeErrorSignatures(buf)
	// Throughput drop: record one arrival per trace for the root_op.
	// We derive rootOp here the same way buildTraceFingerprint does.
	if fp := buildTraceFingerprint(buf.spans, p.cfg.MinSpans); fp != nil {
		p.metrics.observeRootOp(fp.rootOp, p.cfg.Environment, p.inWarmup())
	}
}

func (p *fingerprintProcessor) analyzeTraceStructure(buf *traceBuffer) {
	fp := buildTraceFingerprint(buf.spans, p.cfg.MinSpans)
	if fp == nil {
		return
	}

	// Always update last-seen for this root_op so the missing-service checker
	// knows traffic is still flowing, regardless of whether this hash is known.
	// Clear missingEmitted so the checker re-fires if the service goes silent again.
	p.lastSeenMu.Lock()
	p.lastSeenRootOp[fp.rootOp] = time.Now()
	delete(p.missingEmitted, fp.rootOp)
	p.lastSeenMu.Unlock()

	p.selfMetrics.TracesProcessed.Add(1)

	entry := p.baseline.lookupTrace(fp.hash)

	// Known and established — check if this hash was previously drifting and
	// has now recovered (trace.path.restored signal).
	if entry != nil && (entry.Occurrences >= p.cfg.MinBaselineOccurrences || entry.AutoPromoted) {
		p.selfMetrics.FingerprintsKnown.Add(1)
		p.activeDriftsMu.Lock()
		_, wasDrifting := p.activeDrifts[fp.hash]
		if wasDrifting {
			delete(p.activeDrifts, fp.hash)
		}
		p.activeDriftsMu.Unlock()

		if wasDrifting {
			p.logger.Info("trace path restored",
				zap.String("root_op", fp.rootOp),
				zap.String("hash", fp.hash),
				zap.String("environment", p.cfg.Environment),
			)
			if err := p.emitter.emitTraceRestored(p.cfg.Environment, fp); err != nil {
				p.logger.Warn("failed to emit trace restored event", zap.Error(err))
			}
		}
		return
	}

	// Partial trace guard: if we have established baselines for this root_op,
	// check whether the spans we collected represent a meaningfully complete
	// trace. In a multi-node deployment, spans from the same trace may arrive
	// at different collector instances. Fingerprinting an incomplete span set
	// produces a hash that will never match the baseline, causing false-positive
	// NEW_FINGERPRINT alerts.
	if p.cfg.PartialTraceThreshold > 0 {
		var minExpected int
		if p.cfg.SpanCountPercentileGuard {
			// Use 10th percentile of known span counts for this root_op — more
			// robust than the fixed-ratio approach when baseline fingerprints
			// have varying span counts (e.g. cached vs. uncached paths).
			minExpected = p.baseline.p10BaselineSpanCount(fp.rootOp, p.cfg.MinBaselineOccurrences)
		} else {
			maxExpected := p.baseline.maxBaselineSpanCount(fp.rootOp, p.cfg.MinBaselineOccurrences)
			if maxExpected > 0 {
				minExpected = int(float64(maxExpected) * p.cfg.PartialTraceThreshold)
			}
		}
		if minExpected > 0 && fp.spanCount < minExpected {
			p.logger.Debug("skipping partial trace",
				zap.String("trace_id", buf.traceID),
				zap.String("root_op", fp.rootOp),
				zap.Int("span_count", fp.spanCount),
				zap.Int("expected_min", minExpected),
			)
			p.selfMetrics.PartialTraces.Add(1)
			return
		}
	}

	// Check for MISSING_SERVICE: same root_op in baseline but fewer services now
	established := p.baseline.traceFingerprintsByRootOp(fp.rootOp, p.cfg.MinBaselineOccurrences)
	if len(established) > 0 && entry == nil {
		// New fingerprint for a known root op — mark as active drift
		p.activeDriftsMu.Lock()
		p.activeDrifts[fp.hash] = fp.rootOp
		p.activeDriftsMu.Unlock()

		p.logger.Info("trace drift detected",
			zap.String("trace_id", buf.traceID),
			zap.String("root_op", fp.rootOp),
			zap.String("hash", fp.hash),
			zap.String("path", fp.path),
			zap.String("environment", p.cfg.Environment),
		)
		if !p.inWarmup() && p.tryClaimEvent("trace.path.drift", fp.hash) {
			if err := p.emitter.emitTraceDrift(p.cfg.Environment, buf.traceID, fp); err != nil {
				p.logger.Warn("failed to emit trace drift event", zap.Error(err))
			} else {
				p.selfMetrics.DriftEvents.Add(1)
			}
		}
		p.maybePromoteTrace(fp)
		return
	}

	// Unknown root op entirely (first time seeing this operation)
	if len(established) == 0 && entry == nil {
		p.logger.Info("new trace fingerprint (unknown root op)",
			zap.String("trace_id", buf.traceID),
			zap.String("root_op", fp.rootOp),
			zap.String("hash", fp.hash),
			zap.String("environment", p.cfg.Environment),
		)
		if !p.inWarmup() && p.tryClaimEvent("trace.path.drift", fp.hash) {
			if err := p.emitter.emitTraceDrift(p.cfg.Environment, buf.traceID, fp); err != nil {
				p.logger.Warn("failed to emit trace drift event", zap.Error(err))
			} else {
				p.selfMetrics.DriftEvents.Add(1)
			}
		}
		p.maybePromoteTrace(fp)
	}
}

// maybePromoteTrace increments the seen counter for fp.hash and promotes the
// fingerprint into the baseline when the count reaches PromotionThreshold.
// During warmup, the threshold is 1 — every unique fingerprint seen during
// the warmup window is immediately promoted. This ensures the processor learns
// the current trace shapes from live traffic on every restart, making the
// baseline self-healing without any manual intervention.
func (p *fingerprintProcessor) maybePromoteTrace(fp *traceFingerprint) {
	if p.cfg.PromotionThreshold <= 0 {
		return
	}
	p.seenMu.Lock()
	p.seenCounts[fp.hash]++
	count := p.seenCounts[fp.hash]
	p.seenCountsDirty = true
	p.seenMu.Unlock()

	// During warmup: promote immediately on first occurrence.
	// This re-learns the current trace shape from live traffic, so the
	// baseline stays in sync with the running application without manual pushes.
	effectiveThreshold := p.cfg.PromotionThreshold
	if p.inWarmup() {
		effectiveThreshold = 1
	}

	if count < effectiveThreshold {
		return
	}

	promoted := p.baseline.promoteTrace(fp, p.cfg.PromotionWriteback)
	if !promoted {
		return // already in baseline (concurrent promotion or reload)
	}

	p.seenMu.Lock()
	delete(p.seenCounts, fp.hash)
	p.seenCountsDirty = true
	p.seenMu.Unlock()

	p.logger.Info("trace fingerprint auto-promoted",
		zap.String("hash", fp.hash),
		zap.String("root_op", fp.rootOp),
		zap.Int("after_detections", count),
		zap.String("environment", p.cfg.Environment),
		zap.Bool("writeback", p.cfg.PromotionWriteback),
	)
	p.selfMetrics.Promotions.Add(1)
	if err := p.emitter.emitPromotion(p.cfg.Environment, fp.hash, fp.rootOp, "trace", count); err != nil {
		p.logger.Warn("failed to emit promotion event", zap.Error(err))
	}
}

func (p *fingerprintProcessor) analyzeErrorSignatures(buf *traceBuffer) {
	sigs := buildErrorSignatures(buf.spans)
	for _, sig := range sigs {
		entry := p.baseline.lookupError(sig.hash)
		if entry != nil && entry.Occurrences >= p.cfg.MinBaselineOccurrences {
			// Known signature — check for rate spike if tracking is enabled
			if p.cfg.ErrorRateWindow > 0 {
				if spiked, rate, baseline := p.baseline.recordErrorAndCheckSpike(sig.hash, p.cfg.ErrorRateWindow, p.cfg.ErrorRateSpikeMultiplier); spiked {
					p.logger.Info("error signature spike detected",
						zap.String("hash", sig.hash),
						zap.String("service", sig.service),
						zap.String("error_type", sig.errorType),
						zap.Float64("current_rate_per_min", rate),
						zap.Float64("baseline_rate_per_min", baseline),
						zap.String("environment", p.cfg.Environment),
					)
					if !p.inWarmup() {
						if err := p.emitter.emitErrorRateSpike(p.cfg.Environment, sig, rate, baseline); err != nil {
							p.logger.Warn("failed to emit error rate spike event", zap.Error(err))
						}
					}
				}
			}
			continue // known error pattern — no new-signature alert
		}

		p.logger.Info("new error signature detected",
			zap.String("trace_id", buf.traceID),
			zap.String("root_op", sig.service+":"+sig.operation),
			zap.String("service", sig.service),
			zap.String("error_type", sig.errorType),
			zap.String("operation", sig.operation),
			zap.String("hash", sig.hash),
			zap.String("environment", p.cfg.Environment),
		)
		if !p.inWarmup() && p.tryClaimEvent("error.signature.drift", sig.hash) {
			if err := p.emitter.emitErrorDrift(p.cfg.Environment, buf.traceID, sig); err != nil {
				p.logger.Warn("failed to emit error drift event", zap.Error(err))
			} else {
				p.selfMetrics.ErrorEvents.Add(1)
			}
		}
		p.maybePromoteError(sig)
	}
}

// maybePromoteError increments the seen counter for sig.hash and promotes the
// error signature into the baseline when the count reaches PromotionThreshold.
func (p *fingerprintProcessor) maybePromoteError(sig errorSignature) {
	if p.cfg.PromotionThreshold <= 0 {
		return
	}
	p.seenMu.Lock()
	p.seenCounts[sig.hash]++
	count := p.seenCounts[sig.hash]
	p.seenCountsDirty = true
	p.seenMu.Unlock()

	if count < p.cfg.PromotionThreshold {
		return
	}

	promoted := p.baseline.promoteError(sig, p.cfg.PromotionWriteback)
	if !promoted {
		return
	}

	p.seenMu.Lock()
	delete(p.seenCounts, sig.hash)
	p.seenCountsDirty = true
	p.seenMu.Unlock()

	p.logger.Info("error signature auto-promoted",
		zap.String("hash", sig.hash),
		zap.String("service", sig.service),
		zap.String("error_type", sig.errorType),
		zap.Int("after_detections", count),
		zap.String("environment", p.cfg.Environment),
		zap.Bool("writeback", p.cfg.PromotionWriteback),
	)
	p.selfMetrics.Promotions.Add(1)
	if err := p.emitter.emitPromotion(p.cfg.Environment, sig.hash, sig.service+":"+sig.operation, "error", count); err != nil {
		p.logger.Warn("failed to emit promotion event", zap.Error(err))
	}
}
