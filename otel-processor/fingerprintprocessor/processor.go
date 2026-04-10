package fingerprintprocessor

import (
	"context"
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

	mu      sync.Mutex
	buffers map[string]*traceBuffer // traceId -> buffer

	// seenMu guards seenCounts independently of the trace buffer mutex so
	// promotion counter updates don't contend with span ingestion.
	seenMu     sync.Mutex
	seenCounts map[string]int // hash -> detection count since startup

	stopCh chan struct{}
}

func newFingerprintProcessor(logger *zap.Logger, cfg *Config, next consumer.Traces) (*fingerprintProcessor, error) {
	p := &fingerprintProcessor{
		logger:     logger,
		cfg:        cfg,
		next:       next,
		baseline:   newBaselineStore(cfg.BaselinePath, cfg.ErrorBaselinePath, cfg.BaselineReloadInterval),
		emitter:    newEmitter(cfg.SplunkIngestURL, cfg.SplunkAccessToken, cfg.SplunkApiToken),
		buffers:    make(map[string]*traceBuffer),
		seenCounts: make(map[string]int),
		stopCh:     make(chan struct{}),
	}
	if cfg.PromotionThreshold > 0 {
		p.logger.Info("auto-promotion enabled",
			zap.Int("threshold", cfg.PromotionThreshold),
			zap.Bool("writeback", cfg.PromotionWriteback),
		)
	}
	return p, nil
}

func (p *fingerprintProcessor) Start(_ context.Context, _ component.Host) error {
	go p.flushLoop()
	return nil
}

func (p *fingerprintProcessor) Shutdown(_ context.Context) error {
	close(p.stopCh)
	return nil
}

func (p *fingerprintProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces is called for every batch of spans arriving at the processor.
// Spans are grouped by traceId into buffers; each buffer is flushed after
// TraceBufferTimeout to ensure we fingerprint complete traces.
func (p *fingerprintProcessor) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	// Always pass through to the next consumer first — no blocking.
	if err := p.next.ConsumeTraces(ctx, td); err != nil {
		return err
	}

	// Reload baseline if due
	p.baseline.maybeReload()

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

// analyzeTrace runs both trace structure and error signature detection on a
// flushed trace buffer.
func (p *fingerprintProcessor) analyzeTrace(buf *traceBuffer) {
	p.analyzeTraceStructure(buf)
	p.analyzeErrorSignatures(buf)
}

func (p *fingerprintProcessor) analyzeTraceStructure(buf *traceBuffer) {
	fp := buildTraceFingerprint(buf.spans, p.cfg.MinSpans)
	if fp == nil {
		return
	}

	entry := p.baseline.lookupTrace(fp.hash)

	// Known and established — no alert
	if entry != nil && entry.Occurrences >= p.cfg.MinBaselineOccurrences {
		return
	}
	// Auto-promoted — no alert
	if entry != nil && entry.AutoPromoted {
		return
	}

	// Partial trace guard: if we have established baselines for this root_op,
	// check whether the spans we collected represent a meaningfully complete
	// trace. In a multi-node deployment, spans from the same trace may arrive
	// at different collector instances. Fingerprinting an incomplete span set
	// produces a hash that will never match the baseline, causing false-positive
	// NEW_FINGERPRINT alerts. Skip detection when the span count is below
	// PartialTraceThreshold * max(baseline span counts for this root_op).
	if p.cfg.PartialTraceThreshold > 0 {
		maxExpected := p.baseline.maxBaselineSpanCount(fp.rootOp, p.cfg.MinBaselineOccurrences)
		if maxExpected > 0 {
			threshold := int(float64(maxExpected) * p.cfg.PartialTraceThreshold)
			if fp.spanCount < threshold {
				p.logger.Debug("skipping partial trace",
					zap.String("trace_id", buf.traceID),
					zap.String("root_op", fp.rootOp),
					zap.Int("span_count", fp.spanCount),
					zap.Int("expected_min", threshold),
					zap.Int("baseline_max", maxExpected),
				)
				return
			}
		}
	}

	// Check for MISSING_SERVICE: same root_op in baseline but fewer services now
	established := p.baseline.traceFingerprintsByRootOp(fp.rootOp, p.cfg.MinBaselineOccurrences)
	if len(established) > 0 && entry == nil {
		// New fingerprint for a known root op
		p.logger.Info("trace drift detected",
			zap.String("trace_id", buf.traceID),
			zap.String("root_op", fp.rootOp),
			zap.String("hash", fp.hash),
			zap.String("path", fp.path),
			zap.String("environment", p.cfg.Environment),
		)
		if err := p.emitter.emitTraceDrift(p.cfg.Environment, buf.traceID, fp); err != nil {
			p.logger.Warn("failed to emit trace drift event", zap.Error(err))
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
		if err := p.emitter.emitTraceDrift(p.cfg.Environment, buf.traceID, fp); err != nil {
			p.logger.Warn("failed to emit trace drift event", zap.Error(err))
		}
		p.maybePromoteTrace(fp)
	}
}

// maybePromoteTrace increments the seen counter for fp.hash and promotes the
// fingerprint into the baseline when the count reaches PromotionThreshold.
func (p *fingerprintProcessor) maybePromoteTrace(fp *traceFingerprint) {
	if p.cfg.PromotionThreshold <= 0 {
		return
	}
	p.seenMu.Lock()
	p.seenCounts[fp.hash]++
	count := p.seenCounts[fp.hash]
	p.seenMu.Unlock()

	if count < p.cfg.PromotionThreshold {
		return
	}

	promoted := p.baseline.promoteTrace(fp, p.cfg.PromotionWriteback)
	if !promoted {
		return // already in baseline (concurrent promotion or reload)
	}

	p.seenMu.Lock()
	delete(p.seenCounts, fp.hash)
	p.seenMu.Unlock()

	p.logger.Info("trace fingerprint auto-promoted",
		zap.String("hash", fp.hash),
		zap.String("root_op", fp.rootOp),
		zap.Int("after_detections", count),
		zap.String("environment", p.cfg.Environment),
		zap.Bool("writeback", p.cfg.PromotionWriteback),
	)
	if err := p.emitter.emitPromotion(p.cfg.Environment, fp.hash, fp.rootOp, "trace", count); err != nil {
		p.logger.Warn("failed to emit promotion event", zap.Error(err))
	}
}

func (p *fingerprintProcessor) analyzeErrorSignatures(buf *traceBuffer) {
	sigs := buildErrorSignatures(buf.spans)
	for _, sig := range sigs {
		entry := p.baseline.lookupError(sig.hash)
		if entry != nil && entry.Occurrences >= p.cfg.MinBaselineOccurrences {
			continue // known error pattern
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
		if err := p.emitter.emitErrorDrift(p.cfg.Environment, buf.traceID, sig); err != nil {
			p.logger.Warn("failed to emit error drift event", zap.Error(err))
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
	p.seenMu.Unlock()

	p.logger.Info("error signature auto-promoted",
		zap.String("hash", sig.hash),
		zap.String("service", sig.service),
		zap.String("error_type", sig.errorType),
		zap.Int("after_detections", count),
		zap.String("environment", p.cfg.Environment),
		zap.Bool("writeback", p.cfg.PromotionWriteback),
	)
	if err := p.emitter.emitPromotion(p.cfg.Environment, sig.hash, sig.service+":"+sig.operation, "error", count); err != nil {
		p.logger.Warn("failed to emit promotion event", zap.Error(err))
	}
}
