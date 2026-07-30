package fingerprintprocessor

import (
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// activeAnomaly records a single detected anomaly for root-cause correlation.
type activeAnomaly struct {
	anomalyType string
	timestampMs int64
}

// causalityAnomalyWeights mirrors the confidence scoring in the standalone demo
// topology server (o11y-behaviorbaseline/demo/topology_server.py _ANOMALY_WEIGHTS)
// — higher weight means the anomaly type is a stronger root-cause signal.
// THROUGHPUT_DROP/ERROR_RATE_SPIKE/SLOW_QUERY are the Go processor's real event
// dimensions for the demo's SPAN_COUNT_DROP/ERROR_RATE_ANOMALY-adjacent concepts.
var causalityAnomalyWeights = map[string]float64{
	"MISSING_SERVICE":     1.0,
	"ERROR_RATE_ANOMALY":  0.85,
	"ERROR_RATE_SPIKE":    0.75,
	"NEW_ERROR_SIGNATURE": 0.7,
	"THROUGHPUT_DROP":     0.65,
	"LATENCY_ANOMALY":     0.5,
	"SLOW_QUERY":          0.4,
	"NEW_FINGERPRINT":     0.3,
}

func causalityWeight(anomalyType string) float64 {
	if w, ok := causalityAnomalyWeights[anomalyType]; ok {
		return w
	}
	return 0.1
}

// causalityIndependentAnomalyTypes are anomaly types that represent their own
// independent signal rather than a pure downstream symptom of another
// service's failure — used by isDownstreamSuppressed.
var causalityIndependentAnomalyTypes = map[string]struct{}{
	"NEW_ERROR_SIGNATURE": {},
	"MISSING_SERVICE":     {},
	"ERROR_RATE_ANOMALY":  {},
	"ERROR_RATE_SPIKE":    {},
}

// causalityResult is the outcome of a root-cause computation.
type causalityResult struct {
	rootCause  string
	chain      []string // [root_cause, intermediate..., most_upstream_affected]
	confidence float64
	suppressed []string // affected services that are pure downstream effects of rootCause
}

// causalityTracker maintains a rolling window of active anomalies per service
// and recomputes the most likely root-cause chain across all currently
// affected services whenever a new anomaly is recorded.
//
// This is a Go port of the standalone demo's _find_root_cause / _score_candidate /
// _downstream_suppressed functions (o11y-behaviorbaseline/demo/topology_server.py),
// adapted to run inside the live collector processor against the real topology
// graph (topologyTracker) instead of a disconnected demo correlation engine.
// The demo's "mysql:petclinic" special case is intentionally not ported — it is
// specific to one demo application, not a generalizable part of the algorithm.
type causalityTracker struct {
	mu     sync.Mutex
	active map[string][]activeAnomaly // service -> anomalies within ttl

	ttl         time.Duration
	enabled     bool
	topology    *topologyTracker
	emitter     *emitter
	environment string
	logger      *zap.Logger

	lastChainKey string // dedupe key: rootCause + sorted chain, avoids re-emitting an unchanged chain
}

func newCausalityTracker(topology *topologyTracker, e *emitter, environment string, ttl time.Duration, enabled bool) *causalityTracker {
	return &causalityTracker{
		active:      make(map[string][]activeAnomaly),
		ttl:         ttl,
		enabled:     enabled,
		topology:    topology,
		emitter:     e,
		environment: environment,
		logger:      zap.NewNop(),
	}
}

func (c *causalityTracker) withLogger(l *zap.Logger) *causalityTracker {
	c.logger = l
	return c
}

// record adds a new anomaly for svc and triggers root-cause recomputation.
// Called from the processor's existing detection call sites (trace drift,
// missing service, error signature drift/spike, throughput drop, slow query).
func (c *causalityTracker) record(svc, anomalyType string, ts time.Time) {
	if !c.enabled || svc == "" {
		return
	}
	now := ts.UnixMilli()
	c.mu.Lock()
	c.expireLocked(now)
	c.active[svc] = append(c.active[svc], activeAnomaly{anomalyType: anomalyType, timestampMs: now})
	c.mu.Unlock()
	c.recomputeAndMaybeEmit()
}

// expireLocked drops anomalies older than ttl. Caller must hold c.mu.
func (c *causalityTracker) expireLocked(nowMs int64) {
	cutoff := nowMs - c.ttl.Milliseconds()
	for svc, anoms := range c.active {
		var kept []activeAnomaly
		for _, a := range anoms {
			if a.timestampMs >= cutoff {
				kept = append(kept, a)
			}
		}
		if len(kept) == 0 {
			delete(c.active, svc)
		} else {
			c.active[svc] = kept
		}
	}
}

// findRootCause snapshots the currently-active anomalies and walks the
// dependency graph to identify the most likely root cause and its causality
// chain. Returns nil if there are no active anomalies.
func (c *causalityTracker) findRootCause() *causalityResult {
	c.mu.Lock()
	c.expireLocked(time.Now().UnixMilli())
	active := make(map[string][]activeAnomaly, len(c.active))
	for svc, anoms := range c.active {
		active[svc] = append([]activeAnomaly(nil), anoms...)
	}
	c.mu.Unlock()

	affected := make(map[string]struct{})
	for svc, anoms := range active {
		if len(anoms) > 0 {
			affected[svc] = struct{}{}
		}
	}
	if len(affected) == 0 {
		return nil
	}

	downstream, upstream := c.topology.snapshotAdjacency()

	firstSeen := make(map[string]int64, len(active))
	for svc, anoms := range active {
		if len(anoms) == 0 {
			continue
		}
		min := anoms[0].timestampMs
		for _, a := range anoms {
			if a.timestampMs < min {
				min = a.timestampMs
			}
		}
		firstSeen[svc] = min
	}

	var findDeepest func(svc string, visited map[string]struct{}) string
	findDeepest = func(svc string, visited map[string]struct{}) string {
		if _, ok := visited[svc]; ok {
			return svc
		}
		visited[svc] = struct{}{}
		for _, dep := range downstream[svc] {
			if _, ok := affected[dep]; ok {
				return findDeepest(dep, visited)
			}
		}
		return svc
	}

	candidates := make(map[string]struct{})
	for svc := range affected {
		candidates[findDeepest(svc, make(map[string]struct{}))] = struct{}{}
	}

	// MISSING_SERVICE is a strong structural signal — always a direct candidate,
	// even if findDeepest skipped over it in favor of a deeper affected node.
	for svc, anoms := range active {
		for _, a := range anoms {
			if a.anomalyType == "MISSING_SERVICE" {
				candidates[svc] = struct{}{}
				break
			}
		}
	}

	// Timing override: if an upstream node fired significantly (>=5s) before ALL
	// its affected downstream nodes, it is more likely the root cause itself
	// (e.g. the gateway itself is slow, not its dependencies).
	for svc := range affected {
		svcTs, ok := firstSeen[svc]
		if !ok || svcTs == 0 {
			continue
		}
		var depsAffected []string
		for _, d := range downstream[svc] {
			if _, ok := affected[d]; ok {
				depsAffected = append(depsAffected, d)
			}
		}
		if len(depsAffected) == 0 {
			continue // already a leaf — already a candidate
		}
		allDepsLater := true
		for _, d := range depsAffected {
			dTs, ok := firstSeen[d]
			if !ok {
				dTs = svcTs
			}
			if dTs < svcTs+5000 {
				allDepsLater = false
				break
			}
		}
		if allDepsLater {
			candidates[svc] = struct{}{}
		}
	}

	confidence := make(map[string]float64, len(candidates))
	for svc := range candidates {
		confidence[svc] = c.scoreCandidate(svc, active, upstream, downstream, affected, firstSeen)
	}

	// Deterministic tie-breaking: iterate candidates in sorted order.
	sortedCandidates := make([]string, 0, len(candidates))
	for svc := range candidates {
		sortedCandidates = append(sortedCandidates, svc)
	}
	sort.Strings(sortedCandidates)

	var rootCause string
	best := -1.0
	for _, svc := range sortedCandidates {
		if confidence[svc] > best {
			best = confidence[svc]
			rootCause = svc
		}
	}

	chain := c.buildChain(rootCause, upstream, affected)

	var suppressed []string
	for svc := range affected {
		if c.isDownstreamSuppressed(svc, rootCause, downstream, active) {
			suppressed = append(suppressed, svc)
		}
	}
	sort.Strings(suppressed)

	return &causalityResult{
		rootCause:  rootCause,
		chain:      chain,
		confidence: confidence[rootCause],
		suppressed: suppressed,
	}
}

// scoreCandidate computes a confidence score in [0, 1] for a root-cause
// candidate, mirroring the demo's _score_candidate weighting: anomaly type
// (60%), topology fan-in/fan-out fraction (25%), earliest-timing bonus (10%),
// plus a flat bonus when the candidate is purely a MISSING_SERVICE signal.
func (c *causalityTracker) scoreCandidate(
	svc string,
	active map[string][]activeAnomaly,
	upstream, downstream map[string][]string,
	affected map[string]struct{},
	firstSeen map[string]int64,
) float64 {
	anoms := active[svc]
	if len(anoms) == 0 {
		return 0
	}

	typeWeight := 0.0
	for _, a := range anoms {
		if w := causalityWeight(a.anomalyType); w > typeWeight {
			typeWeight = w
		}
	}

	totalAffected := len(affected) - 1
	if totalAffected < 1 {
		totalAffected = 1
	}

	callersAffected := 0
	for _, caller := range upstream[svc] {
		if _, ok := affected[caller]; ok {
			callersAffected++
		}
	}
	callerFraction := float64(callersAffected) / float64(totalAffected)

	callees := downstream[svc]
	calleesAffected := 0
	for _, callee := range callees {
		if _, ok := affected[callee]; ok {
			calleesAffected++
		}
	}
	calleeFraction := float64(calleesAffected) / float64(totalAffected)

	earliest := firstSeen[svc]
	var minTs, maxTs int64
	first := true
	for _, anomsList := range active {
		for _, a := range anomsList {
			if a.timestampMs == 0 {
				continue
			}
			if first {
				minTs, maxTs = a.timestampMs, a.timestampMs
				first = false
				continue
			}
			if a.timestampMs < minTs {
				minTs = a.timestampMs
			}
			if a.timestampMs > maxTs {
				maxTs = a.timestampMs
			}
		}
	}
	timingBonus := 0.0
	if !first {
		span := maxTs - minTs
		if span == 0 {
			span = 1
		}
		timingBonus = 0.1 * (1.0 - float64(earliest-minTs)/float64(span))
	}

	hasOnlyMissing := true
	for _, a := range anoms {
		if a.anomalyType != "MISSING_SERVICE" {
			hasOnlyMissing = false
			break
		}
	}
	missingBonus := 0.0
	if hasOnlyMissing {
		missingBonus = 0.3
	}

	// Suppress topology fraction when there's a cycle between affected nodes
	// (e.g. checkout <-> payment orchestrator pattern) — it produces false
	// caller boosts.
	hasCycleWithAffected := false
	for _, callee := range callees {
		if _, ok := affected[callee]; !ok {
			continue
		}
		for _, calleeCaller := range upstream[callee] {
			if calleeCaller == svc {
				hasCycleWithAffected = true
				break
			}
		}
		if hasCycleWithAffected {
			break
		}
	}
	topoFraction := callerFraction
	if calleeFraction > topoFraction {
		topoFraction = calleeFraction
	}
	if hasCycleWithAffected {
		topoFraction = 0.0
	}

	score := (typeWeight * 0.6) + (topoFraction * 0.25) + (timingBonus * 0.1) + missingBonus
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// buildChain walks upstream from rootCause through affected callers, layer by
// layer, producing [root_cause, intermediate..., most_upstream_affected].
func (c *causalityTracker) buildChain(rootCause string, upstream map[string][]string, affected map[string]struct{}) []string {
	chain := []string{rootCause}
	visited := map[string]struct{}{rootCause: {}}

	nextAffectedCallers := func(svc string) []string {
		var out []string
		for _, caller := range upstream[svc] {
			if _, ok := affected[caller]; !ok {
				continue
			}
			if _, seen := visited[caller]; seen {
				continue
			}
			out = append(out, caller)
		}
		return out
	}

	frontier := nextAffectedCallers(rootCause)
	for len(frontier) > 0 {
		var next []string
		for _, svc := range frontier {
			if _, seen := visited[svc]; seen {
				continue
			}
			chain = append(chain, svc)
			visited[svc] = struct{}{}
			next = append(next, nextAffectedCallers(svc)...)
		}
		frontier = next
	}
	return chain
}

// isDownstreamSuppressed returns true if svc is purely a downstream effect of
// rootCause: it is not the root cause, has no independent anomaly signal of
// its own, and rootCause is reachable from svc via downstream call edges
// (i.e. svc transitively calls rootCause).
func (c *causalityTracker) isDownstreamSuppressed(
	svc, rootCause string,
	downstream map[string][]string,
	active map[string][]activeAnomaly,
) bool {
	if svc == rootCause {
		return false
	}
	for _, a := range active[svc] {
		if _, ok := causalityIndependentAnomalyTypes[a.anomalyType]; ok {
			return false
		}
	}
	visited := make(map[string]struct{})
	frontier := append([]string(nil), downstream[svc]...)
	for len(frontier) > 0 {
		node := frontier[len(frontier)-1]
		frontier = frontier[:len(frontier)-1]
		if node == rootCause {
			return true
		}
		if _, ok := visited[node]; ok {
			continue
		}
		visited[node] = struct{}{}
		frontier = append(frontier, downstream[node]...)
	}
	return false
}

// recomputeAndMaybeEmit recomputes the root-cause chain and emits a
// service.causality.chain event only when the chain has changed since the
// last emission, to avoid spamming Splunk on every single anomaly.
func (c *causalityTracker) recomputeAndMaybeEmit() {
	if !c.enabled {
		return
	}
	result := c.findRootCause()

	c.mu.Lock()
	if result == nil {
		c.lastChainKey = ""
		c.mu.Unlock()
		return
	}
	key := result.rootCause + "|" + strings.Join(result.chain, ",")
	if key == c.lastChainKey {
		c.mu.Unlock()
		return
	}
	c.lastChainKey = key
	c.mu.Unlock()

	if err := c.emitter.emitCausalityChain(c.environment, result.rootCause, result.chain, result.confidence, result.suppressed); err != nil {
		c.logger.Warn("failed to emit causality chain event", zap.Error(err))
	}
}
