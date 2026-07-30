package fingerprintprocessor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// topologyEdge represents a directed service-to-service call relationship.
type topologyEdge struct {
	Caller    string    `json:"caller"`
	Callee    string    `json:"callee"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// topologyFile is the on-disk format for topology.json.
type topologyFile struct {
	Environment string                  `json:"environment"`
	UpdatedAt   time.Time               `json:"updated_at"`
	Edges       map[string]topologyEdge `json:"edges"` // key: "caller->callee"
}

// topologyTracker observes span parent-child relationships from every flushed
// trace buffer and maintains a live service dependency graph.
//
// New edges (caller→callee pairs not previously seen) are:
//   1. Written to topology.json alongside the baseline file
//   2. Emitted as service.topology.edge events to Splunk so the topology
//      server can animate them onto the graph in real time
//   3. If TopologyDriftEnabled, new edges seen after warmup also emit
//      topology.edge.drift events for downstream correlation.
//
// The tracker is lock-safe and designed to be called from analyzeTrace()
// with minimal overhead — just map lookups on the hot path.
type topologyTracker struct {
	mu          sync.Mutex
	edges       map[string]*topologyEdge // "caller->callee" -> edge
	// baselineEdges holds edges that were present at load time (startup).
	// New edges discovered after startup are candidates for drift events.
	baselineEdges map[string]struct{}
	path          string // path to topology.json
	environment   string
	emitter       *emitter
	driftEnabled   bool
	onDriftEmitted func() // optional callback for counter increment (selfMetrics)
	dirty          bool      // true when edges have changed since last flush
	lastFlush      time.Time // last time topology.json was written
	flushInterval  time.Duration
}

func newTopologyTracker(baselinePath, environment string, e *emitter, driftEnabled bool) *topologyTracker {
	// Place topology.json next to baseline.json
	dir := filepath.Dir(baselinePath)
	topoPath := filepath.Join(dir, "topology.json")

	t := &topologyTracker{
		edges:         make(map[string]*topologyEdge),
		baselineEdges: make(map[string]struct{}),
		path:          topoPath,
		environment:   environment,
		emitter:       e,
		driftEnabled:  driftEnabled,
		flushInterval: 30 * time.Second,
	}
	t.load()
	// Re-emit all known edges on startup so the topology server (which may have
	// just restarted) can build the full picture from the event stream.
	go t.reemitAll()
	return t
}

// reemitAll emits service.topology.edge events for every edge already known
// (loaded from topology.json). Called once at startup after a short delay to
// let the ingest connection stabilize.
func (t *topologyTracker) reemitAll() {
	time.Sleep(10 * time.Second)
	t.mu.Lock()
	edges := make([]topologyEdge, 0, len(t.edges))
	for _, e := range t.edges {
		edges = append(edges, *e)
	}
	t.mu.Unlock()
	for _, edge := range edges {
		if err := t.emitter.emitTopologyEdge(t.environment, edge); err != nil {
			println("[topology] reemit error:", err.Error())
		}
	}
	if len(edges) > 0 {
		println("[topology] re-emitted", len(edges), "known edges on startup")
	}
}

// load reads an existing topology.json from disk (survives pod restarts).
func (t *topologyTracker) load() {
	data, err := os.ReadFile(t.path)
	if err != nil {
		return // file doesn't exist yet — start fresh
	}
	var f topologyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	for k, e := range f.Edges {
		edge := e // copy
		t.edges[k] = &edge
		t.baselineEdges[k] = struct{}{} // mark as known at startup
	}
}

// observe is called for every flushed trace. It extracts caller→callee pairs
// from the span tree and records any new edges.
//
// New edges are immediately emitted as service.topology.edge events.
// If TopologyDriftEnabled and not in warmup, new post-baseline edges also
// emit topology.edge.drift events for downstream anomaly correlation.
// The topology file is flushed to disk on a 30s interval.
func (t *topologyTracker) observe(spans []spanInfo, inWarmup bool) {
	if len(spans) == 0 {
		return
	}

	// Build spanID → span map and spanID → service map
	byID := make(map[string]*spanInfo, len(spans))
	for i := range spans {
		byID[spans[i].spanID] = &spans[i]
	}
	// Use inferParents (same as fingerprinting) to handle both explicit parentSpanID
	// and timing-containment fallback — required because in a DaemonSet spans from
	// the same trace may arrive without explicit parent IDs on every node.
	parentMap := inferParents(spans, byID)

	// Extract unique (caller, callee) pairs from parent→child span relationships
	type pair struct{ caller, callee string }
	seen := make(map[pair]struct{})
	for _, s := range spans {
		pid := parentMap[s.spanID]
		if pid == "" {
			continue
		}
		parent, ok := byID[pid]
		if !ok {
			continue
		}
		callerSvc := parent.service
		calleeSvc := s.service
		if callerSvc == "" || calleeSvc == "" || callerSvc == calleeSvc {
			continue
		}
		seen[pair{callerSvc, calleeSvc}] = struct{}{}
	}

	if len(seen) == 0 {
		return
	}

	now := time.Now()
	type newEdgeInfo struct {
		edge        topologyEdge
		isPostBaseline bool // true if not in baselineEdges at startup
	}
	var newEdges []newEdgeInfo

	t.mu.Lock()
	for p := range seen {
		key := p.caller + "->" + p.callee
		if existing, ok := t.edges[key]; ok {
			existing.LastSeen = now
			existing.Count++
			t.dirty = true
		} else {
			_, wasBaseline := t.baselineEdges[key]
			edge := &topologyEdge{
				Caller:    p.caller,
				Callee:    p.callee,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			}
			t.edges[key] = edge
			newEdges = append(newEdges, newEdgeInfo{
				edge:           *edge,
				isPostBaseline: !wasBaseline,
			})
			t.dirty = true
		}
	}
	shouldFlush := t.dirty && time.Since(t.lastFlush) >= t.flushInterval
	if shouldFlush {
		t.lastFlush = now
		t.dirty = false
	}
	t.mu.Unlock()

	// Emit events for new edges (outside lock)
	for _, ei := range newEdges {
		if err := t.emitter.emitTopologyEdge(t.environment, ei.edge); err != nil {
			println("[topology] emit error:", err.Error())
		}
		// Emit drift event for genuinely new post-baseline edges (not during warmup)
		if ei.isPostBaseline && t.driftEnabled && !inWarmup {
			if err := t.emitter.emitTopologyDrift(t.environment, ei.edge.Caller, ei.edge.Callee); err != nil {
				println("[topology] drift emit error:", err.Error())
			} else if t.onDriftEmitted != nil {
				t.onDriftEmitted()
			}
		}
	}

	// Flush to disk (outside lock, snapshot taken inside)
	if shouldFlush {
		t.flush()
	}
}

// flush writes the current topology to topology.json.
func (t *topologyTracker) flush() {
	t.mu.Lock()
	edgesCopy := make(map[string]topologyEdge, len(t.edges))
	for k, v := range t.edges {
		edgesCopy[k] = *v
	}
	t.mu.Unlock()

	f := topologyFile{
		Environment: t.environment,
		UpdatedAt:   time.Now(),
		Edges:       edgesCopy,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	// Write atomically via temp file + rename
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, t.path)
}

// Edges returns a snapshot of all known edges (for logging/debug).
func (t *topologyTracker) edgeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.edges)
}

// snapshotAdjacency returns the current caller->callees ("downstream") and
// callee->callers ("upstream") adjacency lists derived from known topology
// edges. Used by causalityTracker to walk the dependency graph when
// computing root-cause chains.
func (t *topologyTracker) snapshotAdjacency() (downstream, upstream map[string][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	downstream = make(map[string][]string)
	upstream = make(map[string][]string)
	for _, e := range t.edges {
		downstream[e.Caller] = append(downstream[e.Caller], e.Callee)
		upstream[e.Callee] = append(upstream[e.Callee], e.Caller)
	}
	return downstream, upstream
}
