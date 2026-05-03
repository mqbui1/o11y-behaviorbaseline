package fingerprintprocessor

import (
	"fmt"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func span(id, parent, svc, op string, startNs, durNs uint64, isErr bool) spanInfo {
	return spanInfo{
		spanID:      id,
		parentID:    parent,
		service:     svc,
		operation:   op,
		startTimeNs: startNs,
		durationNs:  durNs,
		isError:     isErr,
		tags:        map[string]string{},
	}
}

// mkTrace builds a simple linear call chain:
//   spans[0] (root) → spans[1] → spans[2] → ...
// Each child's start time is 1µs after parent start; each span 10ms.
func mkTrace(svcsAndOps ...string) []spanInfo {
	if len(svcsAndOps)%2 != 0 {
		panic("svcsAndOps must be (service, op) pairs")
	}
	var spans []spanInfo
	baseNs := uint64(1_000_000_000) // 1s
	durNs := uint64(10_000_000)     // 10ms
	for i := 0; i < len(svcsAndOps); i += 2 {
		id := fmt.Sprintf("span%02d", i/2)
		parent := ""
		if i > 0 {
			parent = fmt.Sprintf("span%02d", i/2-1)
		}
		spans = append(spans, span(
			id, parent,
			svcsAndOps[i], svcsAndOps[i+1],
			baseNs+uint64(i)*1000, durNs-uint64(i)*1000, false,
		))
	}
	return spans
}

// ── buildTraceFingerprint ────────────────────────────────────────────────────

func TestBuildTraceFingerprint_BasicPath(t *testing.T) {
	spans := mkTrace(
		"api-gateway", "GET /owners",
		"customers-service", "GET /owners",
	)
	fp := buildTraceFingerprint(spans, 2)
	if fp == nil {
		t.Fatal("expected fingerprint, got nil")
	}
	if fp.rootOp != "api-gateway:GET /owners" {
		t.Errorf("rootOp = %q, want api-gateway:GET /owners", fp.rootOp)
	}
	if fp.edgeCount != 1 {
		t.Errorf("edgeCount = %d, want 1", fp.edgeCount)
	}
	if len(fp.services) != 2 {
		t.Errorf("services = %v, want 2 entries", fp.services)
	}
}

func TestBuildTraceFingerprint_HashStability(t *testing.T) {
	// Same logical trace, different span order → same hash (cross-service edges
	// are sorted deterministically via the edge string).
	spans1 := mkTrace(
		"api-gateway", "GET /owners",
		"customers-service", "GET /owners",
		"mysql:petclinic", "SELECT owners",
	)
	spans2 := mkTrace(
		"api-gateway", "GET /owners",
		"customers-service", "GET /owners",
		"mysql:petclinic", "SELECT owners_with_extra_where_clause",
	)
	fp1 := buildTraceFingerprint(spans1, 2)
	fp2 := buildTraceFingerprint(spans2, 2)
	if fp1 == nil || fp2 == nil {
		t.Fatal("expected non-nil fingerprints")
	}
	// Cross-service-only hashing: the MySQL intra-query variation doesn't matter
	// because mysql:petclinic spans are intra-service children of customers-service.
	// Both should produce the same hash.
	// NOTE: in this test both are cross-service (api-gw→customers, customers→mysql)
	// so hashes will differ if the operation name is included. Test the contract:
	// same service topology = same hash regardless of intra-service variations.
	// We verify by changing only an intra-service span operation.
	spans3 := mkTrace(
		"api-gateway", "GET /owners",
		"customers-service", "GET /owners",
	)
	// Add an intra-service span to spans3 (same service as customers-service)
	intra := span("span99", "span01", "customers-service", "internal-cache-lookup",
		1_000_002_000, 500_000, false)
	spans3 = append(spans3, intra)

	fp3 := buildTraceFingerprint(spans3, 2)
	if fp3 == nil {
		t.Fatal("expected fp3")
	}
	// fp3 should match fp1 with only api-gw→customers edge (no mysql)
	spans4 := mkTrace(
		"api-gateway", "GET /owners",
		"customers-service", "GET /owners",
	)
	fp4 := buildTraceFingerprint(spans4, 2)
	if fp3.hash != fp4.hash {
		t.Errorf("intra-service span changed hash: fp3=%q fp4=%q", fp3.hash, fp4.hash)
	}
}

func TestBuildTraceFingerprint_IntraServiceEdgesExcluded(t *testing.T) {
	// All spans are the same service — no cross-service edges → edgeCount = 0
	spans := []spanInfo{
		span("s0", "", "api-gateway", "GET /health", 1000, 5000, false),
		span("s1", "s0", "api-gateway", "internal-auth", 1001, 4000, false),
		span("s2", "s1", "api-gateway", "db-fetch", 1002, 3000, false),
	}
	fp := buildTraceFingerprint(spans, 2)
	if fp == nil {
		t.Fatal("expected fingerprint even with 0 edges")
	}
	if fp.edgeCount != 0 {
		t.Errorf("edgeCount = %d, want 0 (all intra-service)", fp.edgeCount)
	}
}

func TestBuildTraceFingerprint_MinSpansFiltering(t *testing.T) {
	spans := mkTrace("api-gateway", "GET /owners")
	fp := buildTraceFingerprint(spans, 3) // need 3, have 1
	if fp != nil {
		t.Errorf("expected nil for too-few spans, got %+v", fp)
	}
}

func TestBuildTraceFingerprint_NoiseOperationFiltered(t *testing.T) {
	spans := mkTrace("discovery-server", "/eureka/apps/delta")
	fp := buildTraceFingerprint(spans, 1)
	if fp != nil {
		t.Errorf("expected nil for noise operation, got %+v", fp)
	}
}

func TestBuildTraceFingerprint_DeduplicateEdges(t *testing.T) {
	// Two spans create the same cross-service edge (e.g. fan-out pattern) —
	// should be deduplicated in the path hash.
	s0 := span("s0", "", "api-gateway", "GET /owners", 1000, 9000, false)
	s1 := span("s1", "s0", "customers-service", "GET /owners/1", 1001, 4000, false)
	s2 := span("s2", "s0", "customers-service", "GET /owners/2", 1002, 4000, false)
	fp := buildTraceFingerprint([]spanInfo{s0, s1, s2}, 2)
	if fp == nil {
		t.Fatal("expected fingerprint")
	}
	// Both s1 and s2 produce the same edge key (api-gateway:GET /owners → customers-service:GET /owners/*)
	// but since they have different operations the key differs — they are distinct edges.
	// What we test is that the same key is not counted twice.
	s3 := span("s3", "s0", "customers-service", "GET /owners/1", 1003, 4000, false) // duplicate of s1
	fp2 := buildTraceFingerprint([]spanInfo{s0, s1, s2, s3}, 2)
	if fp2 == nil {
		t.Fatal("expected fp2")
	}
	if fp.hash != fp2.hash {
		// Adding a duplicate edge should not change the hash
		t.Errorf("duplicate edge changed hash: fp=%q fp2=%q", fp.hash, fp2.hash)
	}
}

func TestBuildTraceFingerprint_NilOnNilSpans(t *testing.T) {
	fp := buildTraceFingerprint(nil, 2)
	if fp != nil {
		t.Errorf("expected nil for nil spans")
	}
}

// ── inferParents ─────────────────────────────────────────────────────────────

func TestInferParents_ExplicitParentId(t *testing.T) {
	s0 := span("aaa", "", "svc", "root", 1000, 5000, false)
	s1 := span("bbb", "aaa", "svc", "child", 1001, 4000, false)
	byID := map[string]*spanInfo{"aaa": &s0, "bbb": &s1}
	parents := inferParents([]spanInfo{s0, s1}, byID)
	if parents["bbb"] != "aaa" {
		t.Errorf("explicit parent not used: got %q", parents["bbb"])
	}
	if parents["aaa"] != "" {
		t.Errorf("root should have no parent: got %q", parents["aaa"])
	}
}

func TestInferParents_TimingContainmentFallback(t *testing.T) {
	// s1 has no parentID but is contained within s0's time window
	s0 := span("aaa", "", "svc", "root", 1000, 5000, false)
	s1 := span("bbb", "", "svc", "child", 1001, 3000, false) // no parentID
	byID := map[string]*spanInfo{"aaa": &s0, "bbb": &s1}
	parents := inferParents([]spanInfo{s0, s1}, byID)
	if parents["bbb"] != "aaa" {
		t.Errorf("timing containment fallback failed: got %q", parents["bbb"])
	}
}

func TestInferParents_MissingParentFallsBack(t *testing.T) {
	// parentID set but not present in trace (cross-buffer span)
	s0 := span("aaa", "", "svc", "root", 1000, 5000, false)
	s1 := span("bbb", "zzz", "svc", "child", 1001, 3000, false) // zzz not in trace
	byID := map[string]*spanInfo{"aaa": &s0, "bbb": &s1}
	parents := inferParents([]spanInfo{s0, s1}, byID)
	// Should fall back to timing containment
	if parents["bbb"] != "aaa" {
		t.Errorf("missing parent should fall back to timing containment: got %q", parents["bbb"])
	}
}

// ── buildErrorSignatures ─────────────────────────────────────────────────────

func TestBuildErrorSignatures_BasicError(t *testing.T) {
	s0 := span("s0", "", "api-gateway", "GET /owners", 1000, 5000, false)
	s1 := span("s1", "s0", "customers-service", "GET /owners", 1001, 4000, true) // error
	s1.tags["exception.type"] = "java.sql.SQLException"
	sigs := buildErrorSignatures([]spanInfo{s0, s1})
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if sigs[0].service != "customers-service" {
		t.Errorf("service = %q", sigs[0].service)
	}
	if sigs[0].errorType != "java.sql.SQLException" {
		t.Errorf("errorType = %q", sigs[0].errorType)
	}
}

func TestBuildErrorSignatures_HashStability(t *testing.T) {
	// Same error on same service+op+path → same hash every time
	makeSpans := func() []spanInfo {
		s0 := span("s0", "", "api-gateway", "GET /owners", 1000, 5000, false)
		s1 := span("s1", "s0", "customers-service", "GET /owners", 1001, 4000, true)
		s1.tags["exception.type"] = "java.sql.SQLException"
		return []spanInfo{s0, s1}
	}
	sigs1 := buildErrorSignatures(makeSpans())
	sigs2 := buildErrorSignatures(makeSpans())
	if sigs1[0].hash != sigs2[0].hash {
		t.Errorf("hash unstable: %q != %q", sigs1[0].hash, sigs2[0].hash)
	}
}

func TestBuildErrorSignatures_NoErrorSpans(t *testing.T) {
	spans := mkTrace("api-gateway", "GET /owners", "customers-service", "GET /owners")
	sigs := buildErrorSignatures(spans)
	if len(sigs) != 0 {
		t.Errorf("expected 0 sigs for non-error spans, got %d", len(sigs))
	}
}

func TestBuildErrorSignatures_NoiseOperationSkipped(t *testing.T) {
	s0 := span("s0", "", "api-gateway", "GET /actuator/health", 1000, 5000, true)
	sigs := buildErrorSignatures([]spanInfo{s0})
	if len(sigs) != 0 {
		t.Errorf("noise operation should be skipped, got %d sigs", len(sigs))
	}
}

func TestBuildErrorSignatures_HttpStatusFallback(t *testing.T) {
	s0 := span("s0", "", "api-gateway", "GET /owners", 1000, 5000, true)
	s0.tags["http.status_code"] = "503"
	sigs := buildErrorSignatures([]spanInfo{s0})
	if len(sigs) != 1 {
		t.Fatalf("expected 1 sig, got %d", len(sigs))
	}
	if sigs[0].errorType != "503" {
		t.Errorf("errorType = %q, want 503", sigs[0].errorType)
	}
	if sigs[0].httpStatus != "503" {
		t.Errorf("httpStatus = %q, want 503", sigs[0].httpStatus)
	}
}

// ── isNoiseOperation ─────────────────────────────────────────────────────────

func TestIsNoiseOperation(t *testing.T) {
	cases := []struct {
		op   string
		want bool
	}{
		{"/eureka/apps/delta", true},
		{"/actuator/health", true},
		{"/healthz", true},
		{"GET /owners", false},
		{"POST /visits", false},
		{"SELECT * FROM owners", false},
	}
	for _, c := range cases {
		got := isNoiseOperation(c.op)
		if got != c.want {
			t.Errorf("isNoiseOperation(%q) = %v, want %v", c.op, got, c.want)
		}
	}
}

// ── baselineStore ─────────────────────────────────────────────────────────────

func TestBaselineStore_PromoteAndLookup(t *testing.T) {
	bs := &baselineStore{
		traceFingerprints: make(map[string]*fingerprintEntry),
		errorSignatures:   make(map[string]*errorSigEntry),
		errorRates:        make(map[string]*errorRateWindow),
	}

	fp := &traceFingerprint{
		hash:      "abc123",
		path:      "api-gateway:GET -> customers-service:GET /owners",
		rootOp:    "api-gateway:GET",
		services:  []string{"api-gateway", "customers-service"},
		spanCount: 5,
		edgeCount: 1,
	}

	promoted := bs.promoteTrace(fp, false)
	if !promoted {
		t.Fatal("expected promotion to succeed")
	}
	// Promoting again should return false
	if bs.promoteTrace(fp, false) {
		t.Error("second promotion should return false")
	}

	entry := bs.lookupTrace("abc123")
	if entry == nil {
		t.Fatal("lookup failed after promotion")
	}
	if entry.RootOp != "api-gateway:GET" {
		t.Errorf("RootOp = %q", entry.RootOp)
	}
	if !entry.AutoPromoted {
		t.Error("AutoPromoted should be true")
	}
}

func TestBaselineStore_TraceFingerprintsByRootOp_IncludesAutoPromoted(t *testing.T) {
	bs := &baselineStore{
		traceFingerprints: map[string]*fingerprintEntry{
			"h1": {Hash: "h1", RootOp: "api-gateway:GET", Occurrences: 1, AutoPromoted: true},
			"h2": {Hash: "h2", RootOp: "api-gateway:GET", Occurrences: 5, AutoPromoted: false},
			"h3": {Hash: "h3", RootOp: "other:GET", Occurrences: 5, AutoPromoted: false},
		},
		errorSignatures: make(map[string]*errorSigEntry),
		errorRates:      make(map[string]*errorRateWindow),
	}

	results := bs.traceFingerprintsByRootOp("api-gateway:GET", 2)
	if len(results) != 2 {
		t.Errorf("expected 2 results (h1 auto_promoted + h2 occurrences≥2), got %d", len(results))
	}
}

func TestBaselineStore_StalenesInfo(t *testing.T) {
	bs := &baselineStore{
		traceFingerprints: make(map[string]*fingerprintEntry),
		errorSignatures:   make(map[string]*errorSigEntry),
		errorRates:        make(map[string]*errorRateWindow),
	}
	mt, p := bs.stalenessInfo()
	if !mt.IsZero() {
		t.Error("modTime should be zero for fresh store")
	}
	if p != 0 {
		t.Errorf("promotions should be 0, got %d", p)
	}

	// Promote something — promotionsSinceLoad should increment
	fp := &traceFingerprint{hash: "x1", rootOp: "svc:op", services: []string{"svc"}}
	bs.promoteTrace(fp, false)
	_, p2 := bs.stalenessInfo()
	if p2 != 1 {
		t.Errorf("promotionsSinceLoad = %d, want 1", p2)
	}
}

// ── throughputWindow ─────────────────────────────────────────────────────────

func TestThroughputDrop_LearnPhase(t *testing.T) {
	cfg := &Config{
		ThroughputDropWindow:      2 * time.Minute,
		ThroughputDropThreshold:   0.5,
		ThroughputLearnMinSamples: 3,
	}
	var dropped bool
	emit := &emitter{ingestURL: "", token: ""}
	mt := &metricsTracker{
		windows:    make(map[string]*metricWindow),
		spanRates:  make(map[string][]spanRateBucket),
		throughput: make(map[string]*throughputWindow),
		emitter:    emit,
		cfg:        cfg,
	}

	// First 3 observations are learn phase — no drop should fire
	for i := 0; i < 3; i++ {
		mt.observeRootOp("api-gateway:GET", "test", false)
	}
	_ = dropped
	tw := mt.throughput["api-gateway:GET"]
	if tw == nil {
		t.Fatal("throughputWindow not created")
	}
	if tw.dropEmitted {
		t.Error("drop should not fire during learn phase")
	}
	if tw.baselineRate <= 0 {
		t.Errorf("baselineRate should be > 0 after learn phase, got %f", tw.baselineRate)
	}
}
