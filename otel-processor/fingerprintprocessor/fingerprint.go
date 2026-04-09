package fingerprintprocessor

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// noisePatterns matches trace root operations that should be excluded.
// Mirrors NOISE_PATTERNS in trace_fingerprint.py.
var noisePatterns = []string{
	"/eureka/", "/apps/delta", "/apps/", "/register", "/peerreplication",
	"/v1/agent/", "/v1/health/", "/v1/catalog/", "/v1/kv/", "/registry/",
	"service_discovery",
	"/actuator", "/health", "/healthz", "/readyz", "/livez",
	"/ready", "/live", "/ping", "/status", "/_health", "/api/health",
}

// isNoiseOperation returns true if the operation should be excluded from fingerprinting.
func isNoiseOperation(op string) bool {
	lower := strings.ToLower(op)
	for _, p := range noisePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// spanInfo is a lightweight representation of a span for fingerprinting.
type spanInfo struct {
	spanID      string
	parentID    string // from actual parentSpanID attribute
	service     string
	operation   string
	startTimeNs uint64
	durationNs  uint64
	isError     bool
	tags        map[string]string
}

// extractSpans flattens a ptrace.Traces into []spanInfo.
func extractSpans(td ptrace.Traces) []spanInfo {
	var spans []spanInfo
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		service := ""
		if v, ok := rs.Resource().Attributes().Get("service.name"); ok {
			service = v.AsString()
		}
		ilss := rs.ScopeSpans()
		for j := 0; j < ilss.Len(); j++ {
			ils := ilss.At(j)
			for k := 0; k < ils.Spans().Len(); k++ {
				s := ils.Spans().At(k)
				info := spanInfo{
					spanID:      s.SpanID().String(),
					parentID:    s.ParentSpanID().String(),
					service:     service,
					operation:   s.Name(),
					startTimeNs: uint64(s.StartTimestamp()),
					durationNs:  uint64(s.EndTimestamp() - s.StartTimestamp()),
					isError:     s.Status().Code() == ptrace.StatusCodeError,
					tags:        make(map[string]string),
				}
				// parentID of all-zeros means no parent
				if info.parentID == "0000000000000000" {
					info.parentID = ""
				}
				s.Attributes().Range(func(k string, v pcommon.Value) bool {
					info.tags[k] = v.AsString()
					return true
				})
				if !info.isError {
					if v, ok := info.tags["error"]; ok && v == "true" {
						info.isError = true
					}
					if v, ok := info.tags["otel.status_code"]; ok && v == "ERROR" {
						info.isError = true
					}
				}
				spans = append(spans, info)
			}
		}
	}
	return spans
}

// traceFingerprint is the computed structural fingerprint of a trace.
type traceFingerprint struct {
	hash      string
	path      string
	rootOp    string
	services  []string
	spanCount int
	edgeCount int
}

// buildTraceFingerprint computes a structural fingerprint from a set of spans
// belonging to the same traceId. Mirrors build_fingerprint() in trace_fingerprint.py.
func buildTraceFingerprint(spans []spanInfo, minSpans int) *traceFingerprint {
	if len(spans) < minSpans {
		return nil
	}

	// Sort by start time
	sort.Slice(spans, func(i, j int) bool {
		return spans[i].startTimeNs < spans[j].startTimeNs
	})

	// Build spanID lookup
	byID := make(map[string]*spanInfo, len(spans))
	for i := range spans {
		byID[spans[i].spanID] = &spans[i]
	}

	// Infer parent map: use actual parentSpanID if present, else timing containment
	parentMap := inferParents(spans, byID)

	// Find root span (no inferred parent)
	var root *spanInfo
	for i := range spans {
		if parentMap[spans[i].spanID] == "" {
			root = &spans[i]
			break
		}
	}
	if root == nil {
		root = &spans[0]
	}

	if isNoiseOperation(root.operation) {
		return nil
	}

	// Filter short noisy traces
	if len(spans) <= 3 {
		allOps := ""
		for _, s := range spans {
			allOps += " " + strings.ToLower(s.operation)
		}
		if isNoiseOperation(allOps) {
			return nil
		}
	}

	rootOp := root.service + ":" + root.operation

	// Build edge list: parent:op -> child:op in time order
	type edge struct {
		from string
		to   string
	}
	var edges []edge
	for _, s := range spans {
		pid := parentMap[s.spanID]
		if pid == "" {
			continue
		}
		parent, ok := byID[pid]
		if !ok {
			continue
		}
		edges = append(edges, edge{
			from: parent.service + ":" + parent.operation,
			to:   s.service + ":" + s.operation,
		})
	}

	// Build path string
	var pathParts []string
	for _, e := range edges {
		pathParts = append(pathParts, e.from+" -> "+e.to)
	}
	path := strings.Join(pathParts, " -> ")
	if path == "" {
		path = rootOp
	}

	// Hash
	h := sha256.Sum256([]byte(path))
	hash := fmt.Sprintf("%x", h[:8]) // 16 hex chars

	// Collect unique services
	svcSet := make(map[string]struct{})
	for _, s := range spans {
		svcSet[s.service] = struct{}{}
	}
	services := make([]string, 0, len(svcSet))
	for svc := range svcSet {
		services = append(services, svc)
	}
	sort.Strings(services)

	return &traceFingerprint{
		hash:      hash,
		path:      path,
		rootOp:    rootOp,
		services:  services,
		spanCount: len(spans),
		edgeCount: len(edges),
	}
}

// inferParents returns a map of spanID -> parentSpanID.
// Uses actual parentSpanID from the span if present, otherwise falls back to
// timing containment (mirrors _infer_parent_id in trace_fingerprint.py).
func inferParents(spans []spanInfo, byID map[string]*spanInfo) map[string]string {
	parents := make(map[string]string, len(spans))
	for _, s := range spans {
		// Use actual parentSpanID if the parent exists in this trace
		if s.parentID != "" {
			if _, ok := byID[s.parentID]; ok {
				parents[s.spanID] = s.parentID
				continue
			}
		}
		// Fall back to timing containment
		bestParent := ""
		bestDuration := uint64(1<<63 - 1)
		for _, candidate := range spans {
			if candidate.spanID == s.spanID {
				continue
			}
			cEnd := candidate.startTimeNs + candidate.durationNs
			if candidate.startTimeNs <= s.startTimeNs && s.startTimeNs < cEnd {
				if candidate.durationNs < bestDuration {
					bestDuration = candidate.durationNs
					bestParent = candidate.spanID
				}
			}
		}
		parents[s.spanID] = bestParent
	}
	return parents
}

// errorSignature is the computed signature of a single error span.
type errorSignature struct {
	hash       string
	service    string
	errorType  string
	httpStatus string
	dbSystem   string
	operation  string
	callPath   string
}

const signatureTopFrames = 3

// buildErrorSignatures extracts error signatures from a set of spans.
// Mirrors build_error_signatures() in error_fingerprint.py.
func buildErrorSignatures(spans []spanInfo) []errorSignature {
	if len(spans) == 0 {
		return nil
	}

	byID := make(map[string]*spanInfo, len(spans))
	for i := range spans {
		byID[spans[i].spanID] = &spans[i]
	}
	parentMap := inferParents(spans, byID)

	var sigs []errorSignature
	for _, span := range spans {
		if !span.isError {
			continue
		}
		if isNoiseOperation(span.operation) {
			continue
		}

		errorType := firstNonEmpty(
			span.tags["exception.type"],
			span.tags["error.type"],
			span.tags["http.status_code"],
			"error",
		)
		httpStatus := span.tags["http.status_code"]
		dbSystem := span.tags["db.system"]

		// Walk ancestor chain to build call path
		var pathFrames []string
		cur := &span
		for len(pathFrames) < signatureTopFrames {
			pid := parentMap[cur.spanID]
			if pid == "" {
				break
			}
			parent, ok := byID[pid]
			if !ok {
				break
			}
			pathFrames = append([]string{parent.service + ":" + parent.operation}, pathFrames...)
			cur = parent
		}
		callPath := strings.Join(pathFrames, " -> ")

		sigStr := strings.Join([]string{span.service, errorType, httpStatus, span.operation, callPath}, "|")
		h := sha256.Sum256([]byte(sigStr))
		hash := fmt.Sprintf("%x", h[:8])

		sigs = append(sigs, errorSignature{
			hash:       hash,
			service:    span.service,
			errorType:  errorType,
			httpStatus: httpStatus,
			dbSystem:   dbSystem,
			operation:  span.operation,
			callPath:   callPath,
		})
	}
	return sigs
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
