package fingerprintprocessor

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// baselineFileAge returns the modification time of a file, or zero if unavailable.
func baselineFileAge(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// timeNow is a test hook; defaults to time.Now.
var timeNow = time.Now

// traceBaselineFile is the on-disk format for the trace baseline JSON.
type traceBaselineFile struct {
	Fingerprints map[string]*fingerprintEntry `json:"fingerprints"`
	Environment  string                       `json:"environment,omitempty"`
}

// errorBaselineFile is the on-disk format for the error baseline JSON.
type errorBaselineFile struct {
	Signatures  map[string]*errorSigEntry `json:"signatures"`
	Environment string                    `json:"environment,omitempty"`
}

// fingerprintEntry mirrors the Python baseline fingerprint dict.
type fingerprintEntry struct {
	Hash         string   `json:"hash"`
	Path         string   `json:"path"`
	RootOp       string   `json:"root_op"`
	Services     []string `json:"services"`
	SpanCount    int      `json:"span_count"`
	EdgeCount    int      `json:"edge_count"`
	Occurrences      int    `json:"occurrences"`
	AutoPromoted     bool   `json:"auto_promoted"`
	NoMissingService bool   `json:"no_missing_service,omitempty"`
	FirstSeen        string `json:"first_seen,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// errorSigEntry mirrors the Python error_baseline signature dict.
type errorSigEntry struct {
	Hash        string `json:"hash"`
	Service     string `json:"service"`
	ErrorType   string `json:"error_type"`
	HttpStatus  string `json:"http_status"`
	Operation   string `json:"operation"`
	CallPath    string `json:"call_path"`
	Occurrences int    `json:"occurrences"`
	FirstSeen   string `json:"first_seen,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// errorRateWindow tracks recent fire timestamps for a known error signature.
type errorRateWindow struct {
	// timestamps of recent occurrences (monotonically increasing)
	times []time.Time
	// baselineRate is occurrences/min computed from the first `windowSize` events
	// after initial promotion. Frozen once we have enough data.
	baselineRate float64
	frozen       bool
}

// baselineStore holds the in-memory view of baseline.json and error_baseline.json.
// It reloads from disk at BaselineReloadInterval.
type baselineStore struct {
	mu sync.RWMutex

	traceFingerprints map[string]*fingerprintEntry // hash -> entry
	errorSignatures   map[string]*errorSigEntry    // hash -> entry

	// errorRates tracks recent fire times for known error signatures.
	errorRatesMu sync.Mutex
	errorRates   map[string]*errorRateWindow // hash -> rate window

	tracePath   string
	errorPath   string
	reloadEvery time.Duration
	lastLoaded  time.Time

	// staleness tracking: count in-memory promotions since the file was last
	// reloaded and record the file's mod time at load time.
	promotionsMu        sync.Mutex
	promotionsSinceLoad int
	traceFileModTime    time.Time
}

func newBaselineStore(tracePath, errorPath string, reloadEvery time.Duration) *baselineStore {
	bs := &baselineStore{
		tracePath:         tracePath,
		errorPath:         errorPath,
		reloadEvery:       reloadEvery,
		traceFingerprints: make(map[string]*fingerprintEntry),
		errorSignatures:   make(map[string]*errorSigEntry),
		errorRates:        make(map[string]*errorRateWindow),
	}
	bs.reload()
	return bs
}

func (bs *baselineStore) reload() {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if tb := bs.loadTraceBaseline(); tb != nil {
		bs.traceFingerprints = tb
	}
	if eb := bs.loadErrorBaseline(); eb != nil {
		bs.errorSignatures = eb
	}
	bs.lastLoaded = time.Now()
	bs.traceFileModTime = baselineFileAge(bs.tracePath)

	// Reset promotion counter — we just loaded a fresh baseline.
	bs.promotionsMu.Lock()
	bs.promotionsSinceLoad = 0
	bs.promotionsMu.Unlock()
}

// maybeReload reloads from disk if the reload interval has elapsed.
// Returns true if a reload actually occurred.
func (bs *baselineStore) maybeReload() bool {
	bs.mu.RLock()
	due := time.Since(bs.lastLoaded) > bs.reloadEvery
	bs.mu.RUnlock()
	if due {
		bs.reload()
		return true
	}
	return false
}

func (bs *baselineStore) loadTraceBaseline() map[string]*fingerprintEntry {
	if bs.tracePath == "" {
		return nil
	}
	data, err := os.ReadFile(bs.tracePath)
	if err != nil {
		return nil
	}
	var raw traceBaselineFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	return raw.Fingerprints
}

func (bs *baselineStore) loadErrorBaseline() map[string]*errorSigEntry {
	if bs.errorPath == "" {
		return nil
	}
	data, err := os.ReadFile(bs.errorPath)
	if err != nil {
		return nil
	}
	var raw errorBaselineFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	return raw.Signatures
}

// promoteTrace adds a new fingerprint to the in-memory trace baseline and,
// if writeback is enabled, persists the full baseline back to disk.
// Returns true if the entry was newly added (not already present).
func (bs *baselineStore) promoteTrace(fp *traceFingerprint, writeback bool) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if _, exists := bs.traceFingerprints[fp.hash]; exists {
		return false
	}
	now := timeNow().UTC().Format(time.RFC3339)
	// Direct-service root ops (not rooted at api-gateway) are service-to-service
	// calls that don't represent user-facing traffic. Suppress MISSING_SERVICE
	// checks for them — they fire on uneven DaemonSet routing, not real outages.
	noMissing := !strings.HasPrefix(fp.rootOp, "api-gateway:")
	bs.traceFingerprints[fp.hash] = &fingerprintEntry{
		Hash:             fp.hash,
		Path:             fp.path,
		RootOp:           fp.rootOp,
		Services:         fp.services,
		SpanCount:        fp.spanCount,
		EdgeCount:        fp.edgeCount,
		Occurrences:      1,
		AutoPromoted:     true,
		NoMissingService: noMissing,
		FirstSeen:        now,
		UpdatedAt:        now,
	}
	if writeback && bs.tracePath != "" {
		_ = bs.writeTraceBaseline()
	}
	bs.promotionsMu.Lock()
	bs.promotionsSinceLoad++
	bs.promotionsMu.Unlock()
	return true
}

// promoteError adds a new error signature to the in-memory error baseline and,
// if writeback is enabled, persists the full baseline back to disk.
// Returns true if the entry was newly added (not already present).
func (bs *baselineStore) promoteError(sig errorSignature, writeback bool) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if _, exists := bs.errorSignatures[sig.hash]; exists {
		return false
	}
	now := timeNow().UTC().Format(time.RFC3339)
	bs.errorSignatures[sig.hash] = &errorSigEntry{
		Hash:        sig.hash,
		Service:     sig.service,
		ErrorType:   sig.errorType,
		HttpStatus:  sig.httpStatus,
		Operation:   sig.operation,
		CallPath:    sig.callPath,
		Occurrences: 1,
		FirstSeen:   now,
		UpdatedAt:   now,
	}
	if writeback && bs.errorPath != "" {
		_ = bs.writeErrorBaseline()
	}
	bs.promotionsMu.Lock()
	bs.promotionsSinceLoad++
	bs.promotionsMu.Unlock()
	return true
}

// StalenessInfo returns the file mod time and promotions-since-load count
// for use by the staleness checker in processor.go.
func (bs *baselineStore) stalenessInfo() (modTime time.Time, promotions int) {
	bs.promotionsMu.Lock()
	p := bs.promotionsSinceLoad
	bs.promotionsMu.Unlock()
	bs.mu.RLock()
	mt := bs.traceFileModTime
	bs.mu.RUnlock()
	return mt, p
}

// writeTraceBaseline serialises traceFingerprints to disk atomically.
// Caller must hold bs.mu (write lock).
func (bs *baselineStore) writeTraceBaseline() error {
	file := traceBaselineFile{Fingerprints: bs.traceFingerprints}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(bs.tracePath, data)
}

// writeErrorBaseline serialises errorSignatures to disk atomically.
// Caller must hold bs.mu (write lock).
func (bs *baselineStore) writeErrorBaseline() error {
	file := errorBaselineFile{Signatures: bs.errorSignatures}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(bs.errorPath, data)
}

// atomicWrite writes data to path via a temp file + rename to avoid
// partial writes being read by a concurrent reload.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// lookupTrace returns the baseline entry for a fingerprint hash, or nil if unknown.
func (bs *baselineStore) lookupTrace(hash string) *fingerprintEntry {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.traceFingerprints[hash]
}

// lookupError returns the baseline entry for an error sig hash, or nil if unknown.
func (bs *baselineStore) lookupError(hash string) *errorSigEntry {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.errorSignatures[hash]
}

// traceFingerprrintsByRootOp returns all established baseline fingerprints for a root_op.
func (bs *baselineStore) traceFingerprintsByRootOp(rootOp string, minOccurrences int) []*fingerprintEntry {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	var out []*fingerprintEntry
	for _, e := range bs.traceFingerprints {
		if e.RootOp == rootOp && (e.Occurrences >= minOccurrences || e.AutoPromoted) {
			out = append(out, e)
		}
	}
	return out
}

// isEmpty returns true if neither baseline has any entries.
func (bs *baselineStore) isEmpty() bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.traceFingerprints) == 0 && len(bs.errorSignatures) == 0
}

// counts returns the number of trace fingerprints and error signatures in the baseline.
func (bs *baselineStore) counts() (int, int) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return len(bs.traceFingerprints), len(bs.errorSignatures)
}

// maxBaselineSpanCount returns the maximum span_count seen across all established
// baseline fingerprints for the given root_op. Returns 0 if no established
// fingerprints exist for the root_op (unknown operation — don't suppress).
func (bs *baselineStore) maxBaselineSpanCount(rootOp string, minOccurrences int) int {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	max := 0
	for _, e := range bs.traceFingerprints {
		if e.RootOp == rootOp && e.Occurrences >= minOccurrences {
			if e.SpanCount > max {
				max = e.SpanCount
			}
		}
	}
	return max
}

// p10BaselineSpanCount returns the 10th-percentile span_count across all
// established baseline fingerprints for the given root_op. Using the 10th
// percentile rather than a fixed ratio of the max is more robust when a
// root_op has fingerprints with very different span counts (e.g. cached vs
// uncached code paths). Returns 0 if no established fingerprints exist.
func (bs *baselineStore) p10BaselineSpanCount(rootOp string, minOccurrences int) int {
	bs.mu.RLock()
	var counts []int
	for _, e := range bs.traceFingerprints {
		if e.RootOp == rootOp && (e.Occurrences >= minOccurrences || e.AutoPromoted) && e.SpanCount > 0 {
			counts = append(counts, e.SpanCount)
		}
	}
	bs.mu.RUnlock()

	if len(counts) == 0 {
		return 0
	}
	sort.Ints(counts)
	// 10th percentile index (floor)
	idx := int(float64(len(counts)-1) * 0.10)
	return counts[idx]
}

// recordErrorAndCheckSpike records a new occurrence of a known error signature
// and returns (spiked, currentRatePerMin, baselineRatePerMin).
// spiked is true when the current rate exceeds baselineRate * multiplier.
func (bs *baselineStore) recordErrorAndCheckSpike(hash string, window time.Duration, multiplier float64) (bool, float64, float64) {
	now := time.Now()

	bs.errorRatesMu.Lock()
	defer bs.errorRatesMu.Unlock()

	rw, ok := bs.errorRates[hash]
	if !ok {
		rw = &errorRateWindow{}
		bs.errorRates[hash] = rw
	}

	rw.times = append(rw.times, now)

	// Prune events older than 2x the window (keep some history for baseline calc)
	cutoff := now.Add(-2 * window)
	keep := 0
	for _, t := range rw.times {
		if t.After(cutoff) {
			break
		}
		keep++
	}
	rw.times = rw.times[keep:]

	// Count events within the current window
	windowCutoff := now.Add(-window)
	windowCount := 0
	for _, t := range rw.times {
		if t.After(windowCutoff) {
			windowCount++
		}
	}
	windowMins := window.Minutes()
	currentRate := float64(windowCount) / windowMins

	// Freeze baseline after we have at least 10 events in the long history
	if !rw.frozen && len(rw.times) >= 10 {
		// Use the oldest half of the stored events as a "quiet baseline"
		half := len(rw.times) / 2
		oldestHalf := rw.times[:half]
		if len(oldestHalf) >= 2 {
			dur := oldestHalf[len(oldestHalf)-1].Sub(oldestHalf[0]).Minutes()
			if dur > 0 {
				rw.baselineRate = float64(len(oldestHalf)) / dur
				rw.frozen = true
			}
		}
	}

	if rw.baselineRate <= 0 || !rw.frozen {
		return false, currentRate, 0
	}

	spiked := currentRate >= rw.baselineRate*multiplier
	return spiked, currentRate, rw.baselineRate
}

// establishedRootOps returns all distinct root_ops that have at least one
// established fingerprint in the baseline. Used by the missing-service checker.
func (bs *baselineStore) establishedRootOps(minOccurrences int) []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	// Track which root_ops are established, and whether any entry opts out of
	// MISSING_SERVICE checks via the no_missing_service flag.
	established := make(map[string]struct{})
	noMissing := make(map[string]struct{})
	for _, e := range bs.traceFingerprints {
		if e.Occurrences >= minOccurrences || e.AutoPromoted {
			established[e.RootOp] = struct{}{}
		}
		if e.NoMissingService {
			noMissing[e.RootOp] = struct{}{}
		}
	}
	result := make([]string, 0, len(established))
	for rootOp := range established {
		if _, skip := noMissing[rootOp]; !skip {
			result = append(result, rootOp)
		}
	}
	return result
}

// infraServices is the set of services that are always-on infrastructure
// components (service registry, config, etc.). Root ops whose baseline
// fingerprints contain ONLY these services are Eureka/Spring heartbeats —
// they fire on a 30s cadence and should not trigger MISSING_SERVICE alerts.
var infraServices = map[string]bool{
	"discovery-server": true,
	"config-server":    true,
	"eureka-server":    true,
}

// isInfraOnlyRootOp returns true when every established baseline fingerprint
// for rootOp contains only infrastructure services. These are heartbeat calls
// that are not user-facing and should not generate MISSING_SERVICE alerts.
func (bs *baselineStore) isInfraOnlyRootOp(rootOp string, minOccurrences int) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	found := false
	for _, e := range bs.traceFingerprints {
		if e.RootOp != rootOp {
			continue
		}
		if e.Occurrences < minOccurrences && !e.AutoPromoted {
			continue
		}
		found = true
		for _, svc := range e.Services {
			if !infraServices[svc] {
				return false // at least one non-infra service → not infra-only
			}
		}
	}
	return found // all services were infra (or no established fingerprints found)
}

// servicesForRootOp returns the union of all services seen across established
// baseline fingerprints for the given root_op.
func (bs *baselineStore) servicesForRootOp(rootOp string, minOccurrences int) []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	seen := make(map[string]struct{})
	for _, e := range bs.traceFingerprints {
		if e.RootOp != rootOp {
			continue
		}
		if e.Occurrences >= minOccurrences || e.AutoPromoted {
			for _, svc := range e.Services {
				seen[svc] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for svc := range seen {
		result = append(result, svc)
	}
	sort.Strings(result)
	return result
}
