package fingerprintprocessor

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

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
	Occurrences  int      `json:"occurrences"`
	AutoPromoted bool     `json:"auto_promoted"`
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
}

// baselineStore holds the in-memory view of baseline.json and error_baseline.json.
// It reloads from disk at BaselineReloadInterval.
type baselineStore struct {
	mu sync.RWMutex

	traceFingerprints map[string]*fingerprintEntry // hash -> entry
	errorSignatures   map[string]*errorSigEntry    // hash -> entry

	tracePath  string
	errorPath  string
	reloadEvery time.Duration
	lastLoaded time.Time
}

func newBaselineStore(tracePath, errorPath string, reloadEvery time.Duration) *baselineStore {
	bs := &baselineStore{
		tracePath:         tracePath,
		errorPath:         errorPath,
		reloadEvery:       reloadEvery,
		traceFingerprints: make(map[string]*fingerprintEntry),
		errorSignatures:   make(map[string]*errorSigEntry),
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
}

func (bs *baselineStore) maybeReload() {
	bs.mu.RLock()
	due := time.Since(bs.lastLoaded) > bs.reloadEvery
	bs.mu.RUnlock()
	if due {
		bs.reload()
	}
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
	bs.traceFingerprints[fp.hash] = &fingerprintEntry{
		Hash:         fp.hash,
		Path:         fp.path,
		RootOp:       fp.rootOp,
		Services:     fp.services,
		SpanCount:    fp.spanCount,
		EdgeCount:    fp.edgeCount,
		Occurrences:  1,
		AutoPromoted: true,
	}
	if writeback && bs.tracePath != "" {
		_ = bs.writeTraceBaseline()
	}
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
	bs.errorSignatures[sig.hash] = &errorSigEntry{
		Hash:        sig.hash,
		Service:     sig.service,
		ErrorType:   sig.errorType,
		HttpStatus:  sig.httpStatus,
		Operation:   sig.operation,
		CallPath:    sig.callPath,
		Occurrences: 1,
	}
	if writeback && bs.errorPath != "" {
		_ = bs.writeErrorBaseline()
	}
	return true
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
		if e.RootOp == rootOp && e.Occurrences >= minOccurrences {
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
