package fingerprintprocessor

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// fingerprintEntry mirrors the Python baseline fingerprint dict.
type fingerprintEntry struct {
	Hash          string   `json:"hash"`
	Path          string   `json:"path"`
	RootOp        string   `json:"root_op"`
	Services      []string `json:"services"`
	Occurrences   int      `json:"occurrences"`
	AutoPromoted  bool     `json:"auto_promoted"`
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
	var raw struct {
		Fingerprints map[string]*fingerprintEntry `json:"fingerprints"`
	}
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
	var raw struct {
		Signatures map[string]*errorSigEntry `json:"signatures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	return raw.Signatures
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
