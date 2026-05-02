package fingerprintprocessor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// dedupClaim represents a single event claim written to the shared claim file.
type dedupClaim struct {
	EventType string    `json:"event_type"`
	Hash      string    `json:"hash"`
	ClaimedAt time.Time `json:"claimed_at"`
	PodID     string    `json:"pod_id"`
}

// dedupFile is the on-disk format for dedup_claims.json.
type dedupFile struct {
	Claims []dedupClaim `json:"claims"`
}

// eventDeduplicator uses a claim file on the shared /baseline/ volume to
// deduplicate events across DaemonSet pods. Before emitting an event, a pod
// tries to claim it by writing its (event_type, hash) pair with a timestamp.
// If another pod already holds a fresh claim, the current pod skips the emit.
//
// The claim file is a simple JSON array — no locking protocol is needed
// because file renames are atomic on Linux ext4/overlayfs, and the worst
// case is two pods racing to claim the same event, both writing and both
// emitting once. This is acceptable: the goal is to eliminate the steady-state
// 3× duplication on every drift event, not to provide strict exactly-once.
type eventDeduplicator struct {
	mu       sync.Mutex
	claims   map[string]dedupClaim // key: event_type+":"+hash
	path     string
	ttl      time.Duration
	podID    string
	lastLoad time.Time
	loadEvery time.Duration
}

func newEventDeduplicator(baselinePath, podID string, ttl time.Duration) *eventDeduplicator {
	dir := filepath.Dir(baselinePath)
	path := filepath.Join(dir, "dedup_claims.json")
	d := &eventDeduplicator{
		claims:    make(map[string]dedupClaim),
		path:      path,
		ttl:       ttl,
		podID:     podID,
		loadEvery: 5 * time.Second,
	}
	d.load()
	return d
}

// TryClaim returns true if this pod successfully claims the event and should
// emit it. Returns false if another pod already holds a fresh claim.
func (d *eventDeduplicator) TryClaim(eventType, hash string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Reload from disk periodically to see other pods' claims.
	if now.Sub(d.lastLoad) >= d.loadEvery {
		d.loadLocked()
	}

	key := eventType + ":" + hash
	if existing, ok := d.claims[key]; ok {
		if now.Sub(existing.ClaimedAt) < d.ttl {
			// Someone else (or us) already claimed this recently — skip.
			return existing.PodID == d.podID
		}
	}

	// Claim it.
	d.claims[key] = dedupClaim{
		EventType: eventType,
		Hash:      hash,
		ClaimedAt: now,
		PodID:     d.podID,
	}
	d.pruneLocked(now)
	d.saveLocked()
	return true
}

func (d *eventDeduplicator) load() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loadLocked()
}

func (d *eventDeduplicator) loadLocked() {
	d.lastLoad = time.Now()
	data, err := os.ReadFile(d.path)
	if err != nil {
		return
	}
	var f dedupFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	now := time.Now()
	for _, c := range f.Claims {
		if now.Sub(c.ClaimedAt) < d.ttl {
			key := c.EventType + ":" + c.Hash
			d.claims[key] = c
		}
	}
}

func (d *eventDeduplicator) pruneLocked(now time.Time) {
	for k, c := range d.claims {
		if now.Sub(c.ClaimedAt) >= d.ttl {
			delete(d.claims, k)
		}
	}
}

func (d *eventDeduplicator) saveLocked() {
	claims := make([]dedupClaim, 0, len(d.claims))
	for _, c := range d.claims {
		claims = append(claims, c)
	}
	data, err := json.Marshal(dedupFile{Claims: claims})
	if err != nil {
		return
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, d.path)
}
