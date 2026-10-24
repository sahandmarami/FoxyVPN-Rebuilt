package main

// Persistent per-key usage accountant (the Windows counterpart of the
// Android UsageAccountant): counts the bytes that flow through the local
// proxies against the volume plan of the activated key, survives restarts
// and shows the same «X از Y مصرف شده» bar as the Android app.
//
// The authoritative quota remains Mozilla's X-Quota reporting (see
// Snapshot.usedLimitBytes); this store is the fallback that keeps the bar
// honest when Guardian headers are not (yet) available.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type UsageRecord struct {
	KeyID    string `json:"key_id"`
	Used     int64  `json:"used_bytes"`
	ResetAt  int64  `json:"reset_at,omitempty"`
	AnchorTS int64  `json:"anchor_ts,omitempty"` // first activation of this key (monthly anchor)
}

type UsageStore struct {
	mu       sync.Mutex
	path     string
	rec      UsageRecord
	lastSeen int64 // last counter snapshot already folded into rec.Used
	dirty    bool
}

func NewUsageStore(dataDir string) *UsageStore {
	return &UsageStore{path: filepath.Join(dataDir, "usage.json")}
}

func (u *UsageStore) load() {
	raw, err := os.ReadFile(u.path)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &u.rec)
}

func (u *UsageStore) flushLocked() {
	if !u.dirty {
		return
	}
	raw, err := json.MarshalIndent(&u.rec, "", "  ")
	if err == nil {
		if os.WriteFile(u.path, raw, 0o600) == nil {
			u.dirty = false
		}
	}
}

// Attach switches accounting to a key. A new key starts from zero unless we
// already have history for its id.
func (u *UsageStore) Attach(keyID string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.load()
	if u.rec.KeyID != keyID {
		anchor := time.Now().Unix()
		u.rec = UsageRecord{KeyID: keyID, AnchorTS: anchor}
		u.dirty = true
	}
	if u.rec.AnchorTS == 0 {
		u.rec.AnchorTS = time.Now().Unix()
		u.dirty = true
	}
	u.lastSeen = 0
	u.flushLocked()
}

// AddDelta folds a fresh traffic counter reading into the stored total.
func (u *UsageStore) AddDelta(totalUp, totalDown int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	total := totalUp + totalDown
	if total < u.lastSeen {
		u.lastSeen = 0 // counters were reset (new session)
	}
	delta := total - u.lastSeen
	if delta <= 0 {
		return
	}
	u.lastSeen = total
	u.rec.Used += delta
	u.dirty = true
	if time.Now().Unix()%10 == 0 { // persist every ~10 s, always on key events
		u.flushLocked()
	}
}

// Flush forces a persist (disconnect, exit, key change).
func (u *UsageStore) Flush() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.flushLocked()
}

// ApplyServerReset switches the stored total to the authoritative reset
// reported by Guardian's X-Quota-Reset headers (monthly re-grant).
func (u *UsageStore) ApplyServerReset(resetAt int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if resetAt <= 0 || u.rec.ResetAt == resetAt {
		return
	}
	now := time.Now().Unix()
	if u.rec.ResetAt > 0 && now >= u.rec.ResetAt && u.rec.ResetAt != resetAt {
		// the previous period has ended: usage restarts from zero
		u.rec.Used = 0
	}
	u.rec.ResetAt = resetAt
	u.dirty = true
	u.flushLocked()
}

// ResetTo syncs the local total with an authoritative used-bytes figure
// (limit - remaining from Guardian), keeping local counting as the delta feed.
func (u *UsageStore) ResetTo(keyID string, used int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.load()
	if u.rec.KeyID != keyID {
		return
	}
	if used >= 0 && used != u.rec.Used {
		u.rec.Used = used
		u.dirty = true
		u.flushLocked()
	}
}

func (u *UsageStore) Used() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rec.Used
}

func (u *UsageStore) ResetAt() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.rec.ResetAt
}
