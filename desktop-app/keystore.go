package main

// Activated-key persistence: the raw key, the per-key usage ledger (which
// survives re-activation), the monthly quota-reset bookkeeping and the
// revocation flag. Mirrors the Android ActivatedKeyStore semantics:
//   - usage is monotonic per key (max wins) so reinstalling or editing one
//     file never resets the counter,
//   - a monthly reset is the only operation allowed to go back to zero and
//     stamps periodStart so stale previous-period numbers can be dropped,
//   - external (gist) usage only ever RAISES the counter.

import (
        "encoding/json"
        "os"
        "path/filepath"
        "sync"
        "time"
)

type KeyUsageState struct {
        UsedBytes     int64
        LastSeenClock int64
}

type keyStoreFile struct {
        RawKey   string `json:"raw_key"`
        SysProxy *bool  `json:"sys_proxy,omitempty"`
        Country  string `json:"country,omitempty"`
        City     string `json:"city,omitempty"`
        AutoConn *bool  `json:"auto_connect,omitempty"`
}

type ledgerEntry struct {
        Used        int64 `json:"used"`
        Clock       int64 `json:"clock"`
        PeriodStart int64 `json:"period_start,omitempty"`
        ResetAt     int64 `json:"reset_at,omitempty"`
        Revoked     bool  `json:"revoked,omitempty"`
}

type KeyStore struct {
        mu   sync.Mutex
        path string // key.json
        lead string // ledger.json

        key      *QuotaKey
        autoSys  bool
        country  string
        city     string
        autoConn bool
}

func NewKeyStore(dataDir string) *KeyStore {
        return &KeyStore{
                path: filepath.Join(dataDir, "key.json"),
                lead: filepath.Join(dataDir, "ledger.json"),
        }
}

func (s *KeyStore) Load() {
        s.mu.Lock()
        defer s.mu.Unlock()
        raw, err := os.ReadFile(s.path)
        if err == nil {
                var st keyStoreFile
                if json.Unmarshal(raw, &st) == nil && st.RawKey != "" {
                        if k, perr := ParseKey(st.RawKey); perr == nil {
                                s.key = k
                        }
                }
                if st.SysProxy != nil {
                        s.autoSys = *st.SysProxy
                } else {
                        s.autoSys = true // the new mechanism: system proxy is ON by default
                }
                s.country, s.city = st.Country, st.City
                if st.AutoConn != nil {
                        s.autoConn = *st.AutoConn
                } else {
                        s.autoConn = true
                }
        } else {
                s.autoSys, s.autoConn = true, true
        }
}

func (s *KeyStore) Save() {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.saveLocked()
}

func (s *KeyStore) saveLocked() {
        var st keyStoreFile
        if s.key != nil {
                st.RawKey = s.key.Raw
        }
        sysProxy := s.autoSys
        st.SysProxy = &sysProxy
        st.Country, st.City = s.country, s.city
        autoConn := s.autoConn
        st.AutoConn = &autoConn
        raw, _ := json.MarshalIndent(st, "", "  ")
        _ = os.WriteFile(s.path, raw, 0o600)
}

func (s *KeyStore) Key() *QuotaKey {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.key
}

func (k *QuotaKey) ReportContextOrZero() (ReportContext, bool) { return k.ReportContext() }

// SetKey activates a key. Usage survives: the ledger is keyed by key id.
func (s *KeyStore) SetKey(k *QuotaKey) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.key = k
        s.saveLocked()
}

// ClearKey forgets the active key only; the ledger deliberately survives so
// re-adding the same key resumes the counter.
func (s *KeyStore) ClearKey() {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.key = nil
        s.saveLocked()
}

// ---------- usage ledger ----------

func (s *KeyStore) readLedger(keyID string) ledgerEntry {
        raw, err := os.ReadFile(s.lead)
        if err != nil {
                return ledgerEntry{}
        }
        var m map[string]ledgerEntry
        if json.Unmarshal(raw, &m) != nil {
                return ledgerEntry{}
        }
        return m[keyID]
}

func (s *KeyStore) writeLedger(keyID string, e ledgerEntry) {
        m := map[string]ledgerEntry{}
        if raw, err := os.ReadFile(s.lead); err == nil {
                _ = json.Unmarshal(raw, &m)
        }
        m[keyID] = e
        raw, _ := json.MarshalIndent(m, "", "  ")
        _ = os.WriteFile(s.lead, raw, 0o600)
}

// Usage returns the monotonic per-key counter.
func (s *KeyStore) Usage(keyID string) KeyUsageState {
        s.mu.Lock()
        defer s.mu.Unlock()
        e := s.readLedger(keyID)
        return KeyUsageState{UsedBytes: max64(e.Used, 0), LastSeenClock: e.Clock}
}

// SaveUsage is monotonic: the counter never goes backwards.
func (s *KeyStore) SaveUsage(keyID string, used int64) {
        s.mu.Lock()
        defer s.mu.Unlock()
        cur := s.readLedger(keyID)
        e := ledgerEntry{
                Used:        max64(cur.Used, used),
                Clock:       max64(cur.Clock, time.Now().UnixMilli()),
                PeriodStart: cur.PeriodStart,
                ResetAt:     cur.ResetAt,
                Revoked:     cur.Revoked,
        }
        s.writeLedger(keyID, e)
}

// IngestExternalUsage raises the counter to a number another device reported
// (multi-device resume). Guarded by the period: numbers from a previous
// period are dropped.
func (s *KeyStore) IngestExternalUsage(keyID string, used int64, updatedSec int64, periodStart int64) {
        if used <= 0 {
                return
        }
        s.mu.Lock()
        defer s.mu.Unlock()
        cur := s.readLedger(keyID)
        if periodStart > 0 && cur.PeriodStart > periodStart {
                return // stale previous-period number
        }
        if updatedSec > 0 && cur.Clock/1000 > updatedSec+60 {
                return // our own record is newer than what the gist holds
        }
        if used <= cur.Used {
                return
        }
        cur.Used = used
        cur.Clock = time.Now().UnixMilli()
        s.writeLedger(keyID, cur)
}

// ResetUsage is the monthly re-grant: the one NON-monotonic operation. It
// zeros every copy and stamps the new period start.
func (s *KeyStore) ResetUsage(keyID string, periodStartSec int64) {
        s.mu.Lock()
        defer s.mu.Unlock()
        cur := s.readLedger(keyID)
        s.writeLedger(keyID, ledgerEntry{
                Used:        0,
                Clock:       time.Now().UnixMilli(),
                PeriodStart: periodStartSec,
                ResetAt:     cur.ResetAt,
        })
}

func (s *KeyStore) PeriodStart(keyID string) int64 {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.readLedger(keyID).PeriodStart
}

// ---------- revocation / reset stamps ----------

func (s *KeyStore) SetResetAt(keyID string, resetAt int64) {
        if resetAt <= 0 {
                return
        }
        s.mu.Lock()
        defer s.mu.Unlock()
        cur := s.readLedger(keyID)
        if cur.ResetAt == resetAt {
                return
        }
        cur.ResetAt = resetAt
        s.writeLedger(keyID, cur)
}

func (s *KeyStore) ResetAt(keyID string) int64 {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.readLedger(keyID).ResetAt
}

// ---------- settings ----------

func (s *KeyStore) AutoSysProxy() bool   { s.mu.Lock(); defer s.mu.Unlock(); return s.autoSys }
func (s *KeyStore) SetAutoSysProxy(on bool) {
        s.mu.Lock(); s.autoSys = on; s.saveLocked(); s.mu.Unlock()
}
func (s *KeyStore) AutoConnect() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.autoConn }
func (s *KeyStore) SetAutoConnect(on bool) {
        s.mu.Lock(); s.autoConn = on; s.saveLocked(); s.mu.Unlock()
}
func (s *KeyStore) ChosenCountry() (string, string) {
        s.mu.Lock(); defer s.mu.Unlock(); return s.country, s.city
}
func (s *KeyStore) SetChosenCountry(country, city string) {
        s.mu.Lock(); s.country, s.city = country, city; s.saveLocked(); s.mu.Unlock()
}

// ---------- national-code book ----------

// codes.json maps the 10-digit «کد ملی» shortcut to the full raw key, so the
// owner can re-activate a key on this device by typing the short code.
func (s *KeyStore) codesPath() string { return filepath.Join(filepath.Dir(s.path), "codes.json") }

func (s *KeyStore) SaveCode(code, rawKey string) {
        if code == "" || rawKey == "" {
                return
        }
        m := map[string]string{}
        if raw, err := os.ReadFile(s.codesPath()); err == nil {
                _ = json.Unmarshal(raw, &m)
        }
        m[code] = rawKey
        data, _ := json.MarshalIndent(m, "", "  ")
        _ = os.WriteFile(s.codesPath(), data, 0o600)
}

func (s *KeyStore) LookupCode(code string) (string, bool) {
        raw, err := os.ReadFile(s.codesPath())
        if err != nil {
                return "", false
        }
        var m map[string]string
        if json.Unmarshal(raw, &m) != nil {
                return "", false
        }
        v, ok := m[code]
        return v, ok && v != ""
}

func max64(a, b int64) int64 {
        if a > b {
                return a
        }
        return b
}
