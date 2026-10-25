package main

// Live usage reporting through the private GitHub gist — a faithful port of
// the Android GistReporter with its two hard rules:
//
//  1. Usage reporting is NEVER held hostage by registry.json readability —
//     even when the registry cannot be read, usage is still written.
//  2. Every failure is classified (auth / permission / missing gist /
//     network / rate limit) so the UI can show the real reason instead of
//     a generic "check your internet".
//
// The gist holds two files:
//
//      registry.json -> { "keys": [ {id, name, gb, exp, revoked, issued, reset} ] }  (FoxyKeygen)
//      usage.json    -> { "usages": { <id>: {used, status, updated, periodStart} } } (clients)
//
// Revocation verdicts are STRICT: only an explicit revoked=true read from a
// fully-readable registry counts. Absence, partial reads and network flakes
// never revoke a key.

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strconv"
        "sync"
        "sync/atomic"
        "time"
)

type SyncIssue int

const (
        SyncNone SyncIssue = iota
        SyncNetwork
        SyncAuth
        SyncForbidden
        SyncRateLimited
        SyncNotFound
)

func (i SyncIssue) Label() string {
        switch i {
        case SyncNetwork:
                return "شبکه در دسترس نیست؛ با اتصال VPN دوباره تلاش می‌شود"
        case SyncAuth:
                return "توکن مخزن نامعتبر است — کلید جدید از کلیدساز بگیرید"
        case SyncForbidden:
                return "توکن دسترسی Gist ندارد — در کلیدساز مخزن را دوباره وصل کنید"
        case SyncRateLimited:
                return "سقف درخواست گیت‌هاب پر شده؛ کمی بعد تلاش می‌شود"
        case SyncNotFound:
                return "مخزن گزارش پیدا نشد — کلید جدید از کلیدساز بگیرید"
        }
        return ""
}

type SyncResult struct {
        Revoked          bool
        Present          bool
        RegistryReadable bool
        Reported         bool
        ReportedUsed     int64
        ReportedUpdated  int64
        ResetAt          int64
        Issue            SyncIssue
}

type GistReporter struct {
        baseURL string // overridable for tests (mock GitHub API)

        inFlight     atomic.Bool
        preferTunnel atomic.Bool

        lastSyncOkMu   sync.Mutex
        lastSyncOkAt   int64
        lastIssueLabel string
}

func NewGistReporter() *GistReporter {
        r := &GistReporter{baseURL: "https://api.github.com"}
        r.preferTunnel.Store(true)
        return r
}

func (r *GistReporter) LastSyncOkAt() int64 {
        r.lastSyncOkMu.Lock()
        defer r.lastSyncOkMu.Unlock()
        return r.lastSyncOkAt
}

func (r *GistReporter) LastIssueLabel() string {
        r.lastSyncOkMu.Lock()
        defer r.lastSyncOkMu.Unlock()
        return r.lastIssueLabel
}

func (r *GistReporter) noteSuccess() {
        r.lastSyncOkMu.Lock()
        r.lastSyncOkAt = time.Now().UnixMilli()
        r.lastIssueLabel = ""
        r.lastSyncOkMu.Unlock()
}

func (r *GistReporter) noteFailure(issue SyncIssue) {
        r.lastSyncOkMu.Lock()
        if issue != SyncNone {
                r.lastIssueLabel = issue.Label()
        }
        r.lastSyncOkMu.Unlock()
}

// tunnelSocksPort is set by the core while the VPN is up; gist traffic then
// prefers the loopback SOCKS route (some networks refuse api.github.com on
// the raw route) and falls back to direct.
var tunnelSocksPort atomic.Int64

func (r *GistReporter) client(socks bool, timeout time.Duration) *http.Client {
        tr := &http.Transport{
                MaxIdleConns:        4,
                IdleConnTimeout:     30 * time.Second,
                TLSHandshakeTimeout: 10 * time.Second,
                ForceAttemptHTTP2:   true,
        }
        if socks {
                port := tunnelSocksPort.Load()
                if port <= 0 {
                        return nil
                }
                tr.Proxy = func(*http.Request) (*url.URL, error) {
                        return url.Parse("socks5://127.0.0.1:" + strconv.FormatInt(port, 10))
                }
        }
        return &http.Client{Timeout: timeout, Transport: tr}
}

// execute sends a request over the remembered-good route first and falls
// back to the other one. Returns nil only when BOTH routes failed.
func (r *GistReporter) execute(req *http.Request, timeout time.Duration) *http.Response {
        prefer := r.preferTunnel.Load()
        var first, second *http.Client
        if prefer {
                first, second = r.client(true, timeout), r.client(false, timeout)
        } else {
                first, second = r.client(false, timeout), r.client(true, timeout)
        }
        if first != nil {
                if resp, err := first.Do(req.Clone(req.Context())); err == nil {
                        r.preferTunnel.Store(first.Transport != nil && socksTransport(first))
                        return resp
                }
        }
        if second != nil {
                if resp, err := second.Do(req.Clone(req.Context())); err == nil {
                        r.preferTunnel.Store(socksTransport(second))
                        return resp
                }
        }
        return nil
}

func socksTransport(c *http.Client) bool {
        tr, ok := c.Transport.(*http.Transport)
        if !ok || tr.Proxy == nil {
                return false
        }
        u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "api.github.com"}})
        if err != nil || u == nil {
                return false
        }
        return u.Scheme == "socks5" || u.Scheme == "socks5h"
}

type gistSnapshot struct {
        registry map[string]any // nil = could not actually read registry.json
        usage    map[string]any
}

type gistFetch struct {
        snapshot *gistSnapshot
        issue    SyncIssue
        detail   string
}

func classifyHTTP(code int) SyncIssue {
        switch code {
        case 401:
                return SyncAuth
        case 404:
                return SyncNotFound
        case 429:
                return SyncRateLimited
        case 403:
                return SyncForbidden
        }
        return SyncNetwork
}

func (r *GistReporter) gistURL(path string) string { return r.baseURL + path }

func (r *GistReporter) fetchGist(ctx ReportContext) gistFetch {
        req, err := http.NewRequest("GET", r.gistURL("/gists/"+ctx.GistID), nil)
        if err != nil {
                return gistFetch{issue: SyncNetwork, detail: err.Error()}
        }
        req.Header.Set("Authorization", "Bearer "+ctx.Token)
        req.Header.Set("Accept", "application/vnd.github+json")
        req.Header.Set("User-Agent", "FoxyVPN-Key")
        resp := r.execute(req, 20*time.Second)
        if resp == nil {
                return gistFetch{issue: SyncNetwork, detail: "no response on either route"}
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                return gistFetch{issue: classifyHTTP(resp.StatusCode), detail: fmt.Sprintf("HTTP %d on gist read", resp.StatusCode)}
        }
        body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
        if err != nil {
                return gistFetch{issue: SyncNetwork, detail: "body read failed"}
        }
        var gist struct {
                Files map[string]struct {
                        Content   string `json:"content"`
                        Truncated bool   `json:"truncated"`
                        RawURL    string `json:"raw_url"`
                        Type      string `json:"type"`
                } `json:"files"`
        }
        if json.Unmarshal(body, &gist) != nil {
                return gistFetch{issue: SyncNetwork, detail: "gist response was not JSON"}
        }
        snap := gistSnapshot{}
        // registry == nil means "could not actually read registry.json" — a broken
        // fetch, NOT an empty registry.
        if reg := fileContent(r, gist.Files, "registry.json", ctx); reg != nil {
                var m map[string]any
                if json.Unmarshal(reg, &m) == nil {
                        snap.registry = m
                } else {
                        snap.registry = nil
                }
        }
        if us := fileContent(r, gist.Files, "usage.json", ctx); us != nil {
                var m map[string]any
                if json.Unmarshal(us, &m) == nil {
                        snap.usage = m
                }
        }
        if snap.usage == nil {
                snap.usage = map[string]any{"usages": map[string]any{}}
        }
        return gistFetch{snapshot: &snap, issue: SyncNone, detail: "ok"}
}

func fileContent(r *GistReporter, files map[string]struct {
        Content   string `json:"content"`
        Truncated bool   `json:"truncated"`
        RawURL    string `json:"raw_url"`
        Type      string `json:"type"`
}, name string, ctx ReportContext) []byte {
        f, ok := files[name]
        if !ok || f.Type != "file" {
                return nil
        }
        // The gist API response already carries small file contents inline — use
        // that first; gist.githubusercontent.com (a different CDN some networks
        // cannot reach) is only a fallback.
        if f.Content != "" && !f.Truncated {
                return []byte(f.Content)
        }
        if f.RawURL == "" {
                if f.Content != "" {
                        return []byte(f.Content)
                }
                return nil
        }
        req, err := http.NewRequest("GET", f.RawURL, nil)
        if err != nil {
                return nil
        }
        req.Header.Set("Authorization", "Bearer "+ctx.Token)
        req.Header.Set("User-Agent", "FoxyVPN-Key")
        resp := r.execute(req, 15*time.Second)
        if resp == nil {
                return nil
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                return nil
        }
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
        return b
}

func (r *GistReporter) patchGist(ctx ReportContext, fileName string, content []byte) int {
        payload := map[string]any{
                "files": map[string]any{
                        fileName: map[string]any{"content": string(content)},
                },
        }
        raw, _ := json.Marshal(payload)
        req, err := http.NewRequest("PATCH", r.gistURL("/gists/"+ctx.GistID), bytes.NewReader(raw))
        if err != nil {
                return -1
        }
        req.Header.Set("Authorization", "Bearer "+ctx.Token)
        req.Header.Set("Accept", "application/vnd.github+json")
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", "FoxyVPN-Key")
        resp := r.execute(req, 25*time.Second)
        if resp == nil {
                return -1
        }
        defer resp.Body.Close()
        io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
        return resp.StatusCode
}

// usageMap returns the mutable "usages" object of a usage doc.
func usageMap(usage map[string]any) map[string]any {
        if us, ok := usage["usages"].(map[string]any); ok {
                return us
        }
        us := map[string]any{}
        usage["usages"] = us
        return us
}

func entryLong(v any) int64 {
        switch n := v.(type) {
        case float64:
                return int64(n)
        case int64:
                return n
        case int:
                return int64(n)
        case json.Number:
                i, _ := n.Int64()
                return i
        }
        return 0
}

// patchUsage writes usedBytes into the usage map and patches the gist.
// Monotonic: a client never LOWERS the stored usage — a friend who just
// reinstalled (counter at 0) must not wipe the dashboard's real number.
func (r *GistReporter) patchUsage(usage map[string]any, ctx ReportContext, usedBytes int64, status string) int {
        us := usageMap(usage)
        previousUsed := int64(0)
        if prev, ok := us[ctx.KeyID].(map[string]any); ok {
                previousUsed = entryLong(prev["used"])
        }
        entry := map[string]any{
                "used":    max64(usedBytes, previousUsed),
                "status":  status,
                "updated": time.Now().Unix(),
        }
        if ps, ok := us[ctx.KeyID].(map[string]any); ok {
                if psVal := entryLong(ps["periodStart"]); psVal > 0 {
                        entry["periodStart"] = psVal
                }
        }
        us[ctx.KeyID] = entry
        raw, err := json.Marshal(usage)
        if err != nil {
                return -1
        }
        return r.patchGist(ctx, "usage.json", raw)
}

// Sync performs one combined revocation-check + usage-report round trip.
// Returns nil ONLY when the gist itself was unreachable.
func (r *GistReporter) Sync(ctx ReportContext, usedBytes, limitBytes int64, expired bool) *SyncResult {
        if !r.inFlight.CompareAndSwap(false, true) {
                return nil
        }
        defer r.inFlight.Store(false)
        fetch := r.fetchGist(ctx)
        if fetch.snapshot == nil {
                r.noteFailure(fetch.issue)
                return nil
        }
        var revoked, present, registryReadable bool
        var resetAt int64
        if keys, ok := fetch.snapshot.registry["keys"].([]any); ok {
                registryReadable = true
                for _, kv := range keys {
                        entry, ok := kv.(map[string]any)
                        if !ok || entry["id"] != ctx.KeyID {
                                continue
                        }
                        present = true
                        revoked, _ = entry["revoked"].(bool)
                        resetAt = entryLong(entry["reset"])
                        break
                }
        }
        status := "active"
        switch {
        case revoked:
                status = "revoked"
        case expired:
                status = "expired"
        case limitBytes > 0 && usedBytes >= limitBytes:
                status = "exhausted"
        }
        code := r.patchUsage(fetch.snapshot.usage, ctx, usedBytes, status)
        reported := code >= 200 && code <= 299
        issue := SyncNone
        if !reported {
                issue = classifyHTTP(code)
        }
        if reported {
                r.noteSuccess()
        } else {
                r.noteFailure(issue)
        }
        usedExternal := int64(0)
        updated := int64(0)
        if us, ok := fetch.snapshot.usage["usages"].(map[string]any); ok {
                if entry, ok := us[ctx.KeyID].(map[string]any); ok {
                        usedExternal = entryLong(entry["used"])
                        updated = entryLong(entry["updated"])
                }
        }
        return &SyncResult{
                Revoked:          revoked,
                Present:          present,
                RegistryReadable: registryReadable,
                Reported:         reported,
                ReportedUsed:     usedExternal,
                ReportedUpdated:  updated,
                ResetAt:          resetAt,
                Issue:            issue,
        }
}

// IsRevoked is the strict verdict used before connecting: true ONLY when a
// fully-read registry explicitly flags this key revoked.
func (r *GistReporter) IsRevoked(ctx ReportContext) bool {
        fetch := r.fetchGist(ctx)
        if fetch.snapshot == nil || fetch.snapshot.registry == nil {
                return false
        }
        keys, ok := fetch.snapshot.registry["keys"].([]any)
        if !ok {
                return false
        }
        for _, kv := range keys {
                entry, ok := kv.(map[string]any)
                if !ok || entry["id"] != ctx.KeyID {
                        continue
                }
                rev, _ := entry["revoked"].(bool)
                return rev
        }
        // The registry answered but does not list this key: a deleted key — or a
        // recreated/partial registry. Absence is NOT revocation.
        return false
}

// FetchReportedUsage returns the usage this key last reported (for resuming
// the counter after a reinstall).
func (r *GistReporter) FetchReportedUsage(ctx ReportContext) (int64, bool) {
        fetch := r.fetchGist(ctx)
        if fetch.snapshot == nil {
                return 0, false
        }
        us, ok := fetch.snapshot.usage["usages"].(map[string]any)
        if !ok {
                return 0, false
        }
        entry, ok := us[ctx.KeyID].(map[string]any)
        if !ok {
                return 0, false
        }
        used := entryLong(entry["used"])
        if used <= 0 {
                return 0, false
        }
        return used, true
}

// PushPeriodReset authoritatively zeros this key's usage entry for the new
// monthly period (the one legitimate way a client lowers the stored value).
func (r *GistReporter) PushPeriodReset(ctx ReportContext, periodStartSec int64) bool {
        fetch := r.fetchGist(ctx)
        if fetch.snapshot == nil {
                return false
        }
        us := usageMap(fetch.snapshot.usage)
        us[ctx.KeyID] = map[string]any{
                "used":        0,
                "status":      "active",
                "updated":     time.Now().Unix(),
                "periodStart": periodStartSec,
        }
        raw, err := json.Marshal(fetch.snapshot.usage)
        if err != nil {
                return false
        }
        code := r.patchGist(ctx, "usage.json", raw)
        return code >= 200 && code <= 299
}
