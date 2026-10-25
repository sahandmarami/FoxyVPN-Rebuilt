package main

// End-to-end tests for the new key mechanism: a mock GitHub gist plays the
// usage registry, a mock FxA plays the token endpoint, a mock Guardian plays
// fpn/token, and the existing mock H2 edge plays the Fastly edge. The full
// Activate -> Connect -> traffic -> usage-report -> revoke lifecycle runs
// against them exactly like in the field.

import (
        "crypto/ed25519"
        "crypto/x509"
        "encoding/json"
        "fmt"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "sync"
        "testing"
        "time"
)

// ---------- test key minting ----------

var testPriv ed25519PrivateKey

type ed25519PrivateKey struct{ seed []byte }

func mintTestKey(t *testing.T, payload QuotaKeyPayload) string {
        t.Helper()
        priv := ed25519.PrivateKey(testPriv.seed)
        if len(priv) != ed25519.PrivateKeySize {
                t.Fatal("bad test signing key")
        }
        payloadJSON, err := json.Marshal(payload)
        if err != nil {
                t.Fatal(err)
        }
        payloadB64 := b64urlEncode(payloadJSON)
        sig := ed25519.Sign(priv, []byte(payloadB64))
        return "FV1." + payloadB64 + "." + b64urlEncode(sig)
}
// ---------- mock gist ----------

type mockGist struct {
        mu       sync.Mutex
        registry map[string]any
        usage    map[string]any
        patches  int
}

func (g *mockGist) handler() http.Handler {
        mux := http.NewServeMux()
        mux.HandleFunc("/gists/", func(w http.ResponseWriter, r *http.Request) {
                g.mu.Lock()
                defer g.mu.Unlock()
                switch r.Method {
                case "GET":
                        w.Header().Set("Content-Type", "application/json")
                        json.NewEncoder(w).Encode(map[string]any{
                                "files": map[string]any{
                                        "registry.json": map[string]any{"content": mustJSON(g.registry), "type": "file"},
                                        "usage.json":    map[string]any{"content": mustJSON(g.usage), "type": "file"},
                                },
                        })
                case "PATCH":
                        var body struct {
                                Files map[string]struct {
                                        Content string `json:"content"`
                                } `json:"files"`
                        }
                        json.NewDecoder(r.Body).Decode(&body)
                        for name, f := range body.Files {
                                switch name {
                                case "registry.json":
                                        var m map[string]any
                                        json.Unmarshal([]byte(f.Content), &m)
                                        g.registry = m
                                case "usage.json":
                                        var m map[string]any
                                        json.Unmarshal([]byte(f.Content), &m)
                                        g.usage = m
                                        g.patches++
                                }
                        }
                        w.WriteHeader(200)
                        w.Write([]byte(`{}`))
                default:
                        w.WriteHeader(405)
                }
        })
        return mux
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---------- mock FxA + Guardian ----------

func startMockFxaGuardian(t *testing.T, quotaRemaining int64) (fxaURL, guardianURL string) {
        t.Helper()
        mux := http.NewServeMux()
        // FxA refresh_token grant
        mux.HandleFunc("/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
                var in map[string]any
                json.NewDecoder(r.Body).Decode(&in)
                if in["grant_type"] != "refresh_token" || in["refresh_token"] == "" {
                        w.WriteHeader(400)
                        w.Write([]byte(`{"errno":108,"message":"bad request"}`))
                        return
                }
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(map[string]any{
                        "access_token":  "mock-access-token-1",
                        "refresh_token": "mock-refresh-token-rotated",
                        "expires_in":    3600,
                        "scope":         oauthScope,
                })
        })
        // Guardian proxy pass
        mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
                if r.Header.Get("Authorization") != "Bearer mock-access-token-1" {
                        w.WriteHeader(401)
                        w.Write([]byte(`{"errno":110,"message":"unauthorized"}`))
                        return
                }
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("X-Quota-Limit", "5368709120")
                w.Header().Set("X-Quota-Remaining", fmt.Sprint(quotaRemaining))
                json.NewEncoder(w).Encode(map[string]any{
                        "token":      "mock-proxy-pass.jwt.sig",
                        "expires_at": time.Now().Add(10 * time.Minute).Unix(),
                })
        })
        mux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
                json.NewEncoder(w).Encode(map[string]any{"subscribed": true, "uid": "mock-uid", "limited_bandwidth": true})
        })
        mux.HandleFunc("/api/v1/fpn/status", func(w http.ResponseWriter, r *http.Request) {
                json.NewEncoder(w).Encode(map[string]any{"subscribed": true, "uid": "mock-uid", "limited_bandwidth": true})
        })
        srv := httptest.NewServer(mux)
        t.Cleanup(srv.Close)
        // split: FxA under /v1, Guardian under /api — same server for both
        return srv.URL + "/v1", srv.URL
}

// ---------- mock server list (points candidates at the mock edge) ----------

func startMockServerList(t *testing.T, edgeHost string, edgePort int) string {
        t.Helper()
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set("Content-Type", "application/json")
                w.Write([]byte(mockServerRecords(edgeHost, edgePort)))
        }))
        t.Cleanup(srv.Close)
        return srv.URL
}

func mockServerRecords(edgeHost string, edgePort int) string {
        return mustJSON(map[string]any{
                "data": []map[string]any{{
                        "code": "DE", "name": "Germany",
                        "cities": []map[string]any{{
                                "code": "fra", "name": "Frankfurt",
                                "servers": []map[string]any{{
                                        "hostname": edgeHost, "port": edgePort, "quarantined": false,
                                        "protocols": []map[string]any{{
                                                "name": "connect", "scheme": "https", "host": edgeHost, "port": edgePort,
                                        }},
                                }},
                        }},
                }},
        })
}

// ---------- the big lifecycle test ----------

func TestKeyMechanismLifecycle(t *testing.T) {
        // 1) signing key for the test
        pub, priv, err := ed25519GenerateKey()
        if err != nil {
                t.Fatal(err)
        }
        testPriv = ed25519PrivateKey{seed: priv}
        oldPubs := pubKeys
        pubKeys = append([]string{pub}, oldPubs...)
        defer func() { pubKeys = oldPubs }()

        // 2) mock gist with a pre-existing usage of 2.5 GB and a future reset
        gist := &mockGist{
                registry: map[string]any{"keys": []any{map[string]any{
                        "id": "test1234", "name": "کاربر تست", "gb": 5, "revoked": false,
                        "issued": time.Now().Add(-48 * time.Hour).Unix(),
                        "reset":  time.Now().Add(15 * 24 * time.Hour).Unix(),
                }}},
                usage: map[string]any{"usages": map[string]any{
                        "test1234": map[string]any{"used": 2_500_000_000, "status": "active", "updated": time.Now().Unix()},
                }},
        }
        gistSrv := httptest.NewServer(gist.handler())
        defer gistSrv.Close()

        // 3) mock FxA + Guardian + edge
        edgeAddr, caPath := startMockEdge(t)
        _, portStr, _ := strings.Cut(edgeAddr, ":")
        var edgePort int
        fmt.Sscanf(portStr, "%d", &edgePort)
        fxaSrv, guardianSrv := startMockFxaGuardian(t, 2_800_000_000)
        serverListSrv := startMockServerList(t, "127.0.0.1", edgePort)
        oldFxa, oldGuardian, oldRS := fxaAuthServer, guardianEndpoint, remoteSettingsURL
        fxaAuthServer, guardianEndpoint, remoteSettingsURL = fxaSrv, guardianSrv, serverListSrv
        defer func() {
                fxaAuthServer, guardianEndpoint, remoteSettingsURL = oldFxa, oldGuardian, oldRS
        }()
        os.Setenv("SSL_CERT_FILE", caPath)
        defer os.Unsetenv("SSL_CERT_FILE")
        // pin the TLS roots for the tunnel too (Go caches the system pool)
        caPEM, err := os.ReadFile(caPath)
        if err != nil {
                t.Fatal(err)
        }
        pool := x509.NewCertPool()
        pool.AppendCertsFromPEM(caPEM)
        testRootCAs = pool
        defer func() { testRootCAs = nil }()

        // 4) core
        logger := NewLogger()
        initControlPlane()
        challengeSolveFunc = func() error { return nil }
        dataDir := t.TempDir()
        store := NewKeyStore(dataDir)
        store.Load()
        reporter := NewGistReporter()
        reporter.baseURL = gistSrv.URL
        core, err := NewCore(CoreConfig{
                DataDir: dataDir, SocksPort: 0, HttpPort: 0, UIPort: 0,
                Bind: "127.0.0.1", TLSSplit: "", EdgeAddress: "", UpstreamProxy: "",
        }, logger, store, reporter)
        if err != nil {
                t.Fatalf("NewCore: %v", err)
        }
        if core.state != StateNeedKey {
                t.Fatalf("initial state = %s, want need-key", core.state)
        }

        // 5) activate with a bad signature first
        badKey := "FV1.c2Ft.zm9v"
        if err := core.ActivateKey(badKey); err == nil {
                t.Fatal("bad signature accepted")
        }

        // 6) activate the real key
        rawKey := mintTestKey(t, QuotaKeyPayload{
                V: 1, Name: "کاربر تست", Gb: 5, Exp: 0,
                ID: "test1234", Rt: "mock-refresh-token",
                Gist: "gistid123", Gt: "gh-token-123",
        })
        if err := core.ActivateKey(rawKey); err != nil {
                t.Fatalf("ActivateKey: %v", err)
        }
        if core.state != StateDisconnected {
                t.Fatalf("state after activate = %s, want disconnected", core.state)
        }
        // counter resumed from the registry (2.5 GB)
        if used := store.Usage("test1234").UsedBytes; used != 2_500_000_000 {
                t.Fatalf("resumed usage = %d, want 2500000000", used)
        }
        // national code saved and resolvable
        code := NationalCode("test1234")
        if got, ok := store.LookupCode(code); !ok || got != rawKey {
                t.Fatalf("national code lookup failed: %q %v", code, ok)
        }

        // 7) connect through the whole mock chain
        if err := core.Connect("DE", "fra"); err != nil {
                t.Fatalf("Connect: %v", err)
        }
        deadline := time.Now().Add(20 * time.Second)
        for {
                core.mu.Lock()
                st := core.state
                msg := core.stateMsg
                core.mu.Unlock()
                if st == StateConnected {
                        break
                }
                if st == StateDisconnected {
                        t.Fatalf("connection dropped back to disconnected: %s", msg)
                }
                if time.Now().After(deadline) {
                        t.Fatalf("never connected (state=%s msg=%s)", st, msg)
                }
                time.Sleep(150 * time.Millisecond)
        }
        t.Logf("connected through the full mock chain")

        // 8) real traffic through the local HTTP proxy
        snap := core.Snapshot()
        if !snap.Connected || snap.HasKey == false {
                t.Fatalf("snapshot wrong: %+v", snap)
        }
        if snap.UsedBytes < 2_500_000_000 {
                t.Fatalf("snapshot used bytes = %d, want >= 2.5GB", snap.UsedBytes)
        }
        client := &http.Client{Timeout: 15 * time.Second}
        resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/generate_204", core.proxy.HttpPort()))
        if err != nil {
                t.Fatalf("traffic through local proxy: %v", err)
        }
        resp.Body.Close()
        if resp.StatusCode != 204 {
                t.Fatalf("got %d, want 204", resp.StatusCode)
        }

        // 9) usage reported to the gist (immediate sync on connect)
        time.Sleep(300 * time.Millisecond)
        gist.mu.Lock()
        reported := gist.usage["usages"].(map[string]any)["test1234"].(map[string]any)["used"].(float64)
        patches := gist.patches
        gist.mu.Unlock()
        if patches == 0 {
                t.Fatal("usage was never patched to the gist")
        }
        if reported < 2_500_000_000 {
                t.Fatalf("reported usage = %f, want >= 2.5GB", reported)
        }
        t.Logf("gist patched %d times, reported usage %f", patches, reported)

        // 10) disconnect restores state
        core.Disconnect()
        core.mu.Lock()
        st := core.state
        core.mu.Unlock()
        if st != StateDisconnected {
                t.Fatalf("state after disconnect = %s", st)
        }

        // 11) remove key -> need-key, then re-activate via the national code
        if err := core.RemoveKey(); err != nil {
                t.Fatalf("RemoveKey: %v", err)
        }
        if core.state != StateNeedKey {
                t.Fatalf("state after remove = %s", core.state)
        }
        if err := core.ActivateKey(code); err != nil {
                t.Fatalf("ActivateKey by national code %s: %v", code, err)
        }
        if core.state != StateDisconnected {
                t.Fatalf("state after code activate = %s", core.state)
        }
}

func TestRevokedKeyRejected(t *testing.T) {
        pub, priv, _ := ed25519GenerateKey()
        testPriv = ed25519PrivateKey{seed: priv}
        oldPubs := pubKeys
        pubKeys = append([]string{pub}, oldPubs...)
        defer func() { pubKeys = oldPubs }()

        gist := &mockGist{
                registry: map[string]any{"keys": []any{map[string]any{
                        "id": "revoked1", "revoked": true,
                }}},
                usage: map[string]any{"usages": map[string]any{}},
        }
        gistSrv := httptest.NewServer(gist.handler())
        defer gistSrv.Close()

        logger := NewLogger()
        initControlPlane()
        dataDir := t.TempDir()
        store := NewKeyStore(dataDir)
        store.Load()
        reporter := NewGistReporter()
        reporter.baseURL = gistSrv.URL
        core, err := NewCore(CoreConfig{DataDir: dataDir, SocksPort: 0, HttpPort: 0, Bind: "127.0.0.1"}, logger, store, reporter)
        if err != nil {
                t.Fatal(err)
        }
        raw := mintTestKey(t, QuotaKeyPayload{V: 1, Name: "x", Gb: 1, ID: "revoked1", Rt: "rt", Gist: "g", Gt: "t"})
        err = core.ActivateKey(raw)
        if err == nil || !strings.Contains(err.Error(), "غیرفعال") {
                t.Fatalf("revoked key accepted: %v", err)
        }
        // the strict checker alone must also say revoked
        rc := ReportContext{GistID: "g", Token: "t", KeyID: "revoked1"}
        if !reporter.IsRevoked(rc) {
                t.Fatal("IsRevoked returned false for an explicit revoked=true registry")
        }
        // absence in the registry must NOT be a revocation
        gist.mu.Lock()
        gist.registry = map[string]any{"keys": []any{}}
        gist.mu.Unlock()
        if reporter.IsRevoked(rc) {
                t.Fatal("absence in registry was treated as revocation")
        }
        // unreachable gist must NOT be a revocation
        reporter2 := NewGistReporter()
        reporter2.baseURL = "http://127.0.0.1:1" // nothing listens here
        if reporter2.IsRevoked(rc) {
                t.Fatal("unreachable gist was treated as revocation")
        }
}

func TestParseKeyForms(t *testing.T) {
        pub, priv, _ := ed25519GenerateKey()
        testPriv = ed25519PrivateKey{seed: priv}
        oldPubs := pubKeys
        pubKeys = append([]string{pub}, oldPubs...)
        defer func() { pubKeys = oldPubs }()

        // expired
        exp := mintTestKey(t, QuotaKeyPayload{V: 1, ID: "e1", Rt: "rt", Exp: time.Now().Add(-time.Hour).Unix()})
        if _, err := ParseKey(exp); err == nil || !strings.Contains(err.Error(), "منقضی") {
                t.Fatalf("expired key accepted: %v", err)
        }
        // whitespace / RTL marks inside the key must be tolerated
        ok := mintTestKey(t, QuotaKeyPayload{V: 1, ID: "e2", Rt: "rt", Gist: "g", Gt: "t"})
        noisy := "  \u200F" + ok[:20] + "\n" + ok[20:] + "  "
        k, err := ParseKey(noisy)
        if err != nil {
                t.Fatalf("noisy key rejected: %v", err)
        }
        if k.KeyID() != "e2" {
                t.Fatalf("wrong key id: %s", k.KeyID())
        }
        if looksLikeNationalCode(ok) {
                t.Fatal("FV1 key mistaken for a national code")
        }
        if !looksLikeNationalCode("1234567890") {
                t.Fatal("10-digit code not detected")
        }
        if looksLikeNationalCode("12345") {
                t.Fatal("short number mistaken for a national code")
        }
}

func TestMonthlyResetFlow(t *testing.T) {
        pub, priv, _ := ed25519GenerateKey()
        testPriv = ed25519PrivateKey{seed: priv}
        oldPubs := pubKeys
        pubKeys = append([]string{pub}, oldPubs...)
        defer func() { pubKeys = oldPubs }()

        // reset stamp in the PAST => activating and syncing must zero the counter
        // and push periodStart
        gist := &mockGist{
                registry: map[string]any{"keys": []any{map[string]any{
                        "id": "reset1", "revoked": false, "reset": time.Now().Add(-2 * time.Hour).Unix(),
                }}},
                usage: map[string]any{"usages": map[string]any{
                        "reset1": map[string]any{"used": 4_000_000_000, "status": "active", "updated": time.Now().Unix()},
                }},
        }
        gistSrv := httptest.NewServer(gist.handler())
        defer gistSrv.Close()

        logger := NewLogger()
        initControlPlane()
        dataDir := t.TempDir()
        store := NewKeyStore(dataDir)
        store.Load()
        reporter := NewGistReporter()
        reporter.baseURL = gistSrv.URL
        core, err := NewCore(CoreConfig{DataDir: dataDir, SocksPort: 0, HttpPort: 0, Bind: "127.0.0.1"}, logger, store, reporter)
        if err != nil {
                t.Fatal(err)
        }
        raw := mintTestKey(t, QuotaKeyPayload{V: 1, Name: "r", Gb: 5, ID: "reset1", Rt: "rt", Gist: "g", Gt: "t"})
        if err := core.ActivateKey(raw); err != nil {
                t.Fatalf("ActivateKey: %v", err)
        }
        // the sync applies the monthly reset (the connect path calls it too)
        core.usageSyncOnce()
        if used := store.Usage("reset1").UsedBytes; used != 0 {
                t.Fatalf("usage after monthly reset = %d, want 0", used)
        }
        if ps := store.PeriodStart("reset1"); ps <= 0 {
                t.Fatal("periodStart not stamped")
        }
        gist.mu.Lock()
        entry := gist.usage["usages"].(map[string]any)["reset1"].(map[string]any)
        used := entry["used"].(float64)
        ps := entry["periodStart"].(float64)
        gist.mu.Unlock()
        if used != 0 || ps <= 0 {
                t.Fatalf("gist entry after reset: used=%f periodStart=%f", used, ps)
        }
}
