package main

// Core state machine: login persistence, connect/disconnect, proxy pass
// renewal, upstream auto-heal, exit checks, quota, logs.

import (
        "bufio"
        "context"
        "crypto/tls"
        "encoding/json"
        "errors"
        "fmt"
        "net"
        "net/http"
        "net/url"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"
)

type State string

const (
        StateNeedLogin    State = "need-login"
        StateNeed2FA      State = "need-2fa"
        StateDisconnected State = "disconnected"
        StateConnecting   State = "connecting"
        StateConnected    State = "connected"
)

type LogLine struct {
        T  time.Time `json:"t"`
        L  string    `json:"l"`
        M  string    `json:"m"`
}

type Logger struct {
        mu    sync.Mutex
        lines []LogLine
        seq   int
        subs  map[chan LogLine]struct{}
}

func NewLogger() *Logger { return &Logger{subs: map[chan LogLine]struct{}{}} }

func (l *Logger) log(level, format string, args ...any) {
        msg := format
        if len(args) > 0 {
                msg = fmt.Sprintf(format, args...)
        }
        line := LogLine{T: time.Now(), L: level, M: msg}
        l.mu.Lock()
        l.lines = append(l.lines, line)
        if len(l.lines) > 800 {
                l.lines = l.lines[len(l.lines)-800:]
        }
        l.seq++
        subs := make([]chan LogLine, 0, len(l.subs))
        for ch := range l.subs {
                subs = append(subs, ch)
        }
        l.mu.Unlock()
        for _, ch := range subs {
                select {
                case ch <- line:
                default:
                }
        }
        if logFile != nil {
                fmt.Fprintf(logFile, "%s [%s] %s\n", line.T.Format("2006-01-02 15:04:05"), level, msg)
        }
}

func (l *Logger) Infof(f string, a ...any)  { l.log("INFO", f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.log("WARN", f, a...) }
func (l *Logger) Errorf(f string, a ...any) { l.log("ERROR", f, a...) }
func (l *Logger) Debugf(f string, a ...any) { l.log("DEBUG", f, a...) }

func (l *Logger) Since(after int) ([]LogLine, int) {
        l.mu.Lock()
        defer l.mu.Unlock()
        if after < 0 || after >= l.seq {
                after = l.seq - len(l.lines)
                if after < 0 {
                        after = 0
                }
        }
        start := after - (l.seq - len(l.lines))
        if start < 0 {
                start = 0
        }
        out := append([]LogLine{}, l.lines[start:]...)
        return out, l.seq
}

type CoreConfig struct {
        DataDir     string
        SocksPort   int
        HttpPort    int
        UIPort      int
        Bind        string
        TLSSplit    string // "", "first-byte", "sni"
        EdgeAddress string // custom edge IP override
        UpstreamProxy string
}

type Core struct {
        mu sync.Mutex

        cfg        CoreConfig
        log        *Logger
        resolver   *DohResolver
        servers    *ServerList
        proxy      *LocalProxy
        counters   *Counters
        fxa        FxaClient
        guardian   GuardianClient

        state        State
        stateMsg     string
        email        string
        auth         *RuntimeAuth
        pendingToken string

        key     *QuotaKeyPayload
        keyRaw  string
        usage   *UsageStore

        pingMu        sync.Mutex
        pingRunning   bool
        pingBestMs    int
        pingBestWhere string

        session        *TunnelSession
        connectedSince time.Time
        exitIP         string
        exitCountry    string
        entitlement    *Entitlement

        chosenCountry string
        chosenCity    string

        sysProxyEnabled bool
        savedProxy      savedProxy
        autoSysProxy    bool

        healWG      sync.WaitGroup
        stopCh      chan struct{}
        redialGen   atomicInt64
        currentPass *ProxyPass
}

var logFile *os.File

type atomicInt64 struct {
        mu sync.Mutex
        v  int64
}

func (a *atomicInt64) Add(d int64) int64 {
        a.mu.Lock()
        defer a.mu.Unlock()
        a.v += d
        return a.v
}
func (a *atomicInt64) Load() int64 {
        a.mu.Lock()
        defer a.mu.Unlock()
        return a.v
}

func NewCore(cfg CoreConfig, logger *Logger) (*Core, error) {
        c := &Core{
                cfg:      cfg,
                log:      logger,
                resolver: NewDohResolver(),
                counters: &Counters{},
                stopCh:   make(chan struct{}),
                state:    StateNeedLogin,
        }
        c.servers = NewServerList(filepath.Join(cfg.DataDir, "vpn_serverlist_cache.json"))
        c.usage = NewUsageStore(cfg.DataDir)

        if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
                return nil, err
        }
        c.loadStore()
        go c.usageLoop()

        c.proxy = NewLocalProxy(cfg.Bind, cfg.SocksPort, cfg.HttpPort, c.resolver, c.counters)
        c.proxy.SetSession(func() (streamOpener, bool) {
                c.mu.Lock()
                defer c.mu.Unlock()
                if c.state == StateConnected && c.session != nil && !c.session.IsClosed() {
                        return c.session, true
                }
                return nil, false
        })
        if err := c.proxy.Start(); err != nil {
                return nil, err
        }
        logger.Infof("local proxies up: SOCKS %s:%d, HTTP %s:%d", cfg.Bind, c.proxy.SocksPort(), cfg.Bind, c.proxy.HttpPort())
        // warm the server list in the background so the UI has a dropdown ready
        go func() {
                if _, err := c.servers.Refresh(false); err != nil {
                        logger.Debugf("server list warm-up: %v", err)
                }
        }()
        return c, nil
}

// ---------- persistence ----------

type storeFile struct {
        Auth         *RuntimeAuth    `json:"auth,omitempty"`
        PendingToken string          `json:"pending_token,omitempty"`
        SysProxy     *bool           `json:"sys_proxy,omitempty"`
        Country      string          `json:"country,omitempty"`
        City         string          `json:"city,omitempty"`
        KeyRaw       string          `json:"key_raw,omitempty"`
        KeyPayload   *QuotaKeyPayload `json:"key_payload,omitempty"`
}

func (c *Core) storePath() string { return filepath.Join(c.cfg.DataDir, "tokens.json") }

func (c *Core) loadStore() {
        raw, err := os.ReadFile(c.storePath())
        if err != nil {
                return
        }
        var st storeFile
        if json.Unmarshal(raw, &st) != nil {
                return
        }
        c.auth = st.Auth
        c.pendingToken = st.PendingToken
        if st.SysProxy != nil {
                c.autoSysProxy = *st.SysProxy
        }
        c.chosenCountry = st.Country
        c.chosenCity = st.City
        c.keyRaw = st.KeyRaw
        c.key = st.KeyPayload
        if c.auth != nil {
                c.email = c.auth.Email
        }
        if c.key != nil {
                c.usage.Attach(c.key.Id)
        }
}

func (c *Core) saveStore() {
        st := storeFile{
                Auth:         c.auth,
                PendingToken: c.pendingToken,
                Country:      c.chosenCountry,
                City:         c.chosenCity,
                KeyRaw:       c.keyRaw,
                KeyPayload:   c.key,
        }
        sysProxy := c.autoSysProxy
        st.SysProxy = &sysProxy
        raw, _ := json.MarshalIndent(st, "", "  ")
        _ = os.WriteFile(c.storePath(), raw, 0o600)
}

func (c *Core) clearStore() {
        _ = os.Remove(c.storePath())
        c.auth = nil
        c.pendingToken = ""
        c.email = ""
        c.key = nil
        c.keyRaw = ""
}

// ---------- session bootstrap ----------

func (c *Core) RestoreSession() {
        c.mu.Lock()
        auth := c.auth
        c.mu.Unlock()
        if auth == nil {
                c.log.Infof("no stored session; the activation key must be entered")
                return
        }
        if c.keyExpired() {
                c.log.Warnf("the stored key has expired; connect is disabled until a new key is activated")
                c.mu.Lock()
                c.state = StateDisconnected
                c.mu.Unlock()
                return
        }
        now := nowUnix()
        if auth.RefreshToken == "" && auth.ExpiresAt <= now {
                c.log.Warnf("stored session has neither a refresh token nor a live access token; signing out")
                c.mu.Lock()
                c.clearStore()
                c.state = StateNeedLogin
                c.mu.Unlock()
                return
        }
        if auth.ExpiresAt > now {
                c.mu.Lock()
                c.state = StateDisconnected
                c.mu.Unlock()
                c.log.Infof("session restored for %s", safeEmail(c.email))
                go c.refreshEntitlement()
                return
        }
        c.mu.Lock()
        c.state = StateConnecting
        c.mu.Unlock()
        newAuth, err := c.fxa.refresh(auth.RefreshToken)
        if err != nil {
                var rf *refreshFailure
                if errors.As(err, &rf) && rf.permanent {
                        c.log.Warnf("FxA rejected the stored session; signing out (%v)", err)
                        c.mu.Lock()
                        c.clearStore()
                        c.state = StateNeedLogin
                        c.mu.Unlock()
                } else {
                        c.log.Warnf("could not renew the session right now; staying signed in (%v)", err)
                        c.mu.Lock()
                        c.state = StateDisconnected
                        c.mu.Unlock()
                }
                return
        }
        newAuth.Email = c.email
        c.mu.Lock()
        c.auth = newAuth
        c.state = StateDisconnected
        c.saveStore()
        c.mu.Unlock()
        c.log.Infof("session renewed for %s", safeEmail(c.email))
        go c.refreshEntitlement()
}

// ---------- key activation (quota-key flow) ----------

// keyExpired reports whether the stored/pending key has passed its expiry.
func (c *Core) keyExpired() bool {
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.key != nil && c.key.Exp > 0 && c.key.Exp <= nowUnix()
}

// ActivateKey implements the exact flow of the Android KeyEntryScreen:
// verify the FV1 signature, bring the FxA session behind the key alive via
// the refresh-token grant, then accept the key and persist it.
func (c *Core) ActivateKey(rawKey string) error {
        c.mu.Lock()
        if c.state == StateConnecting || c.state == StateConnected {
                c.mu.Unlock()
                return errors.New("ابتدا اتصال را قطع کنید")
        }
        c.mu.Unlock()

        payload, cleaned, err := parseQuotaKey(rawKey)
        if err != nil {
                c.log.Warnf("key rejected: %v", err)
                return err
        }

        auth, err := c.fxa.refresh(payload.Rt)
        if err != nil {
                c.log.Errorf("key activation failed: %v", err)
                return &friendlyError{friendlyActivationError(err)}
        }

        c.mu.Lock()
        c.auth = auth
        c.email = ""
        c.pendingToken = ""
        c.key = payload
        c.keyRaw = cleaned
        c.state = StateDisconnected
        c.saveStore()
        c.usage.Attach(payload.Id)
        c.mu.Unlock()
        c.usage.Flush()
        c.log.Infof("key %s activated for %s", payload.Id, safeName(payload.personName()))

        go c.refreshEntitlement()
        return nil
}

// RemoveKey signs out and forgets the key (Android: Sign out).
func (c *Core) RemoveKey() error {
        c.Disconnect()
        c.mu.Lock()
        defer c.mu.Unlock()
        c.clearStore()
        c.state = StateNeedLogin
        c.usage = NewUsageStore(c.cfg.DataDir)
        c.log.Infof("key removed")
        return nil
}

type friendlyError struct{ msg string }

func (e *friendlyError) Error() string { return e.msg }

func safeName(name string) string {
        r := []rune(strings.TrimSpace(name))
        if len(r) == 0 {
                return "کاربر"
        }
        if len(r) <= 2 {
                return string(r)
        }
        return string(r[:2]) + "…"
}

// ---------- login flow (kept for CLI/debug parity) ----------

func (c *Core) Login(email, password string) error {
        c.mu.Lock()
        if c.state == StateConnecting || c.state == StateConnected {
                c.mu.Unlock()
                return errors.New("disconnect before switching accounts")
        }
        c.mu.Unlock()

        sessionToken, verified, _, err := c.fxa.login(email, password)
        if err != nil {
                c.log.Errorf("sign-in failed: %v", err)
                return err
        }
        if !verified {
                c.mu.Lock()
                c.pendingToken = sessionToken
                c.email = normalizeEmail(email)
                c.state = StateNeed2FA
                c.saveStore()
                c.mu.Unlock()
                c.log.Infof("verification code sent to the account email")
                return nil
        }
        auth, err := c.fxa.oauthToken(sessionToken)
        if err != nil {
                c.log.Errorf("oauth token exchange failed: %v", err)
                return err
        }
        auth.Email = normalizeEmail(email)
        c.mu.Lock()
        c.auth = auth
        c.email = auth.Email
        c.pendingToken = ""
        c.state = StateDisconnected
        c.saveStore()
        c.mu.Unlock()
        c.log.Infof("signed in as %s", safeEmail(c.email))
        return nil
}

func (c *Core) Verify2FA(code string) error {
        c.mu.Lock()
        token := c.pendingToken
        c.mu.Unlock()
        if token == "" {
                return errors.New("no pending sign-in; start again")
        }
        if err := c.fxa.verifyCode(token, code); err != nil {
                c.log.Errorf("verification code rejected: %v", err)
                return err
        }
        auth, err := c.fxa.oauthToken(token)
        if err != nil {
                c.log.Errorf("oauth token exchange failed: %v", err)
                return err
        }
        c.mu.Lock()
        c.auth = auth
        c.email = normalizeEmail(c.email)
        c.pendingToken = ""
        c.state = StateDisconnected
        c.saveStore()
        c.mu.Unlock()
        c.log.Infof("signed in as %s", safeEmail(c.email))
        return nil
}

func (c *Core) Logout() error {
        return c.RemoveKey()
}

// ---------- usage accounting loop ----------

// usageLoop folds the live traffic counters into the persistent per-key
// usage store every few seconds so «مصرف شده» survives restarts.
func (c *Core) usageLoop() {
        ticker := time.NewTicker(3 * time.Second)
        defer ticker.Stop()
        for range ticker.C {
                c.mu.Lock()
                connected := c.state == StateConnected
                up := c.counters.Up.Load()
                down := c.counters.Down.Load()
                usage := c.usage
                c.mu.Unlock()
                if connected && usage != nil {
                        usage.AddDelta(up, down)
                }
        }
}

// ---------- ping-all (home «تست پینگ همه» pill) ----------

// StartPingAll measures the TCP latency of the first city of up to 12
// countries and remembers the best result — the Windows counterpart of the
// Android PingUtil ping-all sweep.
func (c *Core) StartPingAll() {
        c.pingMu.Lock()
        if c.pingRunning {
                c.pingMu.Unlock()
                return
        }
        c.pingRunning = true
        c.pingMu.Unlock()

        go func() {
                defer func() {
                        c.pingMu.Lock()
                        c.pingRunning = false
                        c.pingMu.Unlock()
                }()

                countries, err := c.servers.Refresh(false)
                if err != nil || len(countries) == 0 {
                        return
                }
                if len(countries) > 12 {
                        countries = countries[:12]
                }
                best, bestWhere := 0, ""
                for _, country := range countries {
                        var host string
                        var port int
                        for _, city := range country.Cities {
                                for _, srv := range city.Servers {
                                        if !srv.Quarantined {
                                                host, port = srv.Hostname, srv.Port
                                                break
                                        }
                                }
                                if host != "" {
                                        break
                                }
                        }
                        if host == "" {
                                continue
                        }
                        ms := c.measureTCPLatency(host, port)
                        where := country.Name
                        if ms > 0 && (best == 0 || ms < best) {
                                best, bestWhere = ms, where
                        }
                        select {
                        case <-c.stopCh:
                                return
                        default:
                        }
                }
                if best > 0 {
                        c.pingMu.Lock()
                        c.pingBestMs, c.pingBestWhere = best, bestWhere
                        c.pingMu.Unlock()
                }
        }()
}

func (c *Core) measureTCPLatency(host string, port int) int {
        target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
        if ip, ok := c.resolver.EdgeAddress(host); ok {
                target = net.JoinHostPort(ip, fmt.Sprintf("%d", port))
        }
        start := time.Now()
        conn, err := net.DialTimeout("tcp", target, 2500*time.Millisecond)
        if err != nil {
                return 0
        }
        _ = conn.Close()
        ms := int(time.Since(start).Milliseconds())
        if ms < 1 {
                ms = 1
        }
        return ms
}

// PingProbe measures a single city's first server — the server-list rows.
func (c *Core) PingProbe(countryCode, cityCode string) int {
        countries := c.servers.Countries()
        for _, country := range countries {
                if country.Code != countryCode {
                        continue
                }
                for _, city := range country.Cities {
                        if city.Code != cityCode {
                                continue
                        }
                        for _, srv := range city.Servers {
                                if srv.Quarantined {
                                        continue
                                }
                                return c.measureTCPLatency(srv.Hostname, srv.Port)
                        }
                }
        }
        return 0
}

func (c *Core) hasValidAccessToken() bool {
        return c.auth != nil && c.auth.ExpiresAt > nowUnix()+30
}

func (c *Core) freshAccessToken() (string, error) {
        c.mu.Lock()
        auth := c.auth
        c.mu.Unlock()
        if auth == nil {
                return "", errors.New("not signed in")
        }
        if c.hasValidAccessToken() {
                return auth.AccessToken, nil
        }
        if auth.RefreshToken == "" {
                c.mu.Lock()
                c.clearStore()
                c.state = StateNeedLogin
                c.mu.Unlock()
                return "", errors.New("session expired; sign in again")
        }
        newAuth, err := c.fxa.refresh(auth.RefreshToken)
        if err != nil {
                return "", err
        }
        newAuth.Email = auth.Email
        c.mu.Lock()
        c.auth = newAuth
        c.saveStore()
        accessToken := newAuth.AccessToken
        c.mu.Unlock()
        c.log.Infof("access token renewed")
        return accessToken, nil
}

// mintProxyPass fetches a proxy pass, activating the entitlement on 401.
func (c *Core) mintProxyPass() (*ProxyPass, error) {
        token, err := c.freshAccessToken()
        if err != nil {
                return nil, err
        }
        pass, err := c.guardian.fetchProxyPass(token)
        if err == nil {
                return pass, nil
        }
        if errors.Is(err, errTokenInvalid) {
                c.log.Warnf("proxy pass rejected, activating Guardian entitlement and retrying")
                if _, aerr := c.guardian.activate(token); aerr != nil {
                        return nil, aerr
                }
                return c.guardian.fetchProxyPass(token)
        }
        return nil, err
}

// ---------- connect / disconnect ----------

func (c *Core) Connect(country, city string) error {
        c.mu.Lock()
        if c.key != nil && c.key.Exp > 0 && c.key.Exp <= nowUnix() {
                c.mu.Unlock()
                return errors.New("این کلید منقضی شده است؛ کلید جدید فعال کنید")
        }
        switch c.state {
        case StateConnected:
                c.mu.Unlock()
                return nil
        case StateConnecting:
                c.mu.Unlock()
                return errors.New("already connecting")
        case StateNeedLogin, StateNeed2FA:
                c.mu.Unlock()
                return errors.New("sign in first")
        }
        if country != "" {
                c.chosenCountry = country
        }
        if city != "" {
                c.chosenCity = city
        }
        chooseCountry, chooseCity := c.chosenCountry, c.chosenCity
        c.state = StateConnecting
        c.stateMsg = ""
        c.exitIP = ""
        c.exitCountry = ""
        c.counters.Up.Store(0)
        c.counters.Down.Store(0)
        c.mu.Unlock()

        c.saveStore()
        c.healWG.Add(1)
        go c.connectLoop(chooseCountry, chooseCity)
        return nil
}

func (c *Core) connectLoop(country, city string) {
        defer c.healWG.Done()
        attempt := 0
        for {
                select {
                case <-c.stopCh:
                        return
                default:
                }
                c.mu.Lock()
                gen := c.redialGen.Load()
                c.mu.Unlock()

                err := c.dialOnce(country, city)
                if err == nil {
                        return // connected; supervision continues in supervise()
                }
                c.log.Warnf("connect attempt %d failed: %v", attempt+1, err)
                attempt++

                // bail out if a disconnect/another connect superseded us
                if c.redialGen.Load() != gen {
                        return
                }
                c.mu.Lock()
                c.stateMsg = err.Error()
                c.mu.Unlock()
                select {
                case <-c.stopCh:
                        return
                case <-time.After(backoffDelay(attempt)):
                }
        }
}

func backoffDelay(attempt int) time.Duration {
        d := time.Duration(attempt) * 2 * time.Second
        if d > 15*time.Second {
                d = 15 * time.Second
        }
        if d < 1*time.Second {
                d = 1 * time.Second
        }
        return d
}

func (c *Core) dialOnce(country, city string) error {
        countries, err := c.servers.Refresh(len(c.servers.Countries()) == 0)
        if err != nil {
                c.log.Errorf("server list fetch failed: %v", err)
        }
        if len(countries) == 0 {
                return errors.New("server list unavailable")
        }
        cands := candidates(countries, country, city)
        if len(cands) == 0 && city != "" {
                cands = candidates(countries, country, "")
        }
        if len(cands) == 0 {
                cands = candidates(countries, "", "")
        }
        if len(cands) == 0 {
                return errors.New("no server candidates available")
        }

        pass, err := c.mintProxyPass()
        if err != nil {
                if errors.Is(err, errQuotaExceeded) {
                        return fmt.Errorf("monthly quota exhausted; wait for the reset")
                }
                return fmt.Errorf("proxy pass: %v", err)
        }
        c.mu.Lock()
        c.currentPass = pass
        c.mu.Unlock()
        if pass.ExpiresAt > 0 {
                c.log.Infof("proxy pass acquired (valid for %ds)", pass.ExpiresAt-nowUnix())
        }
        if pass.QuotaRemain != nil {
                c.log.Infof("quota remaining: %s", humanBytes(*pass.QuotaRemain))
        }

        var lastErr error
        for _, cand := range cands {
                if c.redialSuperseded() {
                        return nil
                }
                c.log.Infof("connecting to %s (%s) via %s", cand.CountryName, cand.CityName, cand.Host)
                edgeIP := c.cfg.EdgeAddress
                if edgeIP == "" {
                        if ip, ok := c.resolver.EdgeAddress(cand.Host); ok {
                                edgeIP = ip
                        }
                }
                sess, err := DialTunnel(cand.Host, cand.Port, pass.Token, edgeIP, c.cfg.TLSSplit, c.cfg.UpstreamProxy)
                if err != nil {
                        c.log.Warnf("tunnel to %s:%d failed: %v", cand.Host, cand.Port, err)
                        lastErr = err
                        continue
                }
                c.log.Infof("TLS+HTTP/2 to %s is up; verifying real traffic…", cand.Host)
                if perr := probeTunnel(sess, c.resolver); perr != nil {
                        c.log.Warnf("traffic verification via %s failed: %v", cand.Host, perr)
                        sess.Close()
                        lastErr = fmt.Errorf("traffic verification via %s: %v", cand.Host, perr)
                        continue
                }
                c.mu.Lock()
                c.session = sess
                c.state = StateConnected
                c.stateMsg = ""
                c.connectedSince = time.Now()
                c.mu.Unlock()
                c.log.Infof("connected to %s (%s/%s) — traffic verified", cand.Host, cand.CountryCode, cand.CityCode)

                if c.autoSysProxy {
                        if err := EnableSystemProxy(c.proxy.HttpPort(), &c.savedProxy); err != nil {
                                c.log.Warnf("could not enable the system proxy: %v", err)
                        } else {
                                c.log.Infof("system proxy enabled at 127.0.0.1:%d", c.proxy.HttpPort())
                        }
                }
                go c.supervise(sess, cand)
                go c.exitCheck()
                return nil
        }
        if lastErr == nil {
                lastErr = errors.New("no candidate could be dialed")
        }
        return lastErr
}

func (c *Core) redialSuperseded() bool {
        select {
        case <-c.stopCh:
                return true
        default:
        }
        c.mu.Lock()
        defer c.mu.Unlock()
        return c.state != StateConnecting && c.state != StateConnected
}

// supervise watches a live session: renews the proxy pass at half-life and
// rebuilds the tunnel if the edge drops it.
func (c *Core) supervise(sess *TunnelSession, cand ProxyCandidate) {
        defer func() {
                sess.Close()
                c.mu.Lock()
                if c.session == sess {
                        c.session = nil
                }
                c.mu.Unlock()
        }()
        c.mu.Lock()
        renewIn := proxyPassRenewalDelay(passExpiry(c.currentPass))
        c.mu.Unlock()
        renewTimer := time.NewTimer(renewIn)
        defer renewTimer.Stop()
        quotaTimer := time.NewTicker(90 * time.Second)
        defer quotaTimer.Stop()

        for {
                select {
                case <-c.stopCh:
                        return
                case <-renewTimer.C:
                        pass, err := c.mintProxyPass()
                        if err != nil {
                                c.log.Warnf("proxy pass renewal failed: %v (retrying in 30s)", err)
                                renewTimer.Reset(30 * time.Second)
                                continue
                        }
                        c.mu.Lock()
                        c.currentPass = pass
                        c.mu.Unlock()
                        sess.UpdateBearerToken(pass.Token)
                        c.log.Infof("proxy pass swapped into the live session (valid for %ds)", pass.ExpiresAt-nowUnix())
                        renewTimer.Reset(proxyPassRenewalDelay(passExpiry(pass)))
                case <-quotaTimer.C:
                        c.refreshEntitlement()
                        c.mu.Lock()
                        sameSession := c.session == sess && !sess.IsClosed()
                        c.mu.Unlock()
                        if !sameSession {
                                return
                        }
                }
                c.mu.Lock()
                dead := sess.IsClosed() && c.session == sess
                c.mu.Unlock()
                if dead {
                        c.log.Warnf("upstream tunnel dropped; reconnecting")
                        c.mu.Lock()
                        c.state = StateConnecting
                        c.session = nil
                        c.mu.Unlock()
                        c.healWG.Add(1)
                        go c.connectLoop(cand.CountryCode, cand.CityCode)
                        return
                }
        }
}

func passExpiry(p *ProxyPass) int64 {
        if p == nil {
                return 0
        }
        return p.ExpiresAt
}

// proxyPassRenewalDelay mirrors the Android half-life scheduling.
func proxyPassRenewalDelay(expiresAt int64) time.Duration {
        if expiresAt <= 0 {
                return 4 * time.Minute
        }
        remaining := time.Duration(expiresAt-nowUnix()) * time.Second
        if remaining <= 0 {
                return 15 * time.Second
        }
        half := remaining / 2
        beforeExpiry := remaining - 30*time.Second
        d := half
        if beforeExpiry < d {
                d = beforeExpiry
        }
        if d > 30*time.Minute {
                d = 30 * time.Minute
        }
        if d < 15*time.Second {
                d = 15 * time.Second
        }
        return d
}

func (c *Core) refreshEntitlement() {
        token, err := c.freshAccessToken()
        if err != nil {
                return
        }
        if ent, err := c.guardian.fetchUserInfo(token); err == nil {
                c.mu.Lock()
                c.entitlement = ent
                c.mu.Unlock()
        }
}

func (c *Core) Disconnect() {
        c.mu.Lock()
        st := c.state
        if st == StateDisconnected || st == StateNeedLogin || st == StateNeed2FA {
                c.mu.Unlock()
                return
        }
        c.redialGen.Add(1)
        closeStop(&c.stopCh)
        c.stopCh = make(chan struct{})
        sess := c.session
        c.session = nil
        c.state = StateDisconnected
        c.connectedSince = time.Time{}
        c.exitIP = ""
        c.exitCountry = ""
        c.mu.Unlock()

        if c.sysProxyActive() {
                DisableSystemProxy(c.savedProxy)
                c.log.Infof("system proxy restored")
        }
        c.healWG.Wait()
        if sess != nil {
                sess.Close()
        }
        c.usage.Flush()
        c.log.Infof("disconnected")
}

// sysProxyActive reports whether we currently own an enabled system proxy.
func (c *Core) sysProxyActive() bool {
        return c.autoSysProxy
}

func closeStop(chp *chan struct{}) {
        select {
        case <-*chp:
        default:
                close(*chp)
        }
}

// ---------- exit check ----------

func (c *Core) exitCheck() {
        time.Sleep(1500 * time.Millisecond)
        c.mu.Lock()
        httpPort := c.proxy.HttpPort()
        c.mu.Unlock()
        client := &http.Client{
                Timeout: 15 * time.Second,
                Transport: &http.Transport{
                        Proxy: func(*http.Request) (*url.URL, error) {
                                return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpPort))
                        },
                },
        }
        resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
        if err != nil {
                c.log.Warnf("exit check failed: %v", err)
                return
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                c.log.Warnf("exit check: HTTP %d", resp.StatusCode)
                return
        }
        body := make([]byte, 4096)
        n, _ := resp.Body.Read(body)
        ip, country := "", ""
        for _, line := range strings.Split(string(body[:n]), "\n") {
                if strings.HasPrefix(line, "ip=") {
                        ip = strings.TrimSpace(line[3:])
                }
                if strings.HasPrefix(line, "loc=") {
                        country = strings.TrimSpace(line[4:])
                }
        }
        c.mu.Lock()
        c.exitIP, c.exitCountry = ip, country
        c.mu.Unlock()
        c.log.Infof("exit check: ip=%s country=%s", ip, country)
}

// ---------- settings ----------

func (c *Core) SetSysProxyEnabled(on bool) {
        c.mu.Lock()
        c.autoSysProxy = on
        connected := c.state == StateConnected
        if on && connected {
                err := EnableSystemProxy(c.proxy.HttpPort(), &c.savedProxy)
                c.mu.Unlock()
                if err != nil {
                        c.log.Warnf("could not enable the system proxy: %v", err)
                } else {
                        c.log.Infof("system proxy enabled at 127.0.0.1:%d", c.proxy.HttpPort())
                }
        } else {
                wasActive := c.sysProxyActive()
                c.mu.Unlock()
                if !on && wasActive {
                        DisableSystemProxy(c.savedProxy)
                        c.log.Infof("system proxy restored")
                }
        }
        c.mu.Lock()
        c.saveStore()
        c.mu.Unlock()
}

func (c *Core) SetServerChoice(country, city string) {
        c.mu.Lock()
        c.chosenCountry, c.chosenCity = country, city
        c.saveStore()
        c.mu.Unlock()
}

// ---------- snapshot for the UI ----------

type Snapshot struct {
        State       State        `json:"state"`
        StateMsg    string       `json:"state_msg,omitempty"`
        Email       string       `json:"email,omitempty"`
        Need2FA     bool         `json:"need_2fa"`
        ExitIP      string       `json:"exit_ip,omitempty"`
        ExitCountry string       `json:"exit_country,omitempty"`
        Connected   bool         `json:"connected"`
        Since       string       `json:"connected_since,omitempty"`
        QuotaMax    *int64       `json:"quota_max,omitempty"`
        QuotaRemain *int64       `json:"quota_remaining,omitempty"`
        QuotaReset  *int64       `json:"quota_reset,omitempty"`
        UpBytes     int64        `json:"up_bytes"`
        DownBytes   int64        `json:"down_bytes"`
        Country     string       `json:"country"`
        City        string       `json:"city"`
        SysProxy    bool         `json:"sys_proxy"`
        SocksPort   int          `json:"socks_port"`
        HttpPort    int          `json:"http_port"`
        UIPort      int          `json:"ui_port"`
        TLSSplit    string       `json:"tls_split"`
        LastError   string       `json:"last_error,omitempty"`

        // quota-key context (Android HomeScreen account card)
        HasKey     bool   `json:"has_key"`
        KeyName    string `json:"key_name,omitempty"`
        KeyID      string `json:"key_id,omitempty"`
        PlanGb     int64  `json:"plan_gb"`
        PlanMb     int64  `json:"plan_mb"`
        KeyExp     int64  `json:"key_exp"`
        KeyExpired bool   `json:"key_expired"`
        LimitBytes int64  `json:"limit_bytes"`
        UsedBytes  int64  `json:"used_bytes"`
        ResetAt    int64  `json:"reset_at"`

        PingRunning   bool   `json:"ping_running"`
        PingBestMs    int    `json:"ping_best_ms"`
        PingBestWhere string `json:"ping_best_where,omitempty"`
}

func (c *Core) Snapshot() Snapshot {
        c.mu.Lock()
        defer c.mu.Unlock()
        s := Snapshot{
                State:     c.state,
                StateMsg:  c.stateMsg,
                Email:     safeEmail(c.email),
                Need2FA:   c.state == StateNeed2FA,
                Connected: c.state == StateConnected,
                Country:   c.chosenCountry,
                City:      c.chosenCity,
                SysProxy:  c.autoSysProxy,
                SocksPort: c.proxy.SocksPort(),
                HttpPort:  c.proxy.HttpPort(),
                UIPort:    c.cfg.UIPort,
                TLSSplit:  c.cfg.TLSSplit,
        }
        if c.state == StateConnected && !c.connectedSince.IsZero() {
                s.Since = c.connectedSince.Format(time.RFC3339)
        }
        s.ExitIP, s.ExitCountry = c.exitIP, c.exitCountry
        if ent := c.entitlement; ent != nil {
                s.QuotaMax, s.QuotaRemain = ent.MaxBytes, ent.QuotaRemaining
        }
        if c.currentPass != nil {
                s.QuotaReset = c.currentPass.QuotaReset
        }
        s.UpBytes = c.counters.Up.Load()
        s.DownBytes = c.counters.Down.Load()

        // key context
        if c.key != nil {
                s.HasKey = true
                s.KeyName = c.key.personName()
                s.KeyID = c.key.Id
                s.PlanGb, s.PlanMb = c.key.Gb, c.key.Mb
                s.KeyExp = c.key.Exp
                s.KeyExpired = c.key.Exp > 0 && c.key.Exp <= nowUnix()
        }
        // usage: prefer the plan from the key, then Guardian's authoritative
        // X-Quota numbers; fall back to the local persistent counter.
        plan := int64(0)
        if c.key != nil {
                plan = c.key.planBytes()
        }
        s.LimitBytes = plan
        if ent := c.entitlement; ent != nil && ent.MaxBytes != nil && *ent.MaxBytes > 0 {
                if plan <= 0 || *ent.MaxBytes > plan {
                        s.LimitBytes = *ent.MaxBytes
                }
        }
        used := c.usage.Used()
        if ent := c.entitlement; ent != nil && ent.QuotaRemaining != nil && s.LimitBytes > 0 {
                serverUsed := s.LimitBytes - *ent.QuotaRemaining
                if serverUsed > used {
                        used = serverUsed
                }
        }
        s.UsedBytes = used
        if r := c.usage.ResetAt(); r > 0 {
                s.ResetAt = r
        }
        if c.currentPass != nil && c.currentPass.QuotaReset != nil {
                s.ResetAt = *c.currentPass.QuotaReset
        }

        c.pingMu.Lock()
        s.PingRunning, s.PingBestMs, s.PingBestWhere = c.pingRunning, c.pingBestMs, c.pingBestWhere
        c.pingMu.Unlock()
        return s
}

func (c *Core) Shutdown() {
        c.Disconnect()
        c.proxy.Stop()
}

// ShutdownQuick tears the session and the system proxy down WITHOUT waiting
// on background workers (connect retries, relays…). It is used on app exit so
// the tray/Exit button is always instant instead of hanging for minutes.
func (c *Core) ShutdownQuick() {
        c.mu.Lock()
        closeStop(&c.stopCh)
        c.stopCh = make(chan struct{})
        sess := c.session
        c.session = nil
        c.mu.Unlock()
        if c.sysProxyActive() {
                DisableSystemProxy(c.savedProxy)
        }
        if sess != nil {
                sess.Close()
        }
        c.usage.Flush()
}

// ---------- server options / logs for the UI ----------

type ServerOption struct {
        Label   string `json:"label"`
        Country string `json:"country"`
        City    string `json:"city"`
}

// ServerOptions returns the dropdown entries: "auto" first, then country — city.
func (c *Core) ServerOptions() []ServerOption {
        out := []ServerOption{{Label: "خودکار (پیش‌فرض)"}}
        for _, country := range c.servers.Countries() {
                for _, city := range country.Cities {
                        out = append(out, ServerOption{
                                Label:   fmt.Sprintf("%s — %s", country.Name, city.Name),
                                Country: country.Code,
                                City:    city.Code,
                        })
                }
        }
        return out
}

func (c *Core) RecentLogs(after int) ([]LogLine, int) { return c.log.Since(after) }

// ---------- real traffic verification ----------

// probeTunnel pushes actual HTTP traffic through a freshly established tunnel.
// "Connected" is only reported when bytes really round-trip, so the UI never
// shows a green state over a dead tunnel.
func probeTunnel(sess *TunnelSession, resolver *DohResolver) error {
        probes := []struct {
                host   string
                port   int
                useTLS bool
        }{
                {"cp.cloudflare.com", 80, false},
                {"www.gstatic.com", 80, false},
                {"www.gstatic.com", 443, true},
        }
        var lastErr error
        for _, p := range probes {
                err := probeOnce(sess, resolver, p.host, p.port, p.useTLS)
                if err == nil {
                        return nil
                }
                var rej *UpstreamConnectRejected
                if errors.As(err, &rej) {
                        // the edge itself refused the CONNECT (token/quota/challenge):
                        // other targets will be rejected the same way
                        return fmt.Errorf("edge rejected CONNECT (HTTP %d)", rej.StatusCode)
                }
                lastErr = err
        }
        if lastErr == nil {
                lastErr = errors.New("no probe target reachable")
        }
        return lastErr
}

func probeOnce(sess *TunnelSession, resolver *DohResolver, host string, port int, useTLS bool) error {
        ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
        defer cancel()
        dialHost := host
        if ip, ok := resolver.Resolve(host); ok {
                dialHost = ip // bypass a possibly poisoned local resolver
        }
        conn, err := sess.OpenStream(ctx, dialHost, port)
        if err != nil {
                return err
        }
        defer conn.Close()
        if useTLS {
                tc := tls.Client(conn, &tls.Config{
                        ServerName: host,
                        MinVersion: tls.VersionTLS12,
                        NextProtos: []string{"http/1.1"},
                })
                if err := tc.HandshakeContext(ctx); err != nil {
                        return fmt.Errorf("probe TLS handshake: %w", err)
                }
                conn = tc
        }
        req := fmt.Sprintf("GET /generate_204 HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", host, MozillaVpnUserAgent)
        if _, err := conn.Write([]byte(req)); err != nil {
                return err
        }
        br := bufio.NewReader(conn)
        line, err := br.ReadString('\n')
        if err != nil {
                return fmt.Errorf("probe read: %w", err)
        }
        if strings.Contains(line, " 204") {
                return nil
        }
        return fmt.Errorf("probe got %q", strings.TrimSpace(line))
}

func nowUnix() int64 { return time.Now().Unix() }

func safeEmail(email string) string {
        at := strings.Index(email, "@")
        if at <= 0 {
                return email
        }
        name := email[:at]
        if len(name) <= 2 {
                return name + "***" + email[at:]
        }
        return name[:2] + "***" + email[at:]
}

func humanBytes(n int64) string {
        const unit = 1024
        if n < unit {
                return fmt.Sprintf("%d B", n)
        }
        div, exp := int64(unit), 0
        for m := n / unit; m >= unit; m /= unit {
                div *= unit
                exp++
        }
        return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

var _ = net.JoinHostPort

