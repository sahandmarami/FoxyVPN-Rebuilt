package main

// Core state machine — the completely rebuilt "key mechanism".
//
// There is no email/password login anymore: the app is activated with a
// signed quota key (FV1) exactly like the Android app, then connects through
// Guardian + Fastly with one tap. Usage is reported to the distributor's
// gist live; revocation follows the strict explicit-flag rule; the monthly
// volume re-grant is applied from the registry's reset stamp.

import (
        "bufio"
        "context"
        "crypto/tls"
        "errors"
        "fmt"
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
        StateNeedKey     State = "need-key"
        StateDisconnected State = "disconnected"
        StateConnecting  State = "connecting"
        StateConnected   State = "connected"
)

type LogLine struct {
        T time.Time `json:"t"`
        L string    `json:"l"`
        M string    `json:"m"`
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
}

func (l *Logger) Infof(f string, a ...any)  { l.log("info", f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.log("warn", f, a...) }
func (l *Logger) Errorf(f string, a ...any) { l.log("error", f, a...) }
func (l *Logger) Debugf(f string, a ...any) { l.log("debug", f, a...) }

func (l *Logger) Since(after int) ([]LogLine, int) {
        l.mu.Lock()
        defer l.mu.Unlock()
        if after >= l.seq {
                return nil, l.seq
        }
        start := len(l.lines) - (l.seq - after)
        if start < 0 {
                start = 0
        }
        out := make([]LogLine, len(l.lines)-start)
        copy(out, l.lines[start:])
        return out, l.seq
}

var logFile *os.File

type CoreConfig struct {
        DataDir       string
        SocksPort     int
        HttpPort      int
        UIPort        int
        Bind          string
        TLSSplit      string
        EdgeAddress   string
        UpstreamProxy string
}

type Core struct {
        mu sync.Mutex

        cfg      CoreConfig
        log      *Logger
        resolver *DohResolver
        servers  *ServerList
        proxy    *LocalProxy
        counters *Counters
        guardian GuardianClient
        gist     *GistReporter
        store    *KeyStore

        state    State
        stateMsg string

        auth *RuntimeAuth // cached FxA access token minted from the key's rt

        session        *TunnelSession
        connectedSince time.Time
        exitIP         string
        exitCountry    string
        currentPass    *ProxyPass
        sysSaved       savedProxy

        usedBase    int64 // ledger usage when the current connection started
        syncWG      sync.WaitGroup
        syncStop    chan struct{}
        healWG      sync.WaitGroup
        stopCh      chan struct{}
        redialGen   atomicInt64
        lastSyncOk  int64
        lastIssue   string
        lastReport  int64
        blockReason string
}

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

func NewCore(cfg CoreConfig, logger *Logger, store *KeyStore, gist *GistReporter) (*Core, error) {
        c := &Core{
                cfg:      cfg,
                log:      logger,
                resolver: NewDohResolver(),
                counters: &Counters{},
                stopCh:   make(chan struct{}),
                syncStop: make(chan struct{}),
                store:    store,
                gist:     gist,
        }
        c.servers = NewServerList(filepath.Join(cfg.DataDir, "vpn_serverlist_cache.json"))

        if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
                return nil, err
        }
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
        logger.Infof("پروکسی‌های محلی آماده: SOCKS %s:%d ، HTTP %s:%d", cfg.Bind, c.proxy.SocksPort(), cfg.Bind, c.proxy.HttpPort())

        if k := store.Key(); k != nil {
                c.state = StateDisconnected
                c.log.Infof("کلید %s (%s) فعال است", NationalCode(k.KeyID()), k.PersonName())
        } else {
                c.state = StateNeedKey
        }
        return c, nil
}

// ---------- key activation ----------

// ActivateKey accepts either a full FV1 key or a 10-digit national code
// previously registered on this device.
func (c *Core) ActivateKey(input string) error {
        c.mu.Lock()
        if c.state == StateConnecting || c.state == StateConnected {
                c.mu.Unlock()
                return errors.New("برای تعویض کلید ابتدا اتصال را قطع کنید")
        }
        c.mu.Unlock()

        raw := input
        if looksLikeNationalCode(input) {
                code := cleanKeyInput(input)
                found, ok := c.store.LookupCode(code)
                if !ok {
                        c.mu.Lock()
                        c.stateMsg = "این کد در این دستگاه ثبت نشده است"
                        c.mu.Unlock()
                        return fmt.Errorf("این کد در این دستگاه ثبت نشده است؛ کلید کامل را وارد کنید")
                }
                raw = found
                c.log.Infof("کلید از روی کد ملی %s بازیابی شد", faDigits(code))
        }

        key, err := ParseKey(raw)
        if err != nil {
                var ike *InvalidKeyError
                if errors.As(err, &ike) {
                        c.log.Warnf("کلید رد شد: %v", err)
                }
                return err
        }
        c.log.Infof("کلید تأیید شد: %s (شناسه %s)", key.PersonName(), key.KeyID())

        code := NationalCode(key.KeyID())
        c.store.SaveCode(code, key.Raw)
        c.store.SetKey(key)

        // strict revocation check (best effort — an unreachable gist never blocks)
        if rc, ok := key.ReportContext(); ok {
                if c.gist.IsRevoked(rc) {
                        c.log.Warnf("کلید در مخزن غیرفعال علامت خورده است")
                        c.mu.Lock()
                        c.stateMsg = "این کلید غیرفعال شده است"
                        c.mu.Unlock()
                        return fmt.Errorf("این کلید غیرفعال شده است؛ از سازندهٔ کلید کلید جدید بگیرید")
                }
                c.seedFromRegistry(key, rc)
        }
        c.mu.Lock()
        c.state = StateDisconnected
        c.stateMsg = ""
        c.blockReason = ""
        c.mu.Unlock()
        c.log.Infof("کلید فعال شد — کد ملی این کلید: %s", faDigits(code))
        return nil
}

// seedFromRegistry resumes the counter from what other devices reported.
func (c *Core) seedFromRegistry(key *QuotaKey, rc ReportContext) {
        if used, ok := c.gist.FetchReportedUsage(rc); ok {
                c.store.IngestExternalUsage(key.KeyID(), used, 0, 0)
                c.log.Infof("مصرف قبلی از مخزن بازیابی شد: %s", humanBytes(used))
        }
}

func (c *Core) RemoveKey() error {
        c.Disconnect()
        c.mu.Lock()
        defer c.mu.Unlock()
        c.store.ClearKey()
        c.state = StateNeedKey
        c.stateMsg = ""
        c.blockReason = ""
        c.log.Infof("کلید حذف شد")
        return nil
}

// ---------- access token ----------

func (c *Core) freshAccessToken() (string, error) {
        c.mu.Lock()
        auth := c.auth
        key := c.store.Key()
        c.mu.Unlock()
        if key == nil {
                return "", errors.New("کلیدی فعال نیست")
        }
        if auth != nil && auth.ExpiresAt > nowUnix()+30 {
                return auth.AccessToken, nil
        }
        newAuth, err := (FxaClient{}).refresh(key.Payload.Rt)
        if err != nil {
                var rf *refreshFailure
                if errors.As(err, &rf) && rf.permanent {
                        c.mu.Lock()
                        c.auth = nil
                        c.mu.Unlock()
                        return "", errors.New("اعتبارنامهٔ حساب این کلید دیگر معتبر نیست؛ کلید جدید بگیرید")
                }
                return "", fmt.Errorf("اتصال به سرور حساب ناموفق بود: %v", err)
        }
        c.mu.Lock()
        c.auth = newAuth
        c.mu.Unlock()
        c.log.Infof("توکن دسترسی تازه شد")
        return newAuth.AccessToken, nil
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
                c.log.Infof("حساب فعال نشده بود؛ فعال‌سازی Guardian و تلاش دوباره…")
                if _, aerr := c.guardian.activate(token); aerr != nil {
                        return nil, friendlyGuardianError(aerr)
                }
                pass, err = c.guardian.fetchProxyPass(token)
                if err != nil {
                        return nil, friendlyGuardianError(err)
                }
                return pass, nil
        }
        if errors.Is(err, errQuotaExceeded) {
                return nil, errors.New("سهمیهٔ ماهانهٔ حساب تمام شده؛ تا شارژ دوباره صبر کنید")
        }
        return nil, friendlyGuardianError(err)
}

func friendlyGuardianError(err error) error {
        msg := err.Error()
        switch {
        case strings.Contains(msg, "402"):
                return errors.New("حساب هیچ سهمیهٔ فعالی ندارد (اشتراک گاردین فعال نیست)")
        case strings.Contains(msg, "403"):
                return errors.New("دسترسی به حساب رد شد (403)")
        case strings.Contains(msg, "404"):
                return errors.New("سرویس پیدا نشد (404)")
        case strings.Contains(msg, "429"):
                return errors.New("سقف درخواست پر شده؛ چند دقیقه بعد تلاش کنید")
        case strings.Contains(msg, "challenge"):
                return fmt.Errorf("عبور از چالش فست‌لی ناموفق بود: %v", err)
        }
        return err
}

// ---------- quota helpers ----------

func (c *Core) quotaState() (used, limit int64, expired bool) {
        key := c.store.Key()
        if key == nil {
                return 0, 0, false
        }
        used = c.store.Usage(key.KeyID()).UsedBytes
        limit = key.Payload.LimitBytes()
        expired = key.Payload.Exp > 0 && key.Payload.Exp <= nowUnix()
        return used, limit, expired
}

// ---------- connect / disconnect ----------

func (c *Core) Connect(country, city string) error {
        c.mu.Lock()
        switch c.state {
        case StateConnected:
                c.mu.Unlock()
                return nil
        case StateConnecting:
                c.mu.Unlock()
                return errors.New("هم‌اکنون در حال اتصال است")
        case StateNeedKey:
                c.mu.Unlock()
                return errors.New("اول کلید را وارد کنید")
        }
        if c.store.Key() == nil {
                c.state = StateNeedKey
                c.mu.Unlock()
                return errors.New("کلیدی فعال نیست")
        }
        if country != "" {
                c.store.SetChosenCountry(country, "")
        }
        if city != "" {
                cc, _ := c.store.ChosenCountry()
                c.store.SetChosenCountry(cc, city)
        }
        chooseCountry, chooseCity := c.store.ChosenCountry()
        c.state = StateConnecting
        c.stateMsg = ""
        c.blockReason = ""
        c.exitIP = ""
        c.exitCountry = ""
        c.counters.Up.Store(0)
        c.counters.Down.Store(0)
        c.mu.Unlock()

        used, limit, expired := c.quotaState()
        if expired {
                c.mu.Lock()
                c.state = StateDisconnected
                c.stateMsg = "این کلید منقضی شده است"
                c.blockReason = "expired"
                c.mu.Unlock()
                return errors.New("این کلید منقضی شده است")
        }
        if limit > 0 && used >= limit {
                c.mu.Lock()
                c.state = StateDisconnected
                c.stateMsg = "حجم این کلید تمام شده است"
                c.blockReason = "exhausted"
                c.mu.Unlock()
                return errors.New("حجم این کلید تمام شده است؛ تا شارژ دوبارهٔ ماهانه صبر کنید")
        }
        c.usedBase = used

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
                c.log.Warnf("تلاش اتصال %d ناموفق بود: %v", attempt+1, err)
                attempt++

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
                c.log.Debugf("دریافت فهرست سرورها ناموفق بود (از کش استفاده می‌شود): %v", err)
        }
        if len(countries) == 0 {
                return errors.New("فهرست سرورها در دسترس نیست")
        }
        cands := candidates(countries, country, city)
        if len(cands) == 0 && city != "" {
                cands = candidates(countries, country, "")
        }
        if len(cands) == 0 {
                cands = candidates(countries, "", "")
        }
        if len(cands) == 0 {
                return errors.New("هیچ سروری برای اتصال پیدا نشد")
        }

        pass, err := c.mintProxyPass()
        if err != nil {
                if errors.Is(err, errQuotaExceeded) {
                        return errors.New("سهمیهٔ ماهانهٔ حساب تمام شده؛ تا شارژ دوباره صبر کنید")
                }
                return fmt.Errorf("دریافت مجوز اتصال: %v", err)
        }
        c.mu.Lock()
        c.currentPass = pass
        c.mu.Unlock()
        if pass.ExpiresAt > 0 {
                c.log.Infof("مجوز اتصال گرفته شد (معتبر تا %d ثانیه)", pass.ExpiresAt-nowUnix())
        }

        var lastErr error
        for _, cand := range cands {
                if c.redialSuperseded() {
                        return nil
                }
                c.log.Infof("اتصال به %s (%s) از طریق %s", cand.CountryName, cand.CityName, cand.Host)
                edgeIP := c.cfg.EdgeAddress
                if edgeIP == "" {
                        if ip, ok := c.resolver.EdgeAddress(cand.Host); ok {
                                edgeIP = ip
                        }
                }
                sess, err := DialTunnel(cand.Host, cand.Port, pass.Token, edgeIP, c.cfg.TLSSplit, c.cfg.UpstreamProxy)
                if err != nil {
                        c.log.Warnf("تونل به %s:%d ناموفق بود: %v", cand.Host, cand.Port, err)
                        lastErr = err
                        continue
                }
                c.log.Infof("TLS+HTTP/2 به %s برقرار شد؛ آزمایش ترافیک واقعی…", cand.Host)
                if perr := probeTunnel(sess, c.resolver); perr != nil {
                        c.log.Warnf("تأیید ترافیک از %s ناموفق بود: %v", cand.Host, perr)
                        sess.Close()
                        lastErr = fmt.Errorf("تأیید ترافیک از %s: %v", cand.Host, perr)
                        continue
                }
                c.mu.Lock()
                c.session = sess
                c.state = StateConnected
                c.stateMsg = ""
                c.connectedSince = time.Now()
                c.mu.Unlock()
                c.log.Infof("متصل شد به %s (%s/%s) — ترافیک تأیید شد", cand.Host, cand.CountryCode, cand.CityCode)

                if c.store.AutoSysProxy() {
                        if err := EnableSystemProxy(c.proxy.HttpPort(), &c.sysSaved); err != nil {
                                c.log.Warnf("روشن کردن پروکسی سیستم ناموفق بود: %v", err)
                        } else {
                                c.log.Infof("پروکسی سیستم روشن شد روی 127.0.0.1:%d", c.proxy.HttpPort())
                        }
                }
                tunnelSocksPort.Store(int64(c.proxy.SocksPort()))
                go c.supervise(sess, cand)
                go c.exitCheck()
                c.syncWG.Add(1)
                go c.usageLoop()
                return nil
        }
        if lastErr == nil {
                lastErr = errors.New("هیچ سروری پاسخ نداد")
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
                                c.log.Warnf("تمدید مجوز اتصال ناموفق بود: %v (۳۰ ثانیه بعد تلاش می‌شود)", err)
                                renewTimer.Reset(30 * time.Second)
                                continue
                        }
                        c.mu.Lock()
                        c.currentPass = pass
                        c.mu.Unlock()
                        sess.UpdateBearerToken(pass.Token)
                        c.log.Infof("مجوز جدید داخل تونل زنده عوض شد (معتبر تا %d ثانیه)", pass.ExpiresAt-nowUnix())
                        renewTimer.Reset(proxyPassRenewalDelay(passExpiry(pass)))
                case <-quotaTimer.C:
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
                        c.log.Warnf("تونل قطع شد؛ دوباره وصل می‌شود")
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

// ---------- usage reporting loop ----------

// usageLoop ticks while connected: accumulates traffic into the ledger and
// performs the combined gist sync (report usage + revocation + reset).
func (c *Core) usageLoop() {
        defer c.syncWG.Done()
        tick := time.NewTicker(30 * time.Second)
        defer tick.Stop()
        c.usageSyncOnce() // report immediately on connect
        for {
                select {
                case <-c.syncStop:
                        return
                case <-tick.C:
                }
                c.mu.Lock()
                stillConnected := c.state == StateConnected
                c.mu.Unlock()
                if !stillConnected {
                        return
                }
                c.usageSyncOnce()
        }
}

func (c *Core) usageSyncOnce() {
        key := c.store.Key()
        if key == nil {
                return
        }
        rc, ok := key.ReportContext()
        if !ok {
                return // key without gist coordinates: local enforcement only
        }
        // session delta since the previous round
        up := c.counters.Up.Load()
        down := c.counters.Down.Load()
        delta := up + down
        cur := c.store.Usage(key.KeyID()).UsedBytes
        used := max64(cur, c.usedBase) + delta
        if delta > 0 {
                c.store.SaveUsage(key.KeyID(), used)
                c.mu.Lock()
                c.usedBase = used
                c.mu.Unlock()
                c.counters.Up.Store(0)
                c.counters.Down.Store(0)
        }
        _, limit, expired := c.quotaState()
        res := c.gist.Sync(rc, used, limit, expired)
        if res == nil {
                return // unreachable this round; retried on the next tick
        }
        if res.Reported {
                c.mu.Lock()
                c.lastSyncOk = time.Now().UnixMilli()
                c.lastIssue = ""
                c.lastReport = used
                c.mu.Unlock()
        } else {
                c.mu.Lock()
                c.lastIssue = res.Issue.Label()
                c.mu.Unlock()
        }
        if res.ResetAt > 0 {
                c.store.SetResetAt(key.KeyID(), res.ResetAt)
        }
        // monthly re-grant
        c.maybeApplyMonthlyReset(key, rc)
        if res.Revoked {
                c.log.Warnf("کلید در مخزن غیرفعال شده؛ اتصال قطع می‌شود")
                c.Disconnect()
                c.mu.Lock()
                c.stateMsg = "این کلید غیرفعال شده است"
                c.blockReason = "revoked"
                c.mu.Unlock()
        }
}

// maybeApplyMonthlyReset zeroes the counters when the registry's reset stamp
// has passed and pushes the zeroed entry back to the gist.
func (c *Core) maybeApplyMonthlyReset(key *QuotaKey, rc ReportContext) {
        resetAt := c.store.ResetAt(key.KeyID())
        if resetAt <= 0 || nowUnix() < resetAt {
                return
        }
        if ps := c.store.PeriodStart(key.KeyID()); ps >= resetAt {
                return // already applied
        }
        c.store.ResetUsage(key.KeyID(), resetAt)
        c.usedBase = 0
        c.counters.Up.Store(0)
        c.counters.Down.Store(0)
        c.gist.PushPeriodReset(rc, resetAt)
        c.log.Infof("حجم ماهانه شارژ دوباره شد؛ شمارنده از صفر شروع می‌شود")
}

// ---------- disconnect / exit ----------

func (c *Core) Disconnect() {
        c.mu.Lock()
        st := c.state
        if st == StateDisconnected || st == StateNeedKey {
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

        closeStop(&c.syncStop)
        c.syncStop = make(chan struct{})
        tunnelSocksPort.Store(0)

        // final usage flush
        c.usageSyncOnce()

        if c.store.AutoSysProxy() {
                DisableSystemProxy(c.sysSaved)
                c.log.Infof("پروکسی سیستم به حالت قبل برگشت")
        }
        c.healWG.Wait()
        if sess != nil {
                sess.Close()
        }
        c.log.Infof("اتصال قطع شد")
}

func closeStop(chp *chan struct{}) {
        select {
        case <-*chp:
        default:
                close(*chp)
        }
}

// ShutdownQuick tears the session and the system proxy down WITHOUT waiting
// on background workers, so closing the window is always instant.
func (c *Core) ShutdownQuick() {
        c.mu.Lock()
        closeStop(&c.stopCh)
        c.stopCh = make(chan struct{})
        sess := c.session
        c.session = nil
        c.mu.Unlock()
        closeStop(&c.syncStop)
        tunnelSocksPort.Store(0)
        // final flush best-effort in the background: window close must stay instant
        go c.usageSyncOnce()
        if c.store.AutoSysProxy() {
                DisableSystemProxy(c.sysSaved)
        }
        if sess != nil {
                sess.Close()
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
                c.log.Warnf("بررسی IP خروجی ناموفق بود: %v", err)
                return
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                c.log.Warnf("بررسی IP خروجی: HTTP %d", resp.StatusCode)
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
        c.log.Infof("IP خروجی: %s (%s)", ip, country)
}

// ---------- settings ----------

func (c *Core) SetSysProxyEnabled(on bool) {
        c.store.SetAutoSysProxy(on)
        c.mu.Lock()
        connected := c.state == StateConnected
        c.mu.Unlock()
        if on && connected {
                if err := EnableSystemProxy(c.proxy.HttpPort(), &c.sysSaved); err != nil {
                        c.log.Warnf("روشن کردن پروکسی سیستم ناموفق بود: %v", err)
                } else {
                        c.log.Infof("پروکسی سیستم روشن شد روی 127.0.0.1:%d", c.proxy.HttpPort())
                }
        }
        if !on && connected {
                DisableSystemProxy(c.sysSaved)
                c.log.Infof("پروکسی سیستم خاموش شد")
        }
}

// ---------- snapshot for the UI ----------

type KeyInfo struct {
        Name      string `json:"name"`
        Code      string `json:"code"`
        KeyID     string `json:"key_id"`
        GB        int64  `json:"gb"`
        MB        int64  `json:"mb"`
        ExpiresAt int64  `json:"expires_at"`
}

type Snapshot struct {
        State       State  `json:"state"`
        StateMsg    string `json:"state_msg,omitempty"`
        BlockReason string `json:"block_reason,omitempty"`
        ExitIP      string `json:"exit_ip,omitempty"`
        ExitCountry string `json:"exit_country,omitempty"`
        Connected   bool   `json:"connected"`
        Since       string `json:"connected_since,omitempty"`

        HasKey      bool    `json:"has_key"`
        Key         *KeyInfo `json:"key,omitempty"`
        UsedBytes   int64   `json:"used_bytes"`
        LimitBytes  int64   `json:"limit_bytes"`
        ResetAt     int64   `json:"reset_at,omitempty"`
        SyncOkAt    int64   `json:"sync_ok_at,omitempty"`
        SyncIssue   string  `json:"sync_issue,omitempty"`
        ReportedBytes int64 `json:"reported_bytes,omitempty"`

        UpBytes   int64 `json:"up_bytes"`
        DownBytes int64 `json:"down_bytes"`
        Country   string `json:"country"`
        City      string `json:"city"`
        SysProxy  bool  `json:"sys_proxy"`
        AutoConn  bool  `json:"auto_connect"`
        SocksPort int   `json:"socks_port"`
        HttpPort  int   `json:"http_port"`
        UIPort    int   `json:"ui_port"`
        TLSSplit  string `json:"tls_split"`
        LastError string `json:"last_error,omitempty"`
        Version   string `json:"version"`
}

func (c *Core) Snapshot() Snapshot {
        c.mu.Lock()
        defer c.mu.Unlock()
        s := Snapshot{
                State:       c.state,
                StateMsg:    c.stateMsg,
                BlockReason: c.blockReason,
                Connected:   c.state == StateConnected,
                Country:     "",
                SysProxy:    c.store.AutoSysProxy(),
                AutoConn:    c.store.AutoConnect(),
                SocksPort:   c.proxy.SocksPort(),
                HttpPort:    c.proxy.HttpPort(),
                UIPort:      c.cfg.UIPort,
                TLSSplit:    c.cfg.TLSSplit,
                Version:     appVersion,
        }
        if country, city := c.store.ChosenCountry(); country != "" {
                s.Country, s.City = country, city
        }
        if c.state == StateConnected && !c.connectedSince.IsZero() {
                s.Since = c.connectedSince.Format(time.RFC3339)
        }
        s.ExitIP, s.ExitCountry = c.exitIP, c.exitCountry
        if key := c.store.Key(); key != nil {
                s.HasKey = true
                s.Key = &KeyInfo{
                        Name:      key.PersonName(),
                        Code:      NationalCode(key.KeyID()),
                        KeyID:     key.KeyID(),
                        GB:        key.Payload.Gb,
                        MB:        key.Payload.Mb,
                        ExpiresAt: key.Payload.Exp,
                }
                usage := c.store.Usage(key.KeyID())
                s.UsedBytes = max64(usage.UsedBytes, c.usedBase) + c.counters.Up.Load() + c.counters.Down.Load()
                s.LimitBytes = key.Payload.LimitBytes()
                s.ResetAt = c.store.ResetAt(key.KeyID())
        }
        s.SyncOkAt = c.lastSyncOk
        s.SyncIssue = c.lastIssue
        s.ReportedBytes = c.lastReport
        s.UpBytes = c.counters.Up.Load()
        s.DownBytes = c.counters.Down.Load()
        return s
}

func (c *Core) Shutdown() {
        c.Disconnect()
        c.proxy.Stop()
}

// ---------- server options / logs for the UI ----------

type ServerOption struct {
        Label   string `json:"label"`
        Country string `json:"country"`
        City    string `json:"city"`
}

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

// probeTunnel pushes actual HTTP traffic through a freshly established
// tunnel. "Connected" is only reported when bytes really round-trip, so the
// UI never shows a green state over a dead tunnel.
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
                        return fmt.Errorf("لبهٔ فست‌لی درخواست CONNECT را رد کرد (HTTP %d)", rej.StatusCode)
                }
                lastErr = err
        }
        if lastErr == nil {
                lastErr = errors.New("هیچ مقصدی در دسترس نبود")
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
                        return fmt.Errorf("دست‌دادن TLS آزمایشی: %w", err)
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
                return fmt.Errorf("خواندن پاسخ آزمایش: %w", err)
        }
        if strings.Contains(line, " 204") {
                return nil
        }
        return fmt.Errorf("آزمایش پاسخ %q گرفت", strings.TrimSpace(line))
}

func nowUnix() int64 { return time.Now().Unix() }

func humanBytes(n int64) string {
        const unit = 1000 // plans are decimal (1 GB = 1000 MB), like the Android app
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

// faDigits renders ASCII digits as Persian digits for UI-facing strings.
func faDigits(s string) string {
        var b strings.Builder
        for _, r := range s {
                if r >= '0' && r <= '9' {
                        b.WriteRune(rune('۰') + (r - '0'))
                } else {
                        b.WriteRune(r)
                }
        }
        return b.String()
}
