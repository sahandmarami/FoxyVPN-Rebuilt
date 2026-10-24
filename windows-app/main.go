package main

// FoxyVPN for Windows v3 — unofficial Firefox VPN client (the exe twin of the
// Android app). Activation is by the signed FV1 quota key exactly like the
// Android app; the traffic path is the same Guardian proxy pass over an
// HTTP/2 CONNECT tunnel to the Fastly edge, exposed to Windows apps through
// local SOCKS5/HTTP proxies (plus the WinINET system proxy toggle).

import (
        "context"
        "encoding/json"
        "flag"
        "fmt"
        "log"
        "net/http"
        "os"
        "path/filepath"
        "runtime/debug"
        "strings"
        "time"
)

const appVersion = "3.0.0"

var (
        flagSocksPort = flag.Int("socks-port", 1080, "local SOCKS5 port")
        flagHTTPPort  = flag.Int("http-port", 8080, "local HTTP proxy port")
        flagUIPort    = flag.Int("ui-port", 8097, "local app-server port")
        flagBind      = flag.String("bind", "127.0.0.1", "bind address for proxies/app server")
        flagTLSSplit  = flag.String("tls-split", "sni", "TLS ClientHello split mode: off | first-byte | sni")
        flagEdgeAddress = flag.String("edge", "", "custom edge IP (TCP) while keeping SNI/verification")
        flagUpstream    = flag.String("upstream", "", "upstream SOCKS5 proxy (host:port) to chain through")
        flagDataDir     = flag.String("data-dir", "", "config/data directory")
)

func main() {
        // GUI-subsystem build: there is no console anywhere, so surface any
        // startup panic in a visible dialog instead of dying silently.
        defer func() {
                if r := recover(); r != nil {
                        msg := fmt.Sprintf("FoxyVPN نتوانست اجرا شود.\n\n%v\n\nجزئیات: %%APPDATA%%\\FoxyVPN\\foxyvpn.log", r)
                        if logFile != nil {
                                fmt.Fprintf(logFile, "PANIC: %v\n%s", r, debug.Stack())
                        }
                        fatalBox(msg)
                        os.Exit(1)
                }
        }()
        flag.Parse()

        // hidden smoke-test subcommands (run from a terminal, no GUI)
        if len(flag.Args()) > 0 {
                runCLI(flag.Args())
                return
        }

        logger := NewLogger()
        initControlPlane()
        challengeSolveFunc = solveFastlyChallenge

        dataDir := *flagDataDir
        if dataDir == "" {
                base, err := os.UserConfigDir()
                if err != nil {
                        base = "."
                }
                dataDir = filepath.Join(base, "FoxyVPN")
        }
        if f, err := os.OpenFile(filepath.Join(dataDir, "foxyvpn.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
                logFile = f
                log.SetOutput(f) // capture library-level fatals too
        }

        tlsSplit := strings.ToLower(*flagTLSSplit)
        switch tlsSplit {
        case "off", "none", "":
                tlsSplit = ""
        case "first-byte", "firstbyte":
                tlsSplit = "first-byte"
        case "sni":
                tlsSplit = "sni"
        }

        // single-instance: a second copy raises the existing window and exits
        if !acquireSingleInstance() {
                logger.Warnf("another FoxyVPN instance is already running")
                raiseExistingWindow()
                infoBox("FoxyVPN از قبل در حال اجراست!\n\nپنجرهٔ برنامه جلو آورده شد.")
                return
        }
        // clear a leftover system proxy from an unclean previous exit
        cleanupStaleSystemProxy(*flagHTTPPort)
        if isFoxyAppAlive(*flagUIPort) {
                logger.Warnf("another FoxyVPN app server is already running on port %d", *flagUIPort)
                infoBox("FoxyVPN از قبل در حال اجراست!\n\nبرای اجرای نسخهٔ جدید، ابتدا از برنامهٔ فعلی خارج شوید.")
                return
        }

        core, err := NewCore(CoreConfig{
                DataDir:       dataDir,
                SocksPort:     *flagSocksPort,
                HttpPort:      *flagHTTPPort,
                UIPort:        *flagUIPort,
                Bind:          *flagBind,
                TLSSplit:      tlsSplit,
                EdgeAddress:   *flagEdgeAddress,
                UpstreamProxy: *flagUpstream,
        }, logger)
        if err != nil {
                logger.Errorf("startup failed: %v", err)
                fatalBox(fmt.Sprintf("FoxyVPN نتوانست اجرا شود:\n%v", err))
                os.Exit(1)
        }

        api, err := NewAPIServer(core, logger, *flagBind, *flagUIPort)
        if err != nil {
                logger.Errorf("app server startup failed: %v", err)
                fatalBox(fmt.Sprintf("FoxyVPN نتوانست اجرا شود: پورت محلی در دسترس نیست.\n\n%v", err))
                os.Exit(1)
        }
        api.Start()
        core.cfg.UIPort = api.Port()

        uiURL := fmt.Sprintf("http://127.0.0.1:%d/", api.Port())
        logger.Infof("app server ready at %s", uiURL)

        go core.RestoreSession()

        // blocks until the user closes the window
        if startMainWindow(uiURL) {
                // window closed → clean shutdown: tunnel down, proxy restored
                core.ShutdownQuick()
                return
        }
        // window could not be created (WebView2 missing is already explained in
        // a dialog); keep the proxies from lingering silently
        core.ShutdownQuick()
        os.Exit(1)
}

// isFoxyAppAlive probes a local port for a running FoxyVPN app server.
func isFoxyAppAlive(port int) bool {
        client := &http.Client{Timeout: 800 * time.Millisecond}
        ctx, cancel := context.WithTimeout(context.Background(), time.Second)
        defer cancel()
        req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/api/state", port), nil)
        if err != nil {
                return false
        }
        resp, err := client.Do(req)
        if err != nil {
                return false
        }
        defer resp.Body.Close()
        var st struct {
                State string `json:"state"`
        }
        return json.NewDecoder(resp.Body).Decode(&st) == nil && st.State != ""
}
