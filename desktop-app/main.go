package main

// FoxyVPN Desktop — completely rebuilt Windows client.
//
// New mechanism: no email/password, no panel, no manual proxy settings.
// Activate with a signed quota key (the same FV1 keys the Android app uses,
// or their 10-digit «کد ملی» shortcut), press connect, done — the system
// proxy is switched over automatically and restored on exit.

import (
        "flag"
        "fmt"
        "log"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "runtime/debug"
        "strings"
)

const appVersion = "1.0.0"

// devMockHook is set only in devmock builds (go build -tags devmock).
var devMockHook func(port int)

var (
        flagSocksPort = flag.Int("socks-port", 1080, "local SOCKS5 port")
        flagHTTPPort  = flag.Int("http-port", 8080, "local HTTP proxy port")
        flagUIPort    = flag.Int("ui-port", 8097, "local UI port")
        flagBind      = flag.String("bind", "127.0.0.1", "bind address for proxies/UI")
        flagTLSSplit  = flag.String("tls-split", "sni", "TLS ClientHello split mode: off | first-byte | sni")
        flagEdge      = flag.String("edge", "", "custom edge IP (TCP) while keeping SNI/verification")
        flagUpstream  = flag.String("upstream", "", "upstream SOCKS5 proxy (host:port) to chain through")
        flagDataDir   = flag.String("data-dir", "", "config/data directory")
        flagUI        = flag.String("ui", "native", "interface: native (app window) | browser")
)

func main() {
        // never die silently: surface any startup panic in a visible dialog
        defer func() {
                if r := recover(); r != nil {
                        msg := fmt.Sprintf("FoxyVPN شروع نشد.\n\n%v\n\nجزئیات در %%APPDATA%%\\FoxyVPN-Desktop\\foxyvpn.log", r)
                        if logFile != nil {
                                fmt.Fprintf(logFile, "PANIC: %v\n%s", r, debug.Stack())
                        }
                        fatalBox(msg)
                        os.Exit(1)
                }
        }()
        flag.Parse()

        // subcommands for smoke tests / CLI use
        if len(flag.Args()) > 0 {
                if flag.Args()[0] == "mockui" && devMockHook != nil {
                        devMockHook(*flagUIPort)
                        return
                }
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
                dataDir = filepath.Join(base, "FoxyVPN-Desktop")
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

        // single-instance: never spawn a second copy silently
        if !acquireSingleInstance() {
                logger.Warnf("یک نسخهٔ دیگر از FoxyVPN از قبل در حال اجراست")
                raiseExistingWindow()
                infoBox("FoxyVPN از قبل در حال اجراست!\n\nپنجرهٔ برنامه جلو آورده شد.")
                return
        }
        // clear a leftover system proxy from an unclean previous exit
        cleanupStaleSystemProxy(*flagHTTPPort)

        store := NewKeyStore(dataDir)
        store.Load()
        gist := NewGistReporter()

        core, err := NewCore(CoreConfig{
                DataDir:       dataDir,
                SocksPort:     *flagSocksPort,
                HttpPort:      *flagHTTPPort,
                UIPort:        *flagUIPort,
                Bind:          *flagBind,
                TLSSplit:      tlsSplit,
                EdgeAddress:   *flagEdge,
                UpstreamProxy: *flagUpstream,
        }, logger, store, gist)
        if err != nil {
                logger.Errorf("startup failed: %v", err)
                fatalBox(fmt.Sprintf("FoxyVPN شروع نشد: %v", err))
                os.Exit(1)
        }

        api, err := NewAPIServer(core, logger, *flagBind, *flagUIPort)
        if err != nil {
                logger.Errorf("UI startup failed: %v", err)
                fatalBox(fmt.Sprintf("FoxyVPN شروع نشد: پورت رابط آزاد نیست.\n\n%v", err))
                os.Exit(1)
        }
        api.Start()
        core.cfg.UIPort = api.Port()

        panelURL := fmt.Sprintf("http://127.0.0.1:%d/", api.Port())
        logger.Infof("رابط کاربری آماده است: %s", panelURL)

        // auto-connect: the window comes up and the VPN reconnects by itself
        if store.Key() != nil && store.AutoConnect() {
                go func() {
                        if err := core.Connect("", ""); err != nil {
                                logger.Warnf("اتصال خودکار ناموفق بود: %v", err)
                        }
                }()
        }

        // exit path: window closed, /api/exit called, or fatal
        go func() {
                select {
                case <-exitRequested:
                }
                core.ShutdownQuick()
                os.Exit(0)
        }()

        if strings.EqualFold(*flagUI, "native") {
                // blocks until the window is closed
                if startNativeWindow(core, panelURL, dataDir) {
                        core.ShutdownQuick()
                        return
                }
                logger.Warnf("پنجرهٔ بومی در دسترس نیست؛ باز کردن رابط در مرورگر…")
        }

        _ = openBrowser(panelURL)
        <-exitRequested
        core.ShutdownQuick()
}

func openBrowser(url string) error {
        switch runtime.GOOS {
        case "windows":
                return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
        case "darwin":
                return exec.Command("open", url).Start()
        default:
                return exec.Command("xdg-open", url).Start()
        }
}
