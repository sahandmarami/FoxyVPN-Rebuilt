package main

// FoxyVPN for Windows — unofficial Firefox VPN client (port of the Android
// FoxyVPN app). Logs in with a Firefox account, mints a Guardian proxy pass
// and tunnels traffic over HTTP/2 CONNECT to the Fastly edge.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const appVersion = "2.0.0"

var (
	flagSocksPort   = flag.Int("socks-port", 1080, "local SOCKS5 port")
	flagHTTPPort    = flag.Int("http-port", 8080, "local HTTP proxy port")
	flagUIPort      = flag.Int("ui-port", 8097, "local panel port")
	flagBind        = flag.String("bind", "127.0.0.1", "bind address for proxies/panel")
	flagUI          = flag.String("ui", "phone", "interface: phone (default, looks like the Android app) | native (classic panel) | browser")
	flagTLSSplit    = flag.String("tls-split", "sni", "TLS ClientHello split mode: off | first-byte | sni")
	flagEdgeAddress = flag.String("edge", "", "custom edge IP (TCP) while keeping SNI/verification")
	flagUpstream    = flag.String("upstream", "", "upstream SOCKS5 proxy (host:port) to chain through")
	flagDataDir     = flag.String("data-dir", "", "config/data directory")
	flagLang        = flag.String("lang", "fa", "panel language: fa | en")
	flagNoTray      = flag.Bool("no-tray", false, "no-op (kept for compatibility)")
)

func main() {
	// never die silently: surface any startup panic in a visible dialog
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("FoxyVPN could not start.\n\n%v\n\nDetails written to %%APPDATA%%\\FoxyVPN\\foxyvpn.log", r)
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

	// single-instance: never spawn a second copy silently
	if !acquireSingleInstance() {
		logger.Warnf("another FoxyVPN instance is already running")
		raiseExistingWindow()
		infoBox("FoxyVPN \u0627\u0632 \u0642\u0628\u0644 \u062f\u0631 \u062d\u0627\u0644 \u0627\u062c\u0631\u0627\u0633\u062a!\n\n\u067e\u0646\u062c\u0631\u0647 \u0628\u0631\u0646\u0627\u0645\u0647 \u062c\u0644\u0648 \u0622\u0648\u0631\u062f\u0647 \u0634\u062f. \u0622\u06cc\u06a9\u0648\u0646 \u0628\u0631\u0646\u0627\u0645\u0647 \u06a9\u0646\u0627\u0631 \u0633\u0627\u0639\u062a \u0648\u06cc\u0646\u062f\u0648\u0632 \u0646\u06cc\u0632 \u062f\u0631 \u062f\u0633\u062a\u0631\u0633 \u0627\u0633\u062a.")
		return
	}
	// clear a leftover system proxy from an unclean previous exit
	cleanupStaleSystemProxy(*flagHTTPPort)
	if isFoxyPanelAlive(*flagUIPort) {
		logger.Warnf("another FoxyVPN panel is already running on port %d", *flagUIPort)
		infoBox("FoxyVPN \u0627\u0632 \u0642\u0628\u0644 \u062f\u0631 \u062d\u0627\u0644 \u0627\u062c\u0631\u0627\u0633\u062a!\n\n\u0628\u0631\u0627\u06cc \u0627\u062c\u0631\u0627\u06cc \u0646\u0633\u062e\u0647 \u062c\u062f\u06cc\u062f\u060c \u0627\u0628\u062a\u062f\u0627 \u0627\u0632 \u0628\u0631\u0646\u0627\u0645\u0647\u0650 \u0641\u0639\u0644\u06cc \u062e\u0627\u0631\u062c \u0634\u0648\u06cc\u062f.")
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
		fatalBox(fmt.Sprintf("FoxyVPN could not start: %v", err))
		os.Exit(1)
	}

	api, err := NewAPIServer(core, logger, *flagBind, *flagUIPort)
	if err != nil {
		logger.Errorf("panel startup failed: %v", err)
		fatalBox(fmt.Sprintf("FoxyVPN could not start: the panel port is unavailable.\n\n%v", err))
		os.Exit(1)
	}
	api.Start()
	core.cfg.UIPort = api.Port()

	panelURL := fmt.Sprintf("http://127.0.0.1:%d/?lang=%s", api.Port(), *flagLang)
	logger.Infof("panel ready at %s", panelURL)

	go core.RestoreSession()

	if strings.EqualFold(*flagUI, "phone") {
		// blocks until exitApp() hard-exits the process
		if startPhoneWindow(core, panelURL, dataDir) {
			return
		}
		logger.Warnf("phone window unavailable; falling back to the classic native window")
	}

	if strings.EqualFold(*flagUI, "native") || strings.EqualFold(*flagUI, "phone") {
		// blocks until exitApp() hard-exits the process
		if startNativeWindow(core, panelURL, dataDir) {
			return
		}
		logger.Warnf("native window unavailable; falling back to the browser panel")
	}

	go openBrowser(panelURL)
	select {} // run forever; the process is terminated via the panel/API
}

// isFoxyPanelAlive probes a local port for a running FoxyVPN panel.
func isFoxyPanelAlive(port int) bool {
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

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}
