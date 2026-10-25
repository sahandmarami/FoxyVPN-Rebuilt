//go:build windows

package main

// Native window: WebView2 renders the same embedded UI the browser fallback
// would show, inside a large desktop-sized window (proportional to the
// monitor, resizable and maximizable) with the app icon. Closing the window
// exits the app cleanly.

import (
        "os/exec"

        webview2 "github.com/jchv/go-webview2"
        "github.com/jchv/go-webview2/webviewloader"
)

const windowTitle = "FoxyVPN"

var procGetSystemMetrics = user32mod.NewProc("GetSystemMetrics")

const (
        smCxScreen = 0
        smCyScreen = 1
)

func screenWidth() int  { v, _, _ := procGetSystemMetrics.Call(smCxScreen); return int(int32(v)) }
func screenHeight() int { v, _, _ := procGetSystemMetrics.Call(smCyScreen); return int(int32(v)) }

// desktopWindowSize picks a window size that feels like a real desktop app:
// generously big on large monitors, but never larger than the screen itself.
// The manifest is system-DPI-aware, so these are real monitor pixels.
func desktopWindowSize() (int, int) {
        sw, sh := screenWidth(), screenHeight()
        if sw <= 0 {
                sw = 1920
        }
        if sh <= 0 {
                sh = 1080
        }
        w := sw * 62 / 100 // 62% of screen width
        h := sh * 72 / 100 // 72% of screen height
        if w > 1220 {
                w = 1220
        }
        if w < 980 {
                w = 980
        }
        if h > 800 {
                h = 800
        }
        if h < 600 {
                h = 600
        }
        // final safety: always fit the actual monitor (taskbar headroom included)
        if w > sw-40 {
                w = sw - 40
        }
        if h > sh-120 {
                h = sh - 120
        }
        if w < 600 {
                w = 600
        }
        if h < 480 {
                h = 480
        }
        return w, h
}

func webView2Installed() bool {
        ver, err := webviewloader.GetInstalledVersion()
        return err == nil && ver != ""
}

// startNativeWindow blocks until the user closes the window.
// Returns true when the window actually ran (so the caller exits cleanly),
// false when WebView2 is unavailable (caller falls back to the browser).
func startNativeWindow(core *Core, panelURL, dataDir string) bool {
        if !webView2Installed() {
                offerWebView2Install()
                return false
        }
        winW, winH := desktopWindowSize()
        w := webview2.NewWithOptions(webview2.WebViewOptions{
                Debug:     false,
                AutoFocus: true,
                WindowOptions: webview2.WindowOptions{
                        Title:  windowTitle,
                        Width:  winW,
                        Height: winH,
                        IconId: 1, // icon embedded by go-winres
                        Center: true,
                },
        })
        if w == nil {
                return false
        }
        // a real desktop window: resizable, maximizable, with a sane minimum size
        w.SetSize(winW, winH, webview2.HintNone)
        w.SetSize(880, 560, webview2.HintMin)
        w.Navigate(panelURL)
        w.Run()
        w.Destroy()
        return true
}

func offerWebView2Install() {
        const msg = "برای نمایش پنجرهٔ برنامه، کامپوننت رایگان WebView2 مایکروسافت لازم است.\n\n" +
                "روی دکمهٔ OK بزنید تا صفحهٔ دانلود رسمی باز شود؛ بعد از نصب، برنامه را دوباره اجرا کنید.\n\n" +
                "(ویندوز ۱۱ و اکثر ویندوزهای ۱۰ این کامپوننت را از قبل دارند)"
        messageBox("FoxyVPN", msg, mbIconInformation)
        _ = exec.Command("rundll32", "url.dll,FileProtocolHandler",
                "https://developer.microsoft.com/en-us/microsoft-edge/webview2/").Start()
}
