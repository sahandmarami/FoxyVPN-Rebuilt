//go:build windows

package main

// The app window: a small, fixed, phone-proportioned WebView2 shell that
// hosts the embedded UI served by the local app server. WebView2 (Edge) ships
// with Windows 10/11, so there is nothing else to install.

import (
        "fmt"
        "os"
	"strings"

        "github.com/jchv/go-webview2"
        "github.com/jchv/go-webview2/webviewloader"
)

const (
        windowWidth  = 375
        windowHeight = 800
)

// webView2Available reports whether the Evergreen WebView2 runtime exists on
// this machine, so a missing runtime can be explained in Persian instead of
// a silent no-window.
func webView2Available() bool {
        v, err := webviewloader.GetInstalledVersion()
        return err == nil && strings.TrimSpace(v) != ""
}

func startMainWindow(uiURL string) bool {
        if !webView2Available() {
                fatalBox("مرورگر WebView2 ویندوز پیدا نشد.\n\n" +
                        "برای اجرای FoxyVPN باید «WebView2 Runtime» مایکروسافت روی ویندوز نصب باشد " +
                        "(روی ویندوز ۱۰/۱۱ به‌روز معمولاً از قبل نصب است).\n\n" +
                        "از آدرس زیر آن را نصب کنید و یک‌بار دیگر برنامه را باز کنید:\n" +
                        "https://developer.microsoft.com/microsoft-edge/webview2/")
                return false
        }

        w := webview2.NewWithOptions(webview2.WebViewOptions{
                Debug:     false,
                AutoFocus: true,
                WindowOptions: webview2.WindowOptions{
                        Title:  "FoxyVPN",
                        Width:  windowWidth,
                        Height: windowHeight,
                        Center: true,
                        IconId: 1,
                },
        })
        if w == nil {
                return false
        }
        w.SetTitle("FoxyVPN")
        w.SetSize(windowWidth, windowHeight, webview2.HintFixed)
        w.Navigate(uiURL)
        w.Run()
        return true
}

func exitApp(code int) {
        os.Exit(code)
}

var _ = fmt.Sprintf
