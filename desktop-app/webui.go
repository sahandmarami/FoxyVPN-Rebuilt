//go:build windows

package main

// Native window: WebView2 renders the same embedded UI the browser fallback
// would show, inside a fixed, phone-shaped, centered window with the app
// icon. Closing the window exits the app cleanly.

import (
	"os/exec"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
)

const (
	windowTitle  = "FoxyVPN"
	windowWidth  = 400
	windowHeight = 700
)

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
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  windowTitle,
			Width:  windowWidth,
			Height: windowHeight,
			IconId: 1, // icon embedded by go-winres
			Center: true,
		},
	})
	if w == nil {
		return false
	}
	// fixed phone-shaped window: no resize, no maximize
	w.SetSize(windowWidth, windowHeight, webview2.HintFixed)
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
