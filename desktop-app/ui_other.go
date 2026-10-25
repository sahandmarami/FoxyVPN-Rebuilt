//go:build !windows

package main

// Non-Windows stub: the native WebView2 window only exists on Windows.
// Other platforms open the UI in the default browser.

import "log"

func webView2Installed() bool { return false }

func startNativeWindow(core *Core, panelURL, dataDir string) bool {
	log.Printf("native window is only supported on Windows; use the browser UI at %s", panelURL)
	return false
}
