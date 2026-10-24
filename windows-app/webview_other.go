//go:build !windows

package main

// Non-Windows stub so `go test ./...` keeps working on the dev machine.

import "os"

func startMainWindow(uiURL string) bool { return false }

func webView2Available() bool { return false }

func exitApp(code int) { os.Exit(code) }
