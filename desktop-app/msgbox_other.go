//go:build !windows

package main

// Non-Windows stubs: message boxes only exist on Windows.

import "log"

func fatalBox(text string) { log.Printf("[fatal] %s", text) }

func infoBox(text string) { log.Printf("[info] %s", text) }
