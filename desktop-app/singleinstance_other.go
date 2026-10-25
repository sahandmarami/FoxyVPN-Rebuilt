//go:build !windows

package main

// Non-Windows stubs: single-instance guard and window raising are
// Windows-only. Other platforms always proceed.

func acquireSingleInstance() bool { return true }

func raiseExistingWindow() {}
