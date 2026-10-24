//go:build !windows

package main

// Non-Windows stub: the phone + native widget UIs are Windows-only; other
// platforms use the browser panel.

func startNativeWindow(core *Core, panelURL, dataDir string) bool { return false }

func startPhoneWindow(core *Core, panelURL, dataDir string) bool { return false }
