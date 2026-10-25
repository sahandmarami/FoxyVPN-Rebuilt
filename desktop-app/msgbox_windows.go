//go:build windows

package main

// Visible error reporting for the GUI-subsystem build: without a console any
// startup failure would be completely silent, so fatal problems are shown in
// a Win32 message box instead.

import (
	"syscall"
	"unsafe"
)

var (
	user32mod          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW    = user32mod.NewProc("MessageBoxW")
)

const (
	mbIconError      = 0x10
	mbIconInformation = 0x40
	mbTopMost        = 0x40000
)

func utf16Ptr(s string) uintptr {
	p, _ := syscall.UTF16PtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

func messageBox(title, text string, icon uintptr) {
	procMessageBoxW.Call(0, utf16Ptr(text), utf16Ptr(title), icon|mbTopMost)
}

// fatalBox shows an error dialog the user cannot miss.
func fatalBox(text string) {
	messageBox("FoxyVPN", text, mbIconError)
}

func infoBox(text string) {
	messageBox("FoxyVPN", text, mbIconInformation)
}
