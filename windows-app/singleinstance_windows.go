//go:build windows

package main

// Single-instance guard via a named Windows mutex, plus a helper that raises
// the window of the already-running instance.

import (
	"errors"
	"syscall"
	"unsafe"
)

var (
	kernel32mod            = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW       = kernel32mod.NewProc("CreateMutexW")
	procShowWindow2        = user32mod.NewProc("ShowWindow")
	procSetForegroundWnd   = user32mod.NewProc("SetForegroundWindow")
	procFindWindowW        = user32mod.NewProc("FindWindowW")
)

const swRestore = 9

const errAlreadyExists = syscall.Errno(183)

// acquireSingleInstance returns true when this is the only running copy.
func acquireSingleInstance() bool {
	name, _ := syscall.UTF16PtrFromString(`Global\FoxyVPN-App-SingleInstance`)
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		// cannot tell — let the port probe below handle duplicates
		return true
	}
	return !errors.Is(err, errAlreadyExists)
}

// raiseExistingWindow restores and focuses an already-running FoxyVPN window.
func raiseExistingWindow() {
	title, _ := syscall.UTF16PtrFromString("FoxyVPN")
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd != 0 {
		procShowWindow2.Call(hwnd, swRestore)
		procSetForegroundWnd.Call(hwnd)
	}
}
