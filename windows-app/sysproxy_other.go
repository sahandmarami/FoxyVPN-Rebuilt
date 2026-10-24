//go:build !windows

package main

// Non-Windows stubs: system proxy management is Windows-only for now.

type savedProxy struct{}

func EnableSystemProxy(httpPort int, saved *savedProxy) error {
	return errSysProxyUnsupported
}

func DisableSystemProxy(saved savedProxy) {}

func cleanupStaleSystemProxy(httpPort int) {}

var errSysProxyUnsupported = errUnsupported{}

type errUnsupported struct{}

func (errUnsupported) Error() string { return "system proxy management is only supported on Windows" }
