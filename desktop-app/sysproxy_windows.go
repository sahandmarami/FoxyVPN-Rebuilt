//go:build windows

package main

// Windows system proxy management via WinINET registry + refresh broadcast.

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

var (
	wininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOpt = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

func notifyProxyChange() {
	procInternetSetOpt.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	procInternetSetOpt.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

type savedProxy struct {
	enabled   uint64
	server    string
	overrides string
	autoURL   string
	hadValues bool
}

const inetKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func readProxyState() (savedProxy, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return savedProxy{}, err
	}
	defer k.Close()
	s := savedProxy{hadValues: true}
	s.enabled, _, _ = k.GetIntegerValue("ProxyEnable")
	s.server, _, _ = k.GetStringValue("ProxyServer")
	s.overrides, _, _ = k.GetStringValue("ProxyOverride")
	s.autoURL, _, _ = k.GetStringValue("AutoConfigURL")
	return s, nil
}

// cleanupStaleSystemProxy disables a leftover proxy pointing at our own port
// after an unclean exit (crash / kill) so the user is never stuck offline.
func cleanupStaleSystemProxy(httpPort int) {
	s, err := readProxyState()
	if err != nil {
		return
	}
	if s.enabled == 1 && s.server == fmt.Sprintf("127.0.0.1:%d", httpPort) {
		k, kerr := registry.OpenKey(registry.CURRENT_USER, inetKeyPath, registry.SET_VALUE)
		if kerr != nil {
			return
		}
		defer k.Close()
		_ = k.SetDWordValue("ProxyEnable", 0)
		notifyProxyChange()
	}
}

// EnableSystemProxy turns on the WinINET proxy pointing at the local HTTP port.
func EnableSystemProxy(httpPort int, saved *savedProxy) error {
	if s, err := readProxyState(); err == nil {
		*saved = s
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", fmt.Sprintf("127.0.0.1:%d", httpPort)); err != nil {
		return err
	}
	overrides := "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"
	if err := k.SetStringValue("ProxyOverride", overrides); err != nil {
		return err
	}
	notifyProxyChange()
	return nil
}

// DisableSystemProxy restores the previous settings.
func DisableSystemProxy(saved savedProxy) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetKeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	if saved.hadValues {
		_ = k.SetDWordValue("ProxyEnable", uint32(saved.enabled))
		if saved.server != "" {
			_ = k.SetStringValue("ProxyServer", saved.server)
		}
		if saved.overrides != "" {
			_ = k.SetStringValue("ProxyOverride", saved.overrides)
		}
		if saved.autoURL != "" {
			_ = k.SetStringValue("AutoConfigURL", saved.autoURL)
		}
	} else {
		_ = k.SetDWordValue("ProxyEnable", 0)
	}
	notifyProxyChange()
}
