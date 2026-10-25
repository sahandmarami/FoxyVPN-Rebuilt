package main

// Server list from Mozilla Remote Settings (port of ServerListClient.kt).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var remoteSettingsURL = "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

type VpnProtocol struct {
	Name          string `json:"name"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Scheme        string `json:"scheme"`
	TemplateStr   string `json:"templateString"`
}

type VpnServerNode struct {
	Hostname    string        `json:"hostname"`
	Port        int           `json:"port"`
	Quarantined bool          `json:"quarantined"`
	Protocols   []VpnProtocol `json:"protocols"`
}

type VpnCity struct {
	Name    string          `json:"name"`
	Code    string          `json:"code"`
	Servers []VpnServerNode `json:"servers"`
}

type VpnCountry struct {
	Name   string    `json:"name"`
	Code   string    `json:"code"`
	Cities []VpnCity `json:"cities"`
}

type ProxyCandidate struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CityCode   string `json:"city_code"`
	CityName   string `json:"city_name"`
}

type ServerList struct {
	mu        sync.Mutex
	countries []VpnCountry
	fetchedAt time.Time
	cachePath string
}

func NewServerList(cachePath string) *ServerList { return &ServerList{cachePath: cachePath} }

func (s *ServerList) Countries() []VpnCountry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countries
}

func (s *ServerList) Refresh(force bool) ([]VpnCountry, error) {
	s.mu.Lock()
	if !force && len(s.countries) > 0 && time.Since(s.fetchedAt) < 10*time.Minute {
		out := s.countries
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()

	req, _ := http.NewRequest("GET", remoteSettingsURL, nil)
	req.Header.Set("User-Agent", MozillaVpnUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := controlPlane.Do(req)
	if err != nil {
		// fall back to cache
		if cached := s.loadCache(); len(cached) > 0 {
			s.mu.Lock()
			s.countries = cached
			s.mu.Unlock()
			return cached, nil
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if cached := s.loadCache(); len(cached) > 0 {
			s.mu.Lock()
			s.countries = cached
			s.mu.Unlock()
			return cached, nil
		}
		return nil, fmt.Errorf("Remote Settings fetch failed: HTTP %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	countries := parseRecords(string(raw))
	if len(countries) == 0 {
		if cached := s.loadCache(); len(cached) > 0 {
			s.mu.Lock()
			s.countries = cached
			s.mu.Unlock()
			return cached, nil
		}
		return nil, fmt.Errorf("server list is empty")
	}
	s.mu.Lock()
	s.countries = countries
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	s.saveCache(string(raw))
	return countries, nil
}

func (s *ServerList) loadCache() []VpnCountry {
	if s.cachePath == "" {
		return nil
	}
	raw, err := os.ReadFile(s.cachePath)
	if err != nil {
		return nil
	}
	return parseRecords(string(raw))
}

func (s *ServerList) saveCache(raw string) {
	if s.cachePath == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.cachePath), 0o700)
	_ = os.WriteFile(s.cachePath, []byte(raw), 0o600)
}

func parseRecords(raw string) []VpnCountry {
	var body struct {
		Data []struct {
			Code string `json:"code"`
			Name string `json:"name"`
			Cities []struct {
				Code    string `json:"code"`
				Name    string `json:"name"`
				Servers []VpnServerNode `json:"servers"`
			} `json:"cities"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return nil
	}
	var out []VpnCountry
	for _, c := range body.Data {
		if strings.EqualFold(c.Name, "CatchAll Anycast") {
			continue
		}
		country := VpnCountry{Name: c.Name, Code: c.Code}
		for _, city := range c.Cities {
			var servers []VpnServerNode
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				servers = append(servers, srv)
			}
			if len(servers) > 0 {
				country.Cities = append(country.Cities, VpnCity{Name: city.Name, Code: city.Code, Servers: servers})
			}
		}
		if country.Code != "" && len(country.Cities) > 0 {
			out = append(out, country)
		}
	}
	return out
}

// connectTarget mirrors ServerListClient.defaultConnectTarget.
func connectTarget(server VpnServerNode) (string, int, bool) {
	for _, proto := range server.Protocols {
		if proto.Name == "connect" {
			host := proto.Host
			if host == "" {
				host = server.Hostname
			}
			port := proto.Port
			if port == 0 {
				port = server.Port
			}
			return host, port, true
		}
	}
	if len(server.Protocols) == 0 {
		return server.Hostname, server.Port, true
	}
	return "", 0, false
}

func candidates(countries []VpnCountry, countryCode, cityCode string) []ProxyCandidate {
	var out []ProxyCandidate
	for _, country := range countries {
		if countryCode != "" && !strings.EqualFold(country.Code, countryCode) {
			continue
		}
		for _, city := range country.Cities {
			if cityCode != "" && !strings.EqualFold(city.Code, cityCode) {
				continue
			}
			for _, server := range city.Servers {
				if server.Quarantined {
					continue
				}
				if host, port, ok := connectTarget(server); ok {
					out = append(out, ProxyCandidate{
						Host: host, Port: port,
						CountryCode: country.Code, CountryName: country.Name,
						CityCode: city.Code, CityName: city.Name,
					})
				}
			}
		}
	}
	return out
}
