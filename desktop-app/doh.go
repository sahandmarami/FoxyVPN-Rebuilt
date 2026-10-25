package main

// DNS-over-HTTPS resolver (port of EdgeAddressResolver.kt + DohDnsClient).
// Used to resolve the Fastly edge IP without relying on the local (possibly
// poisoned) DNS resolver, and to resolve user destinations before tunneling.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const dohPath = "/dns-query"

var dohEndpoints = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

type DohResolver struct {
	client  *http.Client
	mu      sync.Mutex
	cache   map[string]cacheEntry
	backoff map[string]time.Time
}

type cacheEntry struct {
	ips       []string
	expiresAt time.Time
}

func NewDohResolver() *DohResolver {
	return &DohResolver{
		client: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				DialContext:       (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
			},
		},
		cache:   map[string]cacheEntry{},
		backoff: map[string]time.Time{},
	}
}

func buildDNSQuery(hostname string, qtype uint16) ([]byte, error) {
	labels := bytes.Split([]byte(hostname), []byte("."))
	if len(labels) == 0 {
		return nil, errors.New("empty hostname")
	}
	var out bytes.Buffer
	out.Write([]byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}) // header: id=0, RD=1, 1 question
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("bad label")
		}
		out.WriteByte(byte(len(label)))
		out.Write(label)
	}
	out.WriteByte(0)
	binary.Write(&out, binary.BigEndian, qtype)
	binary.Write(&out, binary.BigEndian, uint16(1)) // IN
	return out.Bytes(), nil
}

func parseDNSAddresses(msg []byte, wantType uint16) []string {
	if len(msg) < 12 || msg[3]&0x0F != 0 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	if an == 0 {
		return nil
	}
	off := 12
	for i := 0; i < qd; i++ {
		o, ok := skipDNSName(msg, off)
		if !ok {
			return nil
		}
		off = o + 4
	}
	var out []string
	for i := 0; i < an && off+10 <= len(msg); i++ {
		o, ok := skipDNSName(msg, off)
		if !ok {
			return out
		}
		off = o
		if off+10 > len(msg) {
			return out
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out
		}
		if rtype == wantType && ((wantType == 1 && rdlen == 4) || (wantType == 28 && rdlen == 16)) {
			ip := net.IP(append([]byte{}, msg[off:off+rdlen]...))
			out = append(out, ip.String())
		}
		off += rdlen
	}
	return out
}

func skipDNSName(msg []byte, off int) (int, bool) {
	for {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		}
		if l > 63 {
			return 0, false
		}
		off += 1 + l
	}
}

func isIPLiteral(host string) bool {
	if stringsContains(host, ":") {
		return net.ParseIP(host) != nil
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil && stringsCount(host, ".") == 3
}

// Resolve returns an IP for host, preferring IPv4, via DoH with cache.
func (r *DohResolver) Resolve(host string) (string, bool) {
	host = trimLower(host)
	if host == "" || isIPLiteral(host) {
		return host, host != ""
	}
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expiresAt) && len(e.ips) > 0 {
		ip := e.ips[0]
		r.mu.Unlock()
		return ip, true
	}
	r.mu.Unlock()

	ip, ok := r.resolveDoH(host)
	if !ok {
		// fall back to the system resolver
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			for _, candidate := range ips {
				if v4 := candidate.To4(); v4 != nil {
					ip, ok = v4.String(), true
					break
				}
			}
			if !ok {
				ip, ok = ips[0].String(), true
			}
		}
	}
	if ok {
		r.mu.Lock()
		r.cache[host] = cacheEntry{ips: []string{ip}, expiresAt: time.Now().Add(5 * time.Minute)}
		r.mu.Unlock()
	}
	return ip, ok
}

func (r *DohResolver) resolveDoH(host string) (string, bool) {
	q4, err := buildDNSQuery(host, 1)
	if err != nil {
		return "", false
	}
	// race all healthy endpoints in parallel; first successful answer wins
	type res struct {
		ip string
		ok bool
	}
	results := make(chan res, len(dohEndpoints))
	var wg sync.WaitGroup
	for _, endpoint := range dohEndpoints {
		if t, ok := r.backoff[endpoint]; ok && time.Now().Before(t) {
			continue
		}
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			ip, ok := r.queryEndpoint(endpoint, host, q4)
			results <- res{ip, ok}
		}(endpoint)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	for out := range results {
		if out.ok {
			return out.ip, true
		}
	}
	return "", false
}

func (r *DohResolver) queryEndpoint(endpoint, host string, q4 []byte) (string, bool) {
	req, _ := http.NewRequest("POST", endpoint+dohPath, bytes.NewReader(q4))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		r.backoff[endpoint] = time.Now().Add(30 * time.Minute)
		return "", false
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		r.backoff[endpoint] = time.Now().Add(30 * time.Minute)
		return "", false
	}
	ips := parseDNSAddresses(buf.Bytes(), 1)
	if len(ips) > 0 {
		return ips[0], true
	}
	// no A record — try AAAA on the same endpoint
	q6, err := buildDNSQuery(host, 28)
	if err != nil {
		return "", false
	}
	req2, _ := http.NewRequest("POST", endpoint+dohPath, bytes.NewReader(q6))
	req2.Header.Set("Content-Type", "application/dns-message")
	req2.Header.Set("Accept", "application/dns-message")
	resp2, err := r.client.Do(req2)
	if err != nil {
		return "", false
	}
	buf2 := new(bytes.Buffer)
	_, _ = buf2.ReadFrom(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode == 200 {
		ips6 := parseDNSAddresses(buf2.Bytes(), 28)
		if len(ips6) > 0 {
			return ips6[0], true
		}
	}
	return "", false
}

// EdgeAddress resolves the tunnel edge host to an IP (mirrors resolveEdgeAddress).
func (r *DohResolver) EdgeAddress(host string) (string, bool) {
	return r.Resolve(host)
}

func trimLower(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out = append(out, c)
	}
	return string(out)
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func stringsCount(s, sub string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			n++
		}
	}
	return n
}

var _ = fmt.Sprintf // keep fmt import
