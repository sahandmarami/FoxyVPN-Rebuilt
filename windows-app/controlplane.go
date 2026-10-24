package main

// Shared control-plane HTTP client: Mozilla VPN UA, cookie jar shared across
// FxA / Guardian requests, and the Fastly challenge plumbing (406 retry).

import (
        "fmt"
        "io"
        "net/http"
        "net/url"
        "sort"
        "strings"
        "sync"
        "time"
)

const MozillaVpnUserAgent = "MozillaVPN/2.35.0 (sys:linux; iap:true)"

// simpleJar implements http.CookieJar with an explicit Set() used by the
// Fastly challenge solver to install cookies for the "firefox.com" domain.
type simpleJar struct {
        mu      sync.Mutex
        byName  map[string]map[string]string // domain -> name -> value
}

func newSimpleJar() *simpleJar {
        return &simpleJar{byName: map[string]map[string]string{}}
}

func (j *simpleJar) set(name, value, domain string) {
        j.mu.Lock()
        defer j.mu.Unlock()
        bucket := j.byName[domain]
        if bucket == nil {
                bucket = map[string]string{}
                j.byName[domain] = bucket
        }
        bucket[name] = value
}

func (j *simpleJar) snapshotFor(domain string) [][2]string {
        j.mu.Lock()
        defer j.mu.Unlock()
        var out [][2]string
        for d, bucket := range j.byName {
                if domain == d || strings.HasSuffix(domain, "."+d) {
                        names := make([]string, 0, len(bucket))
                        for n := range bucket {
                                names = append(names, n)
                        }
                        sort.Strings(names)
                        for _, n := range names {
                                out = append(out, [2]string{n, bucket[n]})
                        }
                }
        }
        return out
}

func (j *simpleJar) Cookies(u *url.URL) []*http.Cookie {
        var out []*http.Cookie
        for _, kv := range j.snapshotFor(u.Hostname()) {
                out = append(out, &http.Cookie{Name: kv[0], Value: kv[1]})
        }
        return out
}

func (j *simpleJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
        for _, c := range cookies {
                domain := c.Domain
                if domain == "" {
                        domain = u.Hostname()
                }
                domain = strings.TrimPrefix(domain, ".")
                j.set(c.Name, c.Value, domain)
        }
}

// controlPlane is the shared HTTP client for api.accounts.firefox.com and
// vpn.mozilla.org. It never uses a proxy.
var controlPlane *http.Client

func initControlPlane() {
        controlPlane = &http.Client{
                Timeout: 30 * time.Second,
                Jar:     newSimpleJar(),
                Transport: &http.Transport{
                        MaxIdleConns:        16,
                        IdleConnTimeout:     60 * time.Second,
                        TLSHandshakeTimeout: 15 * time.Second,
                        ForceAttemptHTTP2:   true,
                },
        }
}

// challengeSolveFunc is installed by fastly.go; returns an error on failure.
var challengeSolveFunc = func() error {
        return fmt.Errorf("fastly challenge solver not initialised")
}

func doControlJSON(method, rawURL, bearer, sessionToken, jsonBody string, challengeRetries int) ([]byte, int, error) {
        for attempt := 0; ; attempt++ {
                req, err := newControlRequest(method, rawURL, bearer, jsonBody)
                if err != nil {
                        return nil, 0, err
                }
                if sessionToken != "" {
                        id, key, err := deriveHawkCredentials(sessionToken)
                        if err != nil {
                                return nil, 0, err
                        }
                        hdr, err := hawkHeader(method, rawURL, id, key, []byte(jsonBody))
                        if err != nil {
                                return nil, 0, err
                        }
                        req.Header.Set("Authorization", hdr)
                }
                body, status, _, err := execControlWithChallenge(req, challengeRetries)
                if err != nil {
                        return nil, status, err
                }
                if status >= 400 {
                        return body, status, nil
                }
                return body, status, nil
        }
}

func newControlRequest(method, rawURL, bearer, jsonBody string) (*http.Request, error) {
        var bodyReader ioReader
        if jsonBody != "" {
                bodyReader = strings.NewReader(jsonBody)
        } else if method == "POST" {
                bodyReader = strings.NewReader("")
        }
        req, err := http.NewRequest(method, rawURL, bodyReader)
        if err != nil {
                return nil, err
        }
        req.Header.Set("User-Agent", MozillaVpnUserAgent)
        req.Header.Set("Accept", "application/json")
        if jsonBody != "" {
                req.Header.Set("Content-Type", "application/json")
        }
        if bearer != "" {
                req.Header.Set("Authorization", "Bearer "+bearer)
        }
        return req, nil
}

func execControlWithChallenge(req *http.Request, challengeRetries int) ([]byte, int, httpHeaders, error) {
        for attempt := 0; ; attempt++ {
                body, status, headers, err := execControl(req)
                if err != nil {
                        return nil, status, nil, err
                }
                if status == 406 && attempt < challengeRetries {
                        if serr := challengeSolveFunc(); serr != nil {
                                return nil, status, nil, fmt.Errorf("Fastly challenge failed: %v", serr)
                        }
                        continue
                }
                return body, status, headers, nil
        }
}

func execControl(req *http.Request) ([]byte, int, httpHeaders, error) {
        resp, err := controlPlane.Do(req)
        if err != nil {
                return nil, 0, nil, err
        }
        defer resp.Body.Close()
        buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        headers := httpHeaders(resp.Header)
        return buf, resp.StatusCode, headers, nil
}

type ioReader interface {
        Read(p []byte) (int, error)
}
