package main

// Guardian service client (port of GuardianClient.kt) — proxy pass minting.

import (
        "encoding/json"
        "errors"
        "fmt"
        "strings"
)

const guardianEndpoint = "https://vpn.mozilla.org"

var (
        errTokenInvalid  = errors.New("access token was rejected by Guardian")
        errQuotaExceeded = errors.New("account proxy quota exceeded")
)

type ProxyPass struct {
        Token       string `json:"token"`
        ExpiresAt   int64  `json:"expires_at"`
        QuotaMax    *int64 `json:"quota_max,omitempty"`
        QuotaRemain *int64 `json:"quota_remaining,omitempty"`
        QuotaReset  *int64 `json:"quota_reset,omitempty"`
}

type Entitlement struct {
        Subscribed       bool   `json:"subscribed"`
        UID              string `json:"uid"`
        MaxBytes         *int64 `json:"maxBytes"`
        LimitedBandwidth bool   `json:"limited_bandwidth"`
        QuotaRemaining   *int64 `json:"quota_remaining,omitempty"`
}

type GuardianClient struct{}

func guardianRequest(method, path, accessToken string) ([]byte, int, httpHeaders, error) {
        url := guardianEndpoint + path
        req, err := newControlRequest(method, url, accessToken, "")
        if err != nil {
                return nil, 0, nil, err
        }
        return execControlWithChallenge(req, 5)
}

func (GuardianClient) fetchProxyPass(accessToken string) (*ProxyPass, error) {
        body, status, headers, err := guardianRequest("GET", "/api/v1/fpn/token", accessToken)
        if err != nil {
                return nil, err
        }
        if status == 401 || status == 403 {
                return nil, errTokenInvalid
        }
        if status == 429 {
                return nil, errQuotaExceeded
        }
        if status != 200 {
                return nil, fmt.Errorf("failed to fetch proxy pass: HTTP %d: %.200s", status, string(body))
        }
        var out struct {
                Token     string `json:"token"`
                ExpiresAt int64  `json:"expires_at"`
        }
        if err := json.Unmarshal(body, &out); err != nil {
                return nil, fmt.Errorf("proxy pass response parse failed: %v", err)
        }
        if out.Token == "" {
                return nil, errors.New("proxy pass response did not contain a token")
        }
        pass := &ProxyPass{Token: out.Token}
        if out.ExpiresAt > 0 {
                pass.ExpiresAt = out.ExpiresAt
        } else if exp, ok := jwtExpiryEpochSeconds(out.Token); ok {
                pass.ExpiresAt = exp
        }
        if v, ok := headers.int64("X-Quota-Limit"); ok {
                pass.QuotaMax = &v
        }
        if v, ok := headers.int64("X-Quota-Remaining"); ok {
                pass.QuotaRemain = &v
        }
        if v, ok := headers.int64("X-Quota-Reset"); ok {
                pass.QuotaReset = &v
        }
        return pass, nil
}

func (GuardianClient) fetchUserInfo(accessToken string) (*Entitlement, error) {
        body, status, _, err := guardianRequest("GET", "/api/v1/fpn/status", accessToken)
        if err != nil {
                return nil, err
        }
        if status == 401 || status == 403 {
                return nil, errTokenInvalid
        }
        if status != 200 {
                return nil, fmt.Errorf("failed to fetch account info: HTTP %d: %.200s", status, string(body))
        }
        var ent Entitlement
        if err := json.Unmarshal(body, &ent); err != nil {
                return nil, err
        }
        if ent.LimitedBandwidth {
                if pass, perr := (GuardianClient{}).fetchProxyPass(accessToken); perr == nil {
                        ent.QuotaRemaining = pass.QuotaRemain
                }
        }
        return &ent, nil
}

func (GuardianClient) activate(accessToken string) (*Entitlement, error) {
        body, status, _, err := guardianRequest("POST", "/api/v1/fpn/activate", accessToken)
        if err != nil {
                return nil, err
        }
        if status != 200 {
                return nil, fmt.Errorf("failed to activate guardian entitlement: HTTP %d: %.200s", status, string(body))
        }
        var ent Entitlement
        if err := json.Unmarshal(body, &ent); err != nil {
                return nil, err
        }
        return &ent, nil
}

// httpHeaders is a minimal case-insensitive header view.
type httpHeaders map[string][]string

func (h httpHeaders) int64(name string) (int64, bool) {
        for k, vs := range h {
                if strings.EqualFold(k, name) && len(vs) > 0 {
                        var v int64
                        if _, err := fmt.Sscan(vs[0], &v); err == nil {
                                return v, true
                        }
                }
        }
        return 0, false
}
