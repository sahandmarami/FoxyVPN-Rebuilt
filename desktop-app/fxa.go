package main

// Firefox Accounts authentication (port of FxaAuthRepository.kt).

import (
        "encoding/json"
        "errors"
        "fmt"
        "regexp"
        "strings"
)

const (
        firefoxClientID = "5882386c6d801776"
        oauthScope      = "profile https://identity.mozilla.com/apps/vpn"
        verify2FA       = "email-2fa"
        fxaErrnoInvalid = 107
)

// fxaAuthServer is a var so the E2E tests can point it at a mock server.
var fxaAuthServer = "https://api.accounts.firefox.com/v1"

type FxaApiError struct {
        Message    string
        Errno      int
        StatusCode int
        HasErrno   bool
}

func (e *FxaApiError) Error() string { return e.Message }

type RuntimeAuth struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token,omitempty"`
        ExpiresAt    int64  `json:"expires_at"`
        Email        string `json:"email,omitempty"`
}

type FxaClient struct{}

func normalizeEmail(email string) string {
        re := regexp.MustCompile(`[\p{Z}\x{200B}-\x{200D}\x{FEFF}\x{00A0}\s]+`)
        return strings.ToLower(re.ReplaceAllString(email, ""))
}

func sanitizeCode(code string) string {
        re := regexp.MustCompile(`[\p{Z}\x{200B}-\x{200D}\x{FEFF}\x{00A0}\s]+`)
        return re.ReplaceAllString(code, "")
}

func fxaAPIError(status int, body []byte) *FxaApiError {
        var parsed struct {
                Errno   int    `json:"errno"`
                Message string `json:"message"`
        }
        hasErrno := json.Unmarshal(body, &parsed) == nil && parsed.Message != "" || status == 400 && parsed.Errno != 0
        if parsed.Message == "" {
                parsed.Message = fmt.Sprintf("HTTP %d: %.200s", status, string(body))
        }
        return &FxaApiError{Message: parsed.Message, Errno: parsed.Errno, StatusCode: status, HasErrno: hasErrno && parsed.Errno != 0}
}

// login posts /account/login. Returns (sessionToken, verified, verificationMethod, error).
func (FxaClient) login(email, password string) (string, bool, string, error) {
        clean := normalizeEmail(email)
        try := func(withVerification bool) (string, bool, string, error) {
                body := map[string]any{"email": clean, "authPW": deriveAuthPw(clean, password)}
                if withVerification {
                        body["verificationMethod"] = verify2FA
                }
                raw, _ := json.Marshal(body)
                respBody, status, err := doControlJSON("POST", fxaAuthServer+"/account/login", "", "", string(raw), 5)
                if err != nil {
                        return "", false, "", err
                }
                if status >= 400 {
                        e := fxaAPIError(status, respBody)
                        return "", false, "", e
                }
                var out struct {
                        SessionToken       string `json:"sessionToken"`
                        Verified           bool   `json:"verified"`
                        VerificationMethod string `json:"verificationMethod"`
                }
                if err := json.Unmarshal(respBody, &out); err != nil {
                        return "", false, "", fmt.Errorf("unexpected login response: %v", err)
                }
                if out.SessionToken == "" {
                        return "", false, "", errors.New("FxA returned no session token")
                }
                return out.SessionToken, out.Verified, out.VerificationMethod, nil
        }
        st, verified, method, err := try(true)
        if err != nil {
                var apiErr *FxaApiError
                if errors.As(err, &apiErr) && apiErr.Errno == fxaErrnoInvalid {
                        return try(false)
                }
        }
        return st, verified, method, err
}

// verifyCode posts /session/verify_code with the email-2fa code.
func (FxaClient) verifyCode(sessionToken, code string) error {
        raw, _ := json.Marshal(map[string]string{"code": sanitizeCode(code)})
        respBody, status, err := doControlJSON("POST", fxaAuthServer+"/session/verify_code", "", sessionToken, string(raw), 5)
        if err != nil {
                return err
        }
        if status >= 400 {
                return fxaAPIError(status, respBody)
        }
        return nil
}

// oauthToken exchanges a verified session for OAuth tokens (fxa-credentials grant).
func (FxaClient) oauthToken(sessionToken string) (*RuntimeAuth, error) {
        body := map[string]any{
                "client_id":   firefoxClientID,
                "grant_type":  "fxa-credentials",
                "scope":       oauthScope,
                "access_type": "offline",
        }
        raw, _ := json.Marshal(body)
        respBody, status, err := doControlJSON("POST", fxaAuthServer+"/oauth/token", "", sessionToken, string(raw), 5)
        if err != nil {
                return nil, err
        }
        if status >= 400 {
                return nil, fxaAPIError(status, respBody)
        }
        return parseAuth(respBody)
}

// refresh renews the access token via the refresh_token grant.
func (FxaClient) refresh(refreshToken string) (*RuntimeAuth, error) {
        body := map[string]any{
                "client_id":    firefoxClientID,
                "grant_type":   "refresh_token",
                "refresh_token": refreshToken,
                "scope":        oauthScope,
        }
        raw, _ := json.Marshal(body)
        respBody, status, err := doControlJSON("POST", fxaAuthServer+"/oauth/token", "", "", string(raw), 5)
        if err != nil {
                return nil, &refreshFailure{msg: "could not reach the Firefox Accounts server: " + err.Error(), permanent: false}
        }
        if status >= 400 {
                e := fxaAPIError(status, respBody)
                permanent := status == 400 || status == 401 || status == 403
                return nil, &refreshFailure{msg: e.Message, permanent: permanent}
        }
        auth, err := parseAuth(respBody)
        if err != nil {
                return nil, &refreshFailure{msg: err.Error(), permanent: false}
        }
        return auth, nil
}

type refreshFailure struct {
        msg       string
        permanent bool
}

func (e *refreshFailure) Error() string { return e.msg }

func parseAuth(body []byte) (*RuntimeAuth, error) {
        var out struct {
                AccessToken string `json:"access_token"`
                RefreshTok  string `json:"refresh_token"`
                ExpiresIn   int    `json:"expires_in"`
        }
        if err := json.Unmarshal(body, &out); err != nil {
                return nil, fmt.Errorf("unexpected token response: %v", err)
        }
        if out.AccessToken == "" {
                return nil, errors.New("FxA returned no access token")
        }
        expiresIn := out.ExpiresIn
        if expiresIn <= 0 {
                expiresIn = 24 * 3600
        }
        return &RuntimeAuth{
                AccessToken:  out.AccessToken,
                RefreshToken: out.RefreshTok,
                ExpiresAt:    nowUnix() + int64(expiresIn),
        }, nil
}
