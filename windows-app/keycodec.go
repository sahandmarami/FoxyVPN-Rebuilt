package main

// FV1 quota-key codec — a faithful port of the Android app's QuotaKey.kt.
// Format: FV1.<b64url(payloadJson)>.<b64url(ed25519Signature)>
//
// The payload carries the person's display name, the volume plan (gb/mb,
// 0 = unlimited), an absolute expiry (unix seconds, 0 = never), a short key
// id, the Firefox refresh token that grants direct access to the
// distributor's account, and (optionally) the GitHub gist coordinates used
// for live usage reporting. The signature is produced by the distributor's
// FoxyKeygen app; this app only embeds the matching public keys, so a key
// that was not signed by the distributor is rejected.

import (
        "crypto/ed25519"
        "encoding/base64"
        "encoding/json"
        "errors"
        "fmt"
        "regexp"
        "strings"
        "time"
)

const (
        bytesPerGB int64 = 1_000_000_000
        bytesPerMB int64 = 1_000_000
)

// quotaKeyPubKeys — every signing public key this build accepts: the current
// FoxyKeygen release key first, then the earlier release keys — so keys
// already in our friends' hands keep working and nobody has to re-issue them.
var quotaKeyPubKeys = []string{
        "hA5+kmj6X7JrqYWraZQY+q09q72mNUJx2aLPNnX/Ntw=",
        "XxKVqJEz37vADD0ctmZSGPgvnS/o+1FCFf7CB1J3++E=", // v2.1.0 era
        "8b705IT0MNKJEXm+zwlKjlGiFazvWIkIoIYLR12cAvE=", // original era
}

type QuotaKeyPayload struct {
        V    int    `json:"v"`
        Name string `json:"name"`
        Gb   int64  `json:"gb"`
        Mb   int64  `json:"mb"`
        Exp  int64  `json:"exp"`
        Id   string `json:"id"`
        Rt   string `json:"rt"`
        Gist string `json:"gist"`
        Gt   string `json:"gt"`
}

func (p *QuotaKeyPayload) isUnlimited() bool { return p.Gb <= 0 && p.Mb <= 0 }
func (p *QuotaKeyPayload) planBytes() int64 {
        switch {
        case p.Gb > 0:
                return p.Gb * bytesPerGB
        case p.Mb > 0:
                return p.Mb * bytesPerMB
        }
        return 0
}

func (p *QuotaKeyPayload) personName() string {
        if strings.TrimSpace(p.Name) == "" {
                return "کاربر"
        }
        return p.Name
}

type InvalidKeyError struct{ msg string }

func (e *InvalidKeyError) Error() string { return e.msg }

func invalidKey(msg string) error { return &InvalidKeyError{msg: msg} }

var keyJunkRe = regexp.MustCompile(`[\p{Z}\x{200B}-\x{200D}\x{FEFF}\x{00A0}\s]+`)

func b64urlDecode(text string) ([]byte, error) {
        b64 := strings.TrimRight(strings.TrimSpace(text), "=")
        return base64.RawURLEncoding.DecodeString(b64)
}

func verifyKeySignature(payloadB64, signatureB64 string) bool {
        sig, err := b64urlDecode(signatureB64)
        if err != nil || len(sig) != ed25519.SignatureSize {
                return false
        }
        for _, pubB64 := range quotaKeyPubKeys {
                pubRaw, err := b64urlDecode(pubB64)
                if err != nil || len(pubRaw) != ed25519.PublicKeySize {
                        continue
                }
                if ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(payloadB64), sig) {
                        return true
                }
        }
        return false
}

// parseQuotaKey parses and verifies a user-pasted key. Errors carry the exact
// Persian messages of the Android app so both platforms speak alike.
func parseQuotaKey(input string) (*QuotaKeyPayload, string, error) {
        cleaned := keyJunkRe.ReplaceAllString(input, "")
        parts := strings.Split(cleaned, ".")
        if len(parts) != 3 || parts[0] != "FV1" {
                return nil, "", invalidKey("کلید واردشده معتبر نیست (قالب FV1 نیست)")
        }
        if !verifyKeySignature(parts[1], parts[2]) {
                return nil, "", invalidKey("امضای کلید تأیید نشد؛ کلید را از سازندهٔ کلید بگیرید")
        }
        payloadJSON, err := b64urlDecode(parts[1])
        if err != nil {
                return nil, "", invalidKey("محتوای کلید قابل خواندن نیست")
        }
        var p QuotaKeyPayload
        if err := json.Unmarshal(payloadJSON, &p); err != nil {
                return nil, "", invalidKey("محتوای کلید نامعتبر است")
        }
        if strings.TrimSpace(p.Rt) == "" {
                return nil, "", invalidKey("کلید فاقد اعتبارنامهٔ اتصال است")
        }
        if p.Exp > 0 && p.Exp <= time.Now().Unix() {
                return nil, "", invalidKey("این کلید منقضی شده است")
        }
        return &p, cleaned, nil
}

// friendlyActivationError maps a failed refresh-token activation to the same
// Persian messages the Android KeyEntryScreen shows.
func friendlyActivationError(err error) string {
        var rf *refreshFailure
        if errors.As(err, &rf) && rf.permanent {
                return "اعتبارنامهٔ این کلید توسط فایرفاکس پذیرفته نشد؛ از فروشندهٔ خود کلید سالم بگیرید"
        }
        var apiErr *FxaApiError
        if errors.As(err, &apiErr) && (apiErr.Errno == 101 || apiErr.Errno == 102) {
                return "اعتبارنامهٔ این کلید باطل شده است؛ از فروشندهٔ خود کلید جدید بگیرید"
        }
        var rf2 *refreshFailure
        if errors.As(err, &rf2) {
                return "اتصال به سرور نشد؛ اینترنت را بررسی و دوباره تلاش کنید"
        }
        return fmt.Sprintf("فعال‌سازی ناموفق بود: %v", err)
}
