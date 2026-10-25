package main

// Quota key format — identical to the Android FoxyVPN / FoxyKeygen pair:
//
//      FV1.<b64url(payloadJson)>.<b64url(ed25519Signature)>
//
// The payload carries the owner's display name, the volume plan (gb, mb,
// 0 = unlimited), an absolute expiry (unix seconds, 0 = never), a short key
// id, the Firefox refresh token that grants access to the distributor's
// account, and the GitHub gist coordinates used for live usage reporting.
// The signature is produced by the distributor's FoxyKeygen app; this client
// only embeds the matching public keys, so a key that was not signed by the
// distributor is rejected.

import (
        "crypto/ed25519"
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "math/big"
        "regexp"
        "strings"
        "time"
)

type QuotaKeyPayload struct {
        V    int    `json:"v"`
        Name string `json:"name"`
        Gb   int64  `json:"gb"`
        Mb   int64  `json:"mb"`
        Exp  int64  `json:"exp"`
        ID   string `json:"id"`
        Rt   string `json:"rt"`
        Gist string `json:"gist"`
        Gt   string `json:"gt"`
}

const (
        bytesPerGB = 1_000_000_000
        bytesPerMB = 1_000_000
)

func (p *QuotaKeyPayload) IsUnlimited() bool { return p.Gb <= 0 && p.Mb <= 0 }
func (p *QuotaKeyPayload) LimitBytes() int64 {
        switch {
        case p.Gb > 0:
                return p.Gb * bytesPerGB
        case p.Mb > 0:
                return p.Mb * bytesPerMB
        default:
                return 0
        }
}

type QuotaKey struct {
        Payload QuotaKeyPayload
        Raw     string
}

func (k *QuotaKey) KeyID() string    { return k.Payload.ID }
func (k *QuotaKey) PersonName() string {
        if strings.TrimSpace(k.Payload.Name) == "" {
                return "کاربر"
        }
        return k.Payload.Name
}

// ReportContext mirrors the Android GistReporter.ReportContext.
type ReportContext struct {
        GistID string
        Token  string
        KeyID  string
}

func (k *QuotaKey) ReportContext() (ReportContext, bool) {
        if k.Payload.Gist == "" || k.Payload.Gt == "" {
                return ReportContext{}, false
        }
        return ReportContext{GistID: k.Payload.Gist, Token: k.Payload.Gt, KeyID: k.Payload.ID}, true
}

// pubKeys is the same list the Android client embeds: the current FoxyKeygen
// release key first, then the older ones, so keys already in circulation
// keep working.
var pubKeys = []string{
        "hA5+kmj6X7JrqYWraZQY+q09q72mNUJx2aLPNnX/Ntw=",
        "XxKVqJEz37vADD0ctmZSGPgvnS/o+1FCFf7CB1J3++E=", // v2.1.0 era
        "8b705IT0MNKJEXm+zwlKjlGiFazvWIkIoIYLR12cAvE=", // original era
}

var b64urlNoPad = base64.RawURLEncoding

type InvalidKeyError struct{ msg string }

func (e *InvalidKeyError) Error() string { return e.msg }

func b64urlDecode(text string) ([]byte, error) {
        return b64urlNoPad.DecodeString(strings.TrimRight(text, "="))
}

func b64urlEncode(data []byte) string { return b64urlNoPad.EncodeToString(data) }

var wsRe = regexp.MustCompile(`[\p{Z}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}\x{00A0}\s]+`)

func cleanKeyInput(input string) string { return strings.TrimSpace(wsRe.ReplaceAllString(input, "")) }

// ParseKey parses and verifies a user-pasted key.
func ParseKey(input string) (*QuotaKey, error) {
        cleaned := cleanKeyInput(input)
        if cleaned == "" {
                return nil, &InvalidKeyError{"کلید را وارد کنید"}
        }
        parts := strings.Split(cleaned, ".")
        if len(parts) != 3 || parts[0] != "FV1" {
                return nil, &InvalidKeyError{"کلید واردشده معتبر نیست (قالب FV1 نیست)"}
        }
        if !verifyKeySignature(parts[1], parts[2]) {
                return nil, &InvalidKeyError{"امضای کلید تأیید نشد؛ کلید را از سازندهٔ کلید بگیرید"}
        }
        payloadJSON, err := b64urlDecode(parts[1])
        if err != nil {
                return nil, &InvalidKeyError{"محتوای کلید قابل خواندن نیست"}
        }
        var payload QuotaKeyPayload
        if err := json.Unmarshal(payloadJSON, &payload); err != nil {
                return nil, &InvalidKeyError{"محتوای کلید نامعتبر است"}
        }
        if strings.TrimSpace(payload.Rt) == "" {
                return nil, &InvalidKeyError{"کلید فاقد اعتبارنامهٔ اتصال است"}
        }
        if payload.Exp > 0 && payload.Exp <= time.Now().Unix() {
                return nil, &InvalidKeyError{"این کلید منقضی شده است"}
        }
        return &QuotaKey{Payload: payload, Raw: cleaned}, nil
}

func verifyKeySignature(payloadB64, signatureB64 string) bool {
        sig, err := b64urlDecode(signatureB64)
        if err != nil || len(sig) != ed25519.SignatureSize {
                return false
        }
        for _, pubB64 := range pubKeys {
                pubRaw, err := base64.StdEncoding.DecodeString(pubB64)
                if err != nil || len(pubRaw) != ed25519.PublicKeySize {
                        continue
                }
                if ed25519.Verify(ed25519.PublicKey(pubRaw), []byte(payloadB64), sig) {
                        return true
                }
        }
        return false
}

// NationalCode returns the stable 10-digit «کد ملی» shortcut of a key. It is
// derived from the key id, so the same key always produces the same code on
// every device and can be used to re-activate the key without pasting the
// long FV1 string again.
func NationalCode(keyID string) string {
        sum := sha256.Sum256([]byte("foxy-desktop-code:" + keyID))
        n := new(big.Int).SetBytes(sum[:8])
        code := fmt.Sprintf("%010d", n.Mod(n, big.NewInt(4_000_000_000)).Int64())
        // keep it look-alive: never start with 0
        if code[0] == '0' {
                code = "1" + code[1:]
        }
        return code
}

var digitsOnlyRe = regexp.MustCompile(`^\d{10,12}$`)

// looksLikeNationalCode reports whether the user typed a bare numeric code
// instead of a full FV1 key.
func looksLikeNationalCode(input string) bool { return digitsOnlyRe.MatchString(cleanKeyInput(input)) }
