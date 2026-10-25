package main

// Minimal PBKDF2-HMAC-SHA256 / HKDF-SHA256 implementations (mirrors the
// Kotlin FoxyVPN helpers exactly, including the zero salt default).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func hmacSha256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func pbkdf2Sha256(password, salt []byte, iterations, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))
		u := hmacSha256(password, append(append([]byte{}, salt...), buf...))
		t := make([]byte, len(u))
		copy(t, u)
		for i := 2; i <= iterations; i++ {
			u = hmacSha256(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func hkdfSha256(ikm []byte, info string, length int, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSha256(salt, ikm)
	infoBytes := []byte(info)
	var result []byte
	var previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		previous = hmacSha256(prk, append(append(append([]byte{}, previous...), infoBytes...), counter))
		result = append(result, previous...)
	}
	return result[:length]
}

func deriveAuthPw(email, password string) string {
	const proto = "identity.mozilla.com/picl/v1/"
	quickStretch := pbkdf2Sha256([]byte(password), []byte(proto+"quickStretch:"+email), 1000, 32)
	return hex.EncodeToString(hkdfSha256(quickStretch, proto+"authPW", 32, nil))
}

func deriveHawkCredentials(sessionTokenHex string) (id string, key []byte, err error) {
	raw, err := hex.DecodeString(sessionTokenHex)
	if err != nil {
		return "", nil, err
	}
	expanded := hkdfSha256(raw, "identity.mozilla.com/picl/v1/sessionToken", 64, nil)
	return hex.EncodeToString(expanded[:32]), expanded[32:], nil
}

func jwtExpiryEpochSeconds(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return 0, false
	}
	var m struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &m); err != nil || m.Exp <= 0 {
		return 0, false
	}
	return m.Exp, true
}
