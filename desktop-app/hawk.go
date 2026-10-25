package main

// Hawk request signing for Firefox Accounts (port of FxaAuthRepository).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func hawkHeader(method, rawURL, tokenID string, hmacKey []byte, body []byte) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonceBytes := make([]byte, 6)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	payloadHash := ""
	if len(body) > 0 {
		d := sha256.New()
		d.Write([]byte("hawk.1.payload\napplication/json\n"))
		d.Write(body)
		d.Write([]byte("\n"))
		payloadHash = base64.StdEncoding.EncodeToString(d.Sum(nil))
	}

	host := u.Hostname()
	port := u.Port()
	normalized := "hawk.1.header\n" + ts + "\n" + nonce + "\n" +
		strings.ToUpper(method) + "\n" + path + "\n" + host + "\n" + port + "\n" +
		payloadHash + "\n\n"

	mac := base64.StdEncoding.EncodeToString(hmacSha256(hmacKey, []byte(normalized)))
	header := fmt.Sprintf(`Hawk id="%s", ts="%s", nonce="%s", mac="%s"`, tokenID, ts, nonce, mac)
	if payloadHash != "" {
		header += fmt.Sprintf(`, hash="%s"`, payloadHash)
	}
	return header, nil
}
