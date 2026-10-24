package main

// Unit tests for the FV1 quota-key codec: format/signature error paths and
// the b64url helpers. Signature-positive paths are covered by the real
// keygen (its keys must verify against the embedded public keys).

import (
	"strings"
	"testing"
)

func TestParseQuotaKeyErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "قالب FV1"},
		{"garbage", "hello world", "قالب FV1"},
		{"wrong prefix", "FX1.abc.def", "قالب FV1"},
		{"two parts", "FV1.abc", "قالب FV1"},
		{"bad signature", "FV1.eyJ2IjoxfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "امضای کلید"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseQuotaKey(tc.in)
			if err == nil {
				t.Fatalf("expected an error for %q", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseQuotaKeyWhitespaceIsStripped(t *testing.T) {
	// junk whitespace inside a formatted-but-unsigned key must not change the error class
	_, _, err := parseQuotaKey("  FV1.\nabc .def\u00A0 ")
	if err == nil || !strings.Contains(err.Error(), "امضای کلید") {
		t.Fatalf("want signature error after cleanup, got %v", err)
	}
}

func TestB64urlDecode(t *testing.T) {
	// "hi" -> aGk  (raw, unpadded)
	b, err := b64urlDecode("aGk")
	if err != nil || string(b) != "hi" {
		t.Fatalf("decode failed: %v %q", err, b)
	}
	// padded input must also work
	b, err = b64urlDecode("aGk=")
	if err != nil || string(b) != "hi" {
		t.Fatalf("padded decode failed: %v %q", err, b)
	}
}

func TestFriendlyActivationError(t *testing.T) {
	rf := &refreshFailure{msg: "rejected", permanent: true}
	if got := friendlyActivationError(rf); !strings.Contains(got, "پذیرفته نشد") {
		t.Fatalf("permanent refresh failure mapped wrong: %s", got)
	}
	apiErr := &FxaApiError{Message: "revoked", Errno: 101}
	if got := friendlyActivationError(apiErr); !strings.Contains(got, "باطل شده") {
		t.Fatalf("errno 101 mapped wrong: %s", got)
	}
	other := &refreshFailure{msg: "network down", permanent: false}
	if got := friendlyActivationError(other); !strings.Contains(got, "اتصال به سرور نشد") {
		t.Fatalf("transient failure mapped wrong: %s", got)
	}
}
