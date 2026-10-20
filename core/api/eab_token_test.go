package api

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// A base64url value can begin with "-", and on a command line one that does is
// read as the next flag: certbot answered "argument --eab-hmac-key: expected
// one argument" for about one credential in 64, the way the console tells
// people to run it. The live ACME check hit it in CI.
func TestAnEABValueNeverStartsWithADash(t *testing.T) {
	// 0xF8 is 111110…, which base64url encodes as "-" first.
	dashFirst := bytes.Repeat([]byte{0xF8}, 32)
	plain := bytes.Repeat([]byte{0x41}, 32)
	src := bytes.NewReader(append(append([]byte{}, dashFirst...), plain...))

	if got := base64.RawURLEncoding.EncodeToString(dashFirst); !strings.HasPrefix(got, "-") {
		t.Fatalf("test input does not encode with a leading dash: %q", got)
	}

	raw, encoded, err := eabToken(src, 32)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(encoded, "-") {
		t.Fatalf("eabToken returned %q", encoded)
	}
	if !bytes.Equal(raw, plain) || encoded != base64.RawURLEncoding.EncodeToString(plain) {
		t.Fatalf("eabToken returned the wrong draw: %x / %q", raw, encoded)
	}
}
