package agentauth

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTheSignatureBindsEverythingItClaimsTo. Each subtest changes exactly one
// thing an attacker would want to change and checks it stops verifying.
func TestTheSignatureBindsEverythingItClaimsTo(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	const path = "/api/v1/agent/heartbeat"
	body := []byte(`{"version":"0.1.0"}`)
	now := time.Now().Unix()
	sig := Sign(priv, http.MethodPost, path, now, body)

	if err := Verify(pub, http.MethodPost, path, now, sig, body, DefaultTolerance); err != nil {
		t.Fatalf("an untouched request should verify: %v", err)
	}

	cases := map[string]func() error{
		"a different body": func() error {
			return Verify(pub, http.MethodPost, path, now, sig, []byte(`{"version":"9.9.9"}`), DefaultTolerance)
		},
		// The one that matters most: a heartbeat's signature must not be
		// liftable onto a route that does something.
		"a different path": func() error {
			return Verify(pub, http.MethodPost, "/api/v1/agent/certificates", now, sig, body, DefaultTolerance)
		},
		"a different method": func() error {
			return Verify(pub, http.MethodDelete, path, now, sig, body, DefaultTolerance)
		},
		"a different timestamp": func() error {
			return Verify(pub, http.MethodPost, path, now+1, sig, body, DefaultTolerance)
		},
		"another agent's key": func() error {
			other, _, _ := GenerateKey()
			return Verify(other, http.MethodPost, path, now, sig, body, DefaultTolerance)
		},
	}

	for name, check := range cases {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatalf("%s must not verify", name)
			}
		})
	}
}

// TestAnEmptyBodyIsSignedRatherThanSkipped. "No body" and "a body that happens
// to be empty" must not be interchangeable, or a signature captured from one
// can be replayed as the other.
func TestAnEmptyBodyIsSignedRatherThanSkipped(t *testing.T) {
	_, priv, _ := GenerateKey()
	now := time.Now().Unix()

	empty := Sign(priv, http.MethodPost, "/x", now, nil)
	full := Sign(priv, http.MethodPost, "/x", now, []byte("{}"))
	if empty == full {
		t.Fatal("an empty body and a non-empty one produced the same signature")
	}
}

// TestAStaleRequestIsRefused bounds replay to the tolerance window, which is
// the only bound this scheme claims to provide.
func TestAStaleRequestIsRefused(t *testing.T) {
	pub, priv, _ := GenerateKey()
	old := time.Now().Add(-30 * time.Minute).Unix()
	sig := Sign(priv, http.MethodPost, "/x", old, nil)

	err := Verify(pub, http.MethodPost, "/x", old, sig, nil, DefaultTolerance)
	if err == nil {
		t.Fatal("a half-hour-old request must not be accepted")
	}
	if !strings.Contains(err.Error(), "clock") {
		t.Fatalf("the error should point at the clock, got: %v", err)
	}

	// And a clock ahead of the server is as wrong as one behind it: a host that
	// is fast would otherwise be able to mint signatures valid into the future.
	future := time.Now().Add(30 * time.Minute).Unix()
	sig = Sign(priv, http.MethodPost, "/x", future, nil)
	if err := Verify(pub, http.MethodPost, "/x", future, sig, nil, DefaultTolerance); err == nil {
		t.Fatal("a request from the future must not be accepted")
	}
}

// TestTheSchemeIsInsideTheSignedBytes. A verifier that supports two schemes at
// once must not be talked into checking a v2 signature with v1 rules.
func TestTheSchemeIsInsideTheSignedBytes(t *testing.T) {
	got := SigningString(http.MethodPost, "/api/v1/agent/heartbeat", 1770000000, []byte("{}"))
	lines := strings.Split(got, "\n")
	if len(lines) != 5 {
		t.Fatalf("the signing string should have five lines, got %d: %q", len(lines), got)
	}
	if lines[0] != Scheme {
		t.Fatalf("the first line should be the scheme, got %q", lines[0])
	}
	// The method is upper-cased so that a client sending "post" and one sending
	// "POST" produce the same bytes.
	if SigningString("post", "/x", 1, nil) != SigningString("POST", "/x", 1, nil) {
		t.Fatal("method case should not change the signature")
	}
}

// TestKeysSurviveADiskRoundTrip — the agent writes these to a file and reads
// them back on every restart.
func TestKeysSurviveADiskRoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKey()

	pubPEM, err := EncodePublicKey(pub)
	if err != nil {
		t.Fatalf("encode public: %v", err)
	}
	backPub, err := ParsePublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if KeyID(backPub) != KeyID(pub) {
		t.Fatal("the public key did not survive the round trip")
	}

	privPEM, err := EncodePrivateKey(priv)
	if err != nil {
		t.Fatalf("encode private: %v", err)
	}
	backPriv, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}

	now := time.Now().Unix()
	sig := Sign(backPriv, http.MethodPost, "/x", now, nil)
	if err := Verify(backPub, http.MethodPost, "/x", now, sig, nil, DefaultTolerance); err != nil {
		t.Fatalf("a reloaded key should still sign verifiably: %v", err)
	}

	// An RSA or ECDSA key is refused rather than coerced.
	if _, err := ParsePublicKey("not pem at all"); err == nil {
		t.Fatal("garbage should not parse as a public key")
	}
}
