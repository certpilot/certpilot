package acmeserver_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"golang.org/x/crypto/acme"
)

// acmeRows is every certificate the ACME endpoint has recorded.
func (f *fixture) acmeRows() []*store.Certificate {
	f.t.Helper()
	certs, _, err := f.st.ListCertificates(context.Background(), store.CertificateFilter{})
	if err != nil {
		f.t.Fatal(err)
	}
	var out []*store.Certificate
	for _, c := range certs {
		if c.DiscoveredVia == "ACME" {
			out = append(out, c)
		}
	}
	return out
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// A client renews by ordering the same names again. Recorded as a new
// certificate, the one it replaced stayed ISSUED: counted, on the horizon, and
// alerting as it neared expiry about something nothing served any more.
func TestOrderingTheSameNamesAgainRenewsTheRecord(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	first, _ := f.issued(c, "web.example.com", "api.example.com")
	second, _ := f.issued(c, "api.example.com", "web.example.com")

	rows := f.acmeRows()
	if len(rows) != 1 {
		t.Fatalf("%d records, want the renewal written over the first", len(rows))
	}
	got := rows[0]
	if got.FingerprintSHA256 != fingerprint(second) || got.RenewalCount != 1 || got.Status != "ISSUED" {
		t.Errorf("record is %s, renewal %d, %s; want the second certificate, renewal 1",
			got.FingerprintSHA256, got.RenewalCount, got.Status)
	}
	if got.PreviousFingerprint != fingerprint(first) {
		t.Errorf("previous fingerprint %q, want the first certificate's", got.PreviousFingerprint)
	}
	if got.KeyCustody != store.KeyCustodyExternal || got.AutoRenew {
		t.Errorf("a renewal changed custody to %s or auto-renew to %v", got.KeyCustody, got.AutoRenew)
	}
}

// Each of these is a second certificate, not a renewal of the first.
func TestADifferentCertificateIsNotARenewal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		second func(f *fixture, first *acme.Client)
	}{
		{"more names", func(f *fixture, c *acme.Client) { f.issued(c, "web.example.com", "api.example.com") }},
		{"another account", func(f *fixture, _ *acme.Client) {
			other := f.client()
			if _, err := register(other, "kid-other", f.credential("kid-other")); err != nil {
				f.t.Fatal(err)
			}
			f.issued(other, "web.example.com")
		}},
		// Two certificates for one name, one per key type, is how a server
		// offers both. Folding them together would leave one unrecorded.
		// Moved to another template since, so no longer this endpoint's to
		// write over.
		{"a record now under another template", func(f *fixture, c *acme.Client) {
			for _, row := range f.acmeRows() {
				other := "another-template"
				row.TemplateID = &other
				if err := f.st.UpdateCertificate(context.Background(), row); err != nil {
					f.t.Fatal(err)
				}
			}
			f.issued(c, "web.example.com")
		}},
		{"another key type", func(f *fixture, c *acme.Client) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				f.t.Fatal(err)
			}
			f.issuedFor(c, key, "web.example.com")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.registered()
			f.issued(c, "web.example.com")
			tc.second(f, c)
			if rows := f.acmeRows(); len(rows) != 2 {
				t.Fatalf("%d records, want two", len(rows))
			}
		})
	}
}

// A revoked record says what happened. Ordering the names again is a new
// certificate, not an overwrite of that.
func TestARevokedCertificateIsNotRenewedOver(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")
	if err := c.RevokeCert(context.Background(), nil, der, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	f.issued(c, "web.example.com")

	rows := f.acmeRows()
	if len(rows) != 2 {
		t.Fatalf("%d records, want the revoked one kept beside the new one", len(rows))
	}
	if f.recorded(der).Status != "REVOKED" {
		t.Error("the revoked record was overwritten")
	}
}

// Renew, then revoke the old one, is what a client does when a key leaks. The
// record now holds the successor, so the old certificate is sent to the CA as
// the client gave it, and the successor stays as it is.
func TestTheCertificateARenewalReplacedCanStillBeRevoked(t *testing.T) {
	for _, tc := range []struct {
		name        string
		withCertKey bool
	}{
		{"by the account", false},
		{"by the old certificate's key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := f.registered()
			old, oldKey := f.issued(c, "web.example.com")
			renewed, _ := f.issued(c, "web.example.com")

			revoker, key := c, crypto.Signer(nil)
			if tc.withCertKey {
				revoker, key = f.client(), oldKey
			}
			err := revoker.RevokeCert(context.Background(), key, old, acme.CRLReasonKeyCompromise)
			if err != nil {
				t.Fatalf("revoke the replaced certificate: %v", err)
			}
			sent, _ := f.gw.lastPEM.Load().(string)
			if block, _ := pem.Decode([]byte(sent)); block == nil || fingerprint(block.Bytes) != fingerprint(old) {
				t.Error("the CA was not sent the replaced certificate")
			}
			if got := f.recorded(renewed); got.Status != "ISSUED" {
				t.Errorf("the successor is %s; revoking what it replaced must not touch it", got.Status)
			}
		})
	}
}
