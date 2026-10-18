package acmeserver_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"golang.org/x/crypto/acme"
)

// issued has c order and finalise a certificate, and returns its DER and the
// key it was issued for.
func (f *fixture) issued(c *acme.Client, names ...string) ([]byte, crypto.Signer) {
	f.t.Helper()
	ctx := context.Background()
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		f.t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	chain, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		f.t.Fatalf("finalize: %v", err)
	}
	return chain[0], key
}

// recorded is the inventory row for a certificate the client holds.
func (f *fixture) recorded(der []byte) *store.Certificate {
	f.t.Helper()
	sum := sha256.Sum256(der)
	cert, err := f.st.GetCertificateByFingerprint(context.Background(), hex.EncodeToString(sum[:]))
	if err != nil || cert == nil {
		f.t.Fatalf("the certificate is not in the inventory: %v", err)
	}
	return cert
}

func TestTheDirectoryAdvertisesRevocation(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.directoryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir struct {
		RevokeCert string `json:"revokeCert"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&dir)
	if dir.RevokeCert != f.srv.URL+"/acme/web/revoke-cert" {
		t.Errorf("revokeCert %q", dir.RevokeCert)
	}
}

func TestTheAccountThatOrderedACertificateCanRevokeIt(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")

	if err := c.RevokeCert(context.Background(), nil, der, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.gw.revoked.Load() != 1 || f.gw.lastReason.Load() != 1 {
		t.Errorf("the CA was asked %d times with reason %d, want once with keyCompromise",
			f.gw.revoked.Load(), f.gw.lastReason.Load())
	}
	got := f.recorded(der)
	if got.Status != "REVOKED" || got.RevocationReason == nil || *got.RevocationReason != 1 {
		t.Errorf("recorded as %s with reason %v", got.Status, got.RevocationReason)
	}
	if got.RevokedBy == "" {
		t.Error("revoked_by is empty; an incident review needs to know it was the ACME client")
	}
}

// Whoever holds the certificate's private key can revoke it, with no account
// at all. That is how a compromised key gets reported by someone who finds it.
func TestTheCertificatesOwnKeyCanRevokeIt(t *testing.T) {
	f := newFixture(t)
	der, certKey := f.issued(f.registered(), "web.example.com")

	stranger := f.client()
	if err := stranger.RevokeCert(context.Background(), certKey, der, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revoke with the certificate's key: %v", err)
	}
	if f.recorded(der).Status != "REVOKED" {
		t.Error("not recorded as revoked")
	}
}

func TestAnotherAccountCannotRevokeACertificateItDidNotOrder(t *testing.T) {
	f := newFixture(t)
	der, _ := f.issued(f.registered(), "web.example.com")

	other := f.client()
	if _, err := register(other, "kid-other", f.credential("kid-other")); err != nil {
		t.Fatal(err)
	}
	err := other.RevokeCert(context.Background(), nil, der, acme.CRLReasonUnspecified)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
	if f.gw.revoked.Load() != 0 || f.recorded(der).Status == "REVOKED" {
		t.Error("another account's request reached the CA")
	}
}

func TestAKeyThatIsNotTheCertificatesCannotRevokeIt(t *testing.T) {
	f := newFixture(t)
	der, _ := f.issued(f.registered(), "web.example.com")

	someKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := f.client().RevokeCert(context.Background(), someKey, der, acme.CRLReasonKeyCompromise)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
	if f.gw.revoked.Load() != 0 {
		t.Error("the CA was asked")
	}
}

func TestRevokingTwiceDoesNotAskTheCATwice(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")
	ctx := context.Background()
	if err := c.RevokeCert(ctx, nil, der, acme.CRLReasonUnspecified); err != nil {
		t.Fatal(err)
	}
	// The Go client reads alreadyRevoked as success, so anything else would
	// come back as an error here.
	if err := c.RevokeCert(ctx, nil, der, acme.CRLReasonUnspecified); err != nil {
		t.Fatalf("second revoke: %v, want alreadyRevoked", err)
	}
	if f.gw.revoked.Load() != 1 {
		t.Errorf("the CA was asked %d times", f.gw.revoked.Load())
	}
}

func TestAReasonRFC5280DoesNotHaveIsRefused(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")
	err := c.RevokeCert(context.Background(), nil, der, acme.CRLReasonCode(7))
	if problemType(err) != "urn:ietf:params:acme:error:badRevocationReason" {
		t.Fatalf("got %v, want badRevocationReason", err)
	}
	if f.gw.revoked.Load() != 0 {
		t.Error("the CA was asked")
	}
}

// A certificate this endpoint did not issue gets the same answer whether it
// exists elsewhere in the inventory or not.
func TestACertificateFromElsewhereIsNotRevokedHere(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")
	cert := f.recorded(der)
	other := "another-template"
	cert.TemplateID = &other
	if err := f.st.UpdateCertificate(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	err := c.RevokeCert(context.Background(), nil, der, acme.CRLReasonUnspecified)
	if problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("got %v, want unauthorized", err)
	}
	if f.gw.revoked.Load() != 0 {
		t.Error("the CA was asked")
	}
}
