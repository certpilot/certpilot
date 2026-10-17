package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"golang.org/x/crypto/acme"
)

// registered is a client with an account, ready to order.
func (f *fixture) registered() *acme.Client {
	f.t.Helper()
	c := f.client()
	kid := "kid-" + strings.ReplaceAll(f.t.Name(), "/", "-")
	if _, err := register(c, kid, f.credential(kid)); err != nil {
		f.t.Fatalf("register: %v", err)
	}
	return c
}

func csrFor(t *testing.T, names ...string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAClientCanOrderAndReceiveACertificate(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()

	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com", "api.example.com"))
	if err != nil {
		t.Fatalf("new order: %v", err)
	}
	if order.Status != acme.StatusReady {
		t.Fatalf("order status %q, want ready: the credential pre-authorises the names", order.Status)
	}
	if len(order.AuthzURLs) != 2 {
		t.Fatalf("%d authorisations, want one per name", len(order.AuthzURLs))
	}
	for _, u := range order.AuthzURLs {
		authz, err := c.GetAuthorization(ctx, u)
		if err != nil || authz.Status != acme.StatusValid {
			t.Fatalf("authorisation %s: %+v, %v", u, authz, err)
		}
	}

	chain, certURL, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com", "api.example.com"), true)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("%d certificates in the chain, want the leaf and the CA", len(chain))
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil || len(leaf.DNSNames) != 2 {
		t.Fatalf("leaf: %v, %v", leaf, err)
	}
	if !strings.Contains(certURL, "/acme/web/") {
		t.Errorf("certificate URL %q is not under the template", certURL)
	}

	// Recorded the way every certificate whose key lives elsewhere is.
	certs, _, err := f.st.ListCertificates(ctx, store.CertificateFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var found *store.Certificate
	for _, cert := range certs {
		if cert.DiscoveredVia == "ACME" {
			found = cert
		}
	}
	if found == nil {
		t.Fatal("the certificate was not recorded with provenance ACME")
	}
	if found.KeyCustody != store.KeyCustodyExternal || found.AutoRenew ||
		found.TemplateID == nil || *found.TemplateID != f.template.ID {
		t.Errorf("recorded wrongly: custody %s, auto_renew %v, template %v",
			found.KeyCustody, found.AutoRenew, found.TemplateID)
	}
}

func TestACSRMustAskForExactlyWhatWasOrdered(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com", "extra.example.com"), true)
	if problemType(err) != "urn:ietf:params:acme:error:badCSR" {
		t.Fatalf("got %v, want badCSR", err)
	}
	if f.gw.issued.Load() != 0 {
		t.Error("the CA was asked to sign a CSR that did not match its order")
	}
}

func TestANameTheTemplateDoesNotAllowIsRefused(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()
	order, err := c.AuthorizeOrder(ctx, acme.DomainIDs("payroll.other.test"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "payroll.other.test"), true)
	if problemType(err) != "urn:ietf:params:acme:error:rejectedIdentifier" {
		t.Fatalf("got %v, want rejectedIdentifier", err)
	}
	if !strings.Contains(err.Error(), "outside the suffixes") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if f.gw.issued.Load() != 0 {
		t.Error("a name the template forbids reached the CA")
	}
	got, _ := c.GetOrder(ctx, order.URI)
	if got.Status != acme.StatusInvalid {
		t.Errorf("order status %q after a refusal, want invalid", got.Status)
	}
}

func TestAnOrderIsFinalisedOnce(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()
	order, _ := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com"))
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com"), true); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com"), true)
	if problemType(err) != "urn:ietf:params:acme:error:orderNotReady" {
		t.Fatalf("second finalize: %v, want orderNotReady", err)
	}
	if n := f.gw.issued.Load(); n != 1 {
		t.Errorf("the CA issued %d certificates for one order", n)
	}
}

func TestWhenTheCARefusesTheOrderBecomesInvalidAndSaysWhy(t *testing.T) {
	f := newFixture(t)
	f.gw.refuse.Store(true)
	c := f.registered()
	ctx := context.Background()
	order, _ := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com"))
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com"), true); err == nil {
		t.Fatal("finalize succeeded with a CA that refuses")
	}
	got, err := c.GetOrder(ctx, order.URI)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != acme.StatusInvalid || got.Error == nil ||
		!strings.Contains(got.Error.Detail, "the CA refused this request") {
		t.Errorf("order %q with error %+v; want invalid, saying the CA refused", got.Status, got.Error)
	}
	if n := f.gw.issued.Load(); n != 0 {
		t.Errorf("%d certificates issued", n)
	}
}

func TestOnlyDNSNamesCanBeOrdered(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	_, err := c.AuthorizeOrder(context.Background(), acme.IPIDs("192.0.2.1"))
	if problemType(err) != "urn:ietf:params:acme:error:unsupportedIdentifier" {
		t.Fatalf("got %v, want unsupportedIdentifier", err)
	}
}

func TestTheTemplateNotTheClientDecidesTheLifetime(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	_, err := c.AuthorizeOrder(context.Background(), acme.DomainIDs("web.example.com"),
		acme.WithOrderNotAfter(timeIn(400)))
	if problemType(err) != "urn:ietf:params:acme:error:malformed" {
		t.Fatalf("got %v, want malformed", err)
	}
}

func TestAnAccountCannotReadAnotherAccountsOrder(t *testing.T) {
	f := newFixture(t)
	a := f.registered()
	order, err := a.AuthorizeOrder(context.Background(), acme.DomainIDs("web.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	b := f.client()
	if _, err := register(b, "kid-other", f.credential("kid-other")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetOrder(context.Background(), order.URI); problemType(err) != "urn:ietf:params:acme:error:unauthorized" {
		t.Fatalf("b read a's order: %v", err)
	}
}

func TestTheCertificateIsServedAsAPEMChain(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	ctx := context.Background()
	order, _ := c.AuthorizeOrder(ctx, acme.DomainIDs("web.example.com"))
	_, certURL, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "web.example.com"), false)
	if err != nil {
		t.Fatal(err)
	}
	key := c.Key.(*ecdsa.PrivateKey)
	acct, _ := c.GetReg(ctx, "")
	body := signedPost(t, key, map[string]any{"alg": "ES256", "nonce": f.nonce(), "kid": acct.URI, "url": certURL}, nil)
	resp, err := http.Post(certURL, "application/jose+json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("Content-Type %q, want application/pem-certificate-chain", ct)
	}
}

func timeIn(days int) time.Time { return time.Now().Add(time.Duration(days) * 24 * time.Hour) }
