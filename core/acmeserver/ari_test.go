package acmeserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// certID is the RFC 9773 identifier of a certificate: its issuer's key
// identifier and its serial, the DER INTEGER's content octets, each base64url.
func certID(t *testing.T, der []byte) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.AuthorityKeyId) == 0 {
		t.Fatal("the test CA issued a certificate with no authority key identifier")
	}
	serial := leaf.SerialNumber.Bytes()
	if len(serial) == 0 || serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial)
}

type window struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
}

func (f *fixture) renewalInfo(id string) (*http.Response, window) {
	f.t.Helper()
	resp, err := http.Get(f.srv.URL + "/acme/web/renewal-info/" + id)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var w window
	_ = json.NewDecoder(resp.Body).Decode(&w)
	return resp, w
}

// account is a registered client with what a hand-built request needs.
type account struct {
	client *acme.Client
	key    *ecdsa.PrivateKey
	url    string
}

func (f *fixture) account(kid string) account {
	f.t.Helper()
	c := f.client()
	acct, err := register(c, kid, f.credential(kid))
	if err != nil {
		f.t.Fatal(err)
	}
	return account{client: c, key: c.Key.(*ecdsa.PrivateKey), url: acct.URI}
}

// newOrder sends a new-order naming what it replaces, which the Go client
// cannot do.
func (f *fixture) newOrder(a account, replaces string, names ...string) (int, map[string]any) {
	f.t.Helper()
	ids := []map[string]string{}
	for _, n := range names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	payload, _ := json.Marshal(map[string]any{"identifiers": ids, "replaces": replaces})
	url := f.srv.URL + "/acme/web/new-order"
	resp, got := post(f.t, url, signedPost(f.t, a.key, map[string]any{
		"alg": "ES256", "nonce": f.nonce(), "kid": a.url, "url": url,
	}, payload))
	return resp.StatusCode, got
}

func TestTheDirectoryAdvertisesRenewalInfo(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.directoryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&dir)
	if dir.RenewalInfo != f.srv.URL+"/acme/web/renewal-info" {
		t.Errorf("renewalInfo %q", dir.RenewalInfo)
	}
}

// The window is when the core itself would renew a certificate under this
// template, so a client asking gets the same answer the core would act on.
func TestRenewalInfoSuggestsAWindowBeforeExpiry(t *testing.T) {
	f := newFixture(t)
	der, _ := f.issued(f.registered(), "web.example.com")
	leaf, _ := x509.ParseCertificate(der)

	resp, w := f.renewalInfo(certID(t, der))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("no Retry-After: RFC 9773 clients use it to know when to ask again")
	}
	start, end := w.SuggestedWindow.Start, w.SuggestedWindow.End
	if !start.After(leaf.NotBefore) || !end.After(start) || !end.Before(leaf.NotAfter) {
		t.Errorf("window %s to %s for a certificate valid %s to %s", start, end, leaf.NotBefore, leaf.NotAfter)
	}
}

// A revoked certificate should be replaced now, and saying so through
// renewalInfo is how the core tells every client that asks.
func TestARevokedCertificateShouldBeRenewedNow(t *testing.T) {
	f := newFixture(t)
	c := f.registered()
	der, _ := f.issued(c, "web.example.com")
	if err := c.RevokeCert(context.Background(), nil, der, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	resp, w := f.renewalInfo(certID(t, der))
	if resp.StatusCode != http.StatusOK || w.SuggestedWindow.End.IsZero() {
		t.Fatalf("status %d, window %+v", resp.StatusCode, w)
	}
	if !w.SuggestedWindow.End.Before(time.Now()) {
		t.Errorf("window ends %s; a revoked certificate's window is in the past", w.SuggestedWindow.End)
	}
}

func TestRenewalInfoForSomethingElseIsRefused(t *testing.T) {
	f := newFixture(t)
	if resp, _ := f.renewalInfo("not-a-cert-id"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a malformed identifier: %d, want 400", resp.StatusCode)
	}
	// 0x80 first: a negative INTEGER, which no serial is.
	if resp, _ := f.renewalInfo("AAEC.gAE"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a negative serial: %d, want 400", resp.StatusCode)
	}
	if resp, _ := f.renewalInfo("AAEC.AQI"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a certificate never issued here: %d, want 404", resp.StatusCode)
	}

	// Issued here, then moved to another template: no longer this endpoint's.
	der, _ := f.issued(f.registered(), "web.example.com")
	for _, row := range f.acmeRows() {
		other := "another-template"
		row.TemplateID = &other
		if err := f.st.UpdateCertificate(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	}
	if resp, _ := f.renewalInfo(certID(t, der)); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another template's certificate: %d, want 404", resp.StatusCode)
	}
}

// With replaces, a client can change its names on renewal and still renew the
// record it holds, which ordering the same names again cannot express.
func TestAnOrderThatNamesWhatItReplacesRenewsThatRecord(t *testing.T) {
	f := newFixture(t)
	a := f.account("kid-a")
	der, _ := f.issued(a.client, "web.example.com")
	id := certID(t, der)

	status, order := f.newOrder(a, id, "web.example.com", "api.example.com")
	if status != http.StatusCreated || order["replaces"] != id {
		t.Fatalf("new order: %d %v; want it created and saying what it replaces", status, order)
	}
	finalize, _ := order["finalize"].(string)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"web.example.com", "api.example.com"}}, newKey(t))
	if _, _, err := a.client.CreateOrderCert(context.Background(), finalize, csr, true); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	rows := f.acmeRows()
	if len(rows) != 1 || rows[0].RenewalCount != 1 || len(rows[0].SANs) != 2 {
		t.Fatalf("%d records; want the one it replaced, renewed with both names", len(rows))
	}
	if rows[0].PreviousFingerprint != fingerprint(der) {
		t.Error("the renewal did not keep the replaced certificate's fingerprint")
	}
}

func TestACertificateIsOnlyReplacedOnce(t *testing.T) {
	f := newFixture(t)
	a := f.account("kid-a")
	der, _ := f.issued(a.client, "web.example.com")
	id := certID(t, der)

	_, order := f.newOrder(a, id, "web.example.com")
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"web.example.com"}}, newKey(t))
	if _, _, err := a.client.CreateOrderCert(context.Background(), order["finalize"].(string), csr, true); err != nil {
		t.Fatal(err)
	}
	status, got := f.newOrder(a, id, "web.example.com")
	if status != http.StatusConflict || got["type"] != "urn:ietf:params:acme:error:alreadyReplaced" {
		t.Fatalf("got %d %v, want 409 alreadyReplaced", status, got)
	}
}

func TestReplacesHasToBeAboutTheSameCertificate(t *testing.T) {
	f := newFixture(t)
	a := f.account("kid-a")
	der, _ := f.issued(a.client, "web.example.com")
	id := certID(t, der)

	b := f.account("kid-b")
	if status, got := f.newOrder(b, id, "web.example.com"); status != http.StatusForbidden ||
		got["type"] != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("another account replacing it: %d %v, want 403 unauthorized", status, got)
	}
	if status, got := f.newOrder(a, id, "other.example.com"); status != http.StatusBadRequest ||
		got["type"] != "urn:ietf:params:acme:error:malformed" {
		t.Errorf("an order sharing no name with it: %d %v, want 400 malformed", status, got)
	}
	if status, got := f.newOrder(a, "garbage", "web.example.com"); status != http.StatusBadRequest {
		t.Errorf("a malformed identifier: %d %v, want 400", status, got)
	}
}

// A certificate CertPilot no longer has a record of, because somebody deleted
// it, must not stop its client renewing. The order goes ahead as a new one.
func TestReplacingACertificateNobodyRecordsStillOrders(t *testing.T) {
	f := newFixture(t)
	a := f.account("kid-a")
	if status, got := f.newOrder(a, "AAEC.AQI", "web.example.com"); status != http.StatusCreated {
		t.Fatalf("got %d %v, want the order created", status, got)
	}
}

// A serial is unique per issuer only, so the issuer's key is half the name.
func TestTheRightSerialFromAnotherIssuerIsNotThatCertificate(t *testing.T) {
	f := newFixture(t)
	der, _ := f.issued(f.registered(), "web.example.com")
	_, serial, _ := strings.Cut(certID(t, der), ".")
	if resp, _ := f.renewalInfo(base64.RawURLEncoding.EncodeToString([]byte("another issuer")) + "." + serial); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

// Revoked between ordering and finalising: the revoked record says what
// happened, and the order's certificate is a new record beside it.
func TestAReplacedCertificateRevokedMeanwhileIsNotWrittenOver(t *testing.T) {
	f := newFixture(t)
	a := f.account("kid-a")
	der, _ := f.issued(a.client, "web.example.com")
	_, order := f.newOrder(a, certID(t, der), "web.example.com")
	if err := a.client.RevokeCert(context.Background(), nil, der, acme.CRLReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"web.example.com"}}, newKey(t))
	if _, _, err := a.client.CreateOrderCert(context.Background(), order["finalize"].(string), csr, true); err != nil {
		t.Fatal(err)
	}
	if rows := f.acmeRows(); len(rows) != 2 || f.recorded(der).Status != "REVOKED" {
		t.Fatalf("%d records; want the revoked one kept and a new one", len(rows))
	}
}
