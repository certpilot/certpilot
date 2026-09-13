package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// csrWith builds a signed request carrying whatever a caller wants to test,
// including the extensions a request has no business asking for.
func csrWith(t *testing.T, tmpl *x509.CertificateRequest) *x509util.CSRInfo {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := x509util.ParseCSRPEM(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: der,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// TestARequestToBecomeAnAuthorityIsRefusedOnEveryPath.
//
// This control used to live in the fleet issuer and applied to agents only, so
// the identical CSR submitted by a person through the API reached the gateway
// unchecked. It is the mirror image of the bypass this package was written to
// close, and it is fixed the same way: one place decides, and every path asks.
//
// Refused rather than stripped. A correct CA builds its own template and
// ignores everything in the request but the public key and the names — which is
// what the gateways here do — but "the code downstream is careful" is a hope
// about code that may be a third-party gateway next year, not a control.
func TestARequestToBecomeAnAuthorityIsRefusedOnEveryPath(t *testing.T) {
	basicConstraints, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: true, MaxPathLen: -1})
	if err != nil {
		t.Fatal(err)
	}
	keyCertSign, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		ext      pkix.Extension
		contains string
	}{
		{
			name:     "basicConstraints CA:TRUE",
			ext:      pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basicConstraints},
			contains: "never an authority that could issue more",
		},
		{
			name:     "keyCertSign",
			ext:      pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: keyCertSign},
			contains: "never an authority",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, accountID := fixture(t)
			save(t, s, unconstrained("any", accountID))

			csr := csrWith(t, &x509.CertificateRequest{
				Subject:         pkix.Name{CommonName: "a.example.com"},
				DNSNames:        []string{"a.example.com"},
				ExtraExtensions: []pkix.Extension{tc.ext},
			})

			_, err := r.Resolve(context.Background(), Request{TemplateRef: "any", CSR: csr})
			refusedBy(t, err, RungTemplate, tc.contains)
		})
	}
}

// TestATemplateDecidesWhichKindsOfNameItIssues.
//
// san_rules.types was accepted by the API, stored, shown on the template and
// consulted by nothing — a rule an operator wrote that changed no outcome. That
// is the defect class this whole line of work exists to remove, reintroduced
// one layer up, and it is the reason this test exists rather than a
// hard-coded DNS-only rule in the agent path.
//
// Migration 038 sets `{"types": ["DNS"]}` on every template generated from an
// existing grant, so agents behave exactly as they did and a template can now
// permit an IP or SPIFFE name deliberately.
func TestATemplateDecidesWhichKindsOfNameItIssues(t *testing.T) {
	spiffe, err := url.Parse("spiffe://example.com/ns/default/sa/web")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		types    []string
		csr      *x509.CertificateRequest
		contains string
	}{
		{
			name:     "an IP name under a DNS-only template",
			types:    []string{"DNS"},
			csr:      &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.example.com"}, DNSNames: []string{"a.example.com"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
			contains: "carries ip name",
		},
		{
			name:     "an email name under a DNS-only template",
			types:    []string{"DNS"},
			csr:      &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.example.com"}, DNSNames: []string{"a.example.com"}, EmailAddresses: []string{"ops@example.com"}},
			contains: "carries email name",
		},
		{
			name:     "a URI name under a DNS-only template",
			types:    []string{"DNS"},
			csr:      &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.example.com"}, DNSNames: []string{"a.example.com"}, URIs: []*url.URL{spiffe}},
			contains: "carries uri name",
		},
		{
			name:     "a DNS name under a template that issues only SPIFFE identities",
			types:    []string{"URI"},
			csr:      &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.example.com"}, DNSNames: []string{"a.example.com"}, URIs: []*url.URL{spiffe}},
			contains: "carries DNS name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s, accountID := fixture(t)
			tpl := unconstrained("typed", accountID)
			tpl.SANRules.Types = tc.types
			save(t, s, tpl)

			_, err := r.Resolve(context.Background(), Request{
				TemplateRef: "typed", CSR: csrWith(t, tc.csr),
			})
			refusedBy(t, err, RungTemplate, tc.contains)
		})
	}

	// And a template that permits the kind lets it through, or the rule is a
	// refusal with no matching acceptance.
	t.Run("an IP name a template permits", func(t *testing.T) {
		r, s, accountID := fixture(t)
		tpl := unconstrained("ip-ok", accountID)
		tpl.SANRules.Types = []string{"DNS", "IP"}
		save(t, s, tpl)

		csr := csrWith(t, &x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: "a.example.com"},
			DNSNames:    []string{"a.example.com"},
			IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		})
		if _, err := r.Resolve(context.Background(), Request{TemplateRef: "ip-ok", CSR: csr}); err != nil {
			t.Fatalf("a template permitting IP names refused one: %v", err)
		}
	})

	// A template saying nothing about types restricts none of them.
	t.Run("a template with no type rule", func(t *testing.T) {
		r, s, accountID := fixture(t)
		save(t, s, unconstrained("untyped", accountID))

		csr := csrWith(t, &x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: "a.example.com"},
			DNSNames:    []string{"a.example.com"},
			IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		})
		if _, err := r.Resolve(context.Background(), Request{TemplateRef: "untyped", CSR: csr}); err != nil {
			t.Fatalf("a template with no type rule refused a name: %v", err)
		}
	})
}

// TestNamesAreNormalisedOnce.
//
// The issued certificate, the grant's name list and the template's suffixes all
// have to be talking about the same string. DNS names are case-insensitive and
// a trailing dot is the same name, so both are normalised here rather than at
// each comparison — where one of the three would eventually forget.
func TestNamesAreNormalisedOnce(t *testing.T) {
	r, s, accountID := fixture(t)
	save(t, s, unconstrained("any", accountID))

	csr := csrWith(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "APP.Example.COM."},
		DNSNames: []string{"APP.example.com", "app.example.com."},
	})

	d, err := r.Resolve(context.Background(), Request{TemplateRef: "any", CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Domains) != 1 || d.Domains[0] != "app.example.com" {
		t.Errorf("three spellings of one name came through as %v", d.Domains)
	}
}

// TestATemplateCanRequireTheKeyToBeSomewhereElse. A template for host workloads
// says AGENT, and a request that would leave the key in CertPilot is refused
// rather than quietly honoured.
func TestATemplateCanRequireTheKeyToBeSomewhereElse(t *testing.T) {
	r, s, accountID := fixture(t)
	tpl := unconstrained("hosts-only", accountID)
	tpl.KeyCustodyRequired = store.KeyCustodyAgent
	save(t, s, tpl)

	csr := csrWith(t, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "a.example.com"}, DNSNames: []string{"a.example.com"},
	})

	if _, err := r.Resolve(context.Background(), Request{
		TemplateRef: "hosts-only", CSR: csr, KeyCustody: store.KeyCustodyAgent,
	}); err != nil {
		t.Fatalf("an agent's own key was refused by a template that requires exactly that: %v", err)
	}

	_, err := r.Resolve(context.Background(), Request{
		TemplateRef: "hosts-only", CSR: csr, KeyCustody: store.KeyCustodyCertPilot,
	})
	refusedBy(t, err, RungTemplate, "held by AGENT")
}
