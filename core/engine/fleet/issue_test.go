package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

// csrFor builds a request the way the agent does, optionally with extensions it
// has no business asking for.
func csrFor(t *testing.T, commonName string, sans []string, extra []pkix.Extension) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: commonName},
		DNSNames:        sans,
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestARequestMustBeSignedByTheKeyItContains.
//
// Without this, anybody who can reach the endpoint could obtain a certificate
// for a public key belonging to somebody else — which is a certificate issued
// to that somebody else, from an authority this organisation runs.
func TestARequestMustBeSignedByTheKeyItContains(t *testing.T) {
	valid := csrFor(t, "site.example.com", []string{"site.example.com"}, nil)

	block, _ := pem.Decode([]byte(valid))
	tampered := append([]byte{}, block.Bytes...)
	// Flip a bit in the subject, leaving the signature covering the original.
	tampered[len(tampered)/3] ^= 0x01
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))

	if _, err := parseCSR(valid); err != nil {
		t.Fatalf("a well-formed request should parse: %v", err)
	}
	if _, err := parseCSR(broken); err == nil {
		t.Fatal("a request whose signature does not cover its contents must be refused")
	}
	if _, err := parseCSR("not pem"); err == nil {
		t.Fatal("garbage must be refused")
	}
}

// TestARequestToBecomeAnAuthorityIsVisibleToTheCaller.
//
// The refusal moved. It used to live in this package and applied to agents
// only, so the identical CSR submitted by a person through the API reached the
// gateway unchecked — a control in one of two places, which is the shape of
// defect this whole line of work exists to remove. It is in the resolver now,
// and every issuance path goes through that.
//
// What is still this package's business is that parsing surfaces the ask at
// all, because a decision cannot refuse what it cannot see.
func TestARequestToBecomeAnAuthorityIsVisibleToTheCaller(t *testing.T) {
	basicConstraints, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: true, MaxPathLen: -1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	csr, err := parseCSR(csrFor(t, "site.example.com", []string{"site.example.com"}, []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: basicConstraints},
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !csr.RequestsCA {
		t.Error("a request for basicConstraints CA:TRUE was parsed without noticing")
	}

	// keyCertSign, which is the same ask by another route.
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	csr, err = parseCSR(csrFor(t, "site.example.com", []string{"site.example.com"}, []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: usage},
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !csr.RequestsKeyCertSign {
		t.Error("a request for keyCertSign was parsed without noticing")
	}
}

// TestTheCommonNameIsAuthorisedToo.
//
// A request whose SANs are all permitted and whose CN is not would otherwise
// produce a certificate for a name nobody granted.
func TestTheCommonNameIsAuthorisedToo(t *testing.T) {
	csr, err := parseCSR(csrFor(t, "payroll.example.com", []string{"site.example.com"}, nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names, err := requestedNames(csr)
	if err != nil {
		t.Fatalf("names: %v", err)
	}

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["payroll.example.com"] || !found["site.example.com"] {
		t.Fatalf("both the CN and the SANs have to be authorised, got %v", names)
	}
}

// TestAGrantCoversWhatItSays — wildcard semantics matching certificates', so a
// grant means what the person who wrote it thinks it means.
func TestAGrantCoversWhatItSays(t *testing.T) {
	grant := &store.TemplateGrant{
		IsEnabled: true,
		Names:     []string{"exact.example.com", "*.web.example.com"},
	}

	cases := map[string]bool{
		"exact.example.com":      true,
		"EXACT.example.com":      true, // case-insensitive
		"exact.example.com.":     true, // trailing dot
		"a.web.example.com":      true,
		"a.b.web.example.com":    false, // wildcards match one level
		"web.example.com":        false, // and not the bare domain
		"other.example.com":      false,
		"exact.example.com.evil": false,
	}
	for name, want := range cases {
		if got := grant.Covers(name); got != want {
			t.Fatalf("%q: expected %v, got %v", name, want, got)
		}
	}
}

// TestAGrantOnlyAppliesToTheHostsItNames.
//
// Labels come from the enrolment token, not from the agent, which is what makes
// them worth trusting: a host cannot label itself into a grant somebody wrote
// for a different tier.
func TestAGrantOnlyAppliesToTheHostsItNames(t *testing.T) {
	id := "agent-1"
	web := &store.Agent{ID: "agent-1", Status: store.AgentActive, Labels: map[string]string{"tier": "web", "env": "prod"}}
	db := &store.Agent{ID: "agent-2", Status: store.AgentActive, Labels: map[string]string{"tier": "db", "env": "prod"}}

	byID := &store.TemplateGrant{IsEnabled: true, AgentID: &id}
	if !byID.AppliesTo(web) || byID.AppliesTo(db) {
		t.Fatal("an agent-targeted grant applies to exactly that agent")
	}

	byLabel := &store.TemplateGrant{IsEnabled: true, LabelSelector: map[string]string{"tier": "web", "env": "prod"}}
	if !byLabel.AppliesTo(web) || byLabel.AppliesTo(db) {
		t.Fatal("a label selector matches only agents carrying every label")
	}

	// Every key must match, not any.
	partial := &store.TemplateGrant{IsEnabled: true, LabelSelector: map[string]string{"tier": "web", "env": "staging"}}
	if partial.AppliesTo(web) {
		t.Fatal("a selector with one wrong label must not match")
	}

	// And a revoked grant is not permission for anything.
	byID.IsEnabled = false
	if byID.AppliesTo(web) {
		t.Fatal("a disabled grant must apply to nothing")
	}
}
