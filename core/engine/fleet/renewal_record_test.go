package fleet

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/store"
)

// An agent renews by asking again, with a new key. The core recorded every
// answer as a new certificate, so the one it replaced stayed ISSUED, counted in
// the inventory and on the horizon, and would alert as it neared expiry about
// a certificate nothing was serving any more. A renewal done by the core
// updates its record in place; one done by the host now does too.

type recordFixture struct {
	issuer   *Issuer
	store    store.Store
	agent    *store.Agent
	grant    *store.TemplateGrant
	decision *issuance.Decision
}

func newRecordFixture(t *testing.T) recordFixture {
	t.Helper()
	issuer, s, agent, tpl := bypassFixture(t)
	ctx := context.Background()
	grants, err := s.GetGrantsForAgent(ctx, agent.ID)
	if err != nil || len(grants) == 0 {
		t.Fatalf("the fixture's grant: %v", err)
	}
	acc, err := s.GetCAAccount(ctx, tpl.CAAccountID)
	if err != nil {
		t.Fatalf("the fixture's account: %v", err)
	}
	return recordFixture{issuer, s, agent, grants[0],
		&issuance.Decision{Template: tpl, Account: acc, RenewBeforeDays: 30, KeyType: "ECDSA", KeySize: 256}}
}

var hostNames = []string{"web-01.example.com"}

// issue records what a gateway returned, as Issue does after the CA answers.
func (f recordFixture) issue(t *testing.T, agent *store.Agent, prev *store.Certificate, serial, fingerprint string) *store.Certificate {
	t.Helper()
	now := time.Now()
	info := &x509util.CertInfo{
		CommonName: hostNames[0], SANs: hostNames, SerialNumber: serial, FingerprintSHA256: fingerprint,
		NotBefore: now, NotAfter: now.Add(90 * 24 * time.Hour), DaysRemaining: 90, KeyType: "ECDSA", KeySize: 256,
	}
	resp := &providerv1.IssueCertificateResponse{Certificate: &commonv1.CertificateInfo{
		CertificatePem: []byte("-----BEGIN CERTIFICATE-----\n" + serial + "\n-----END CERTIFICATE-----\n"),
	}}
	cert, err := f.issuer.record(context.Background(), agent, f.grant, f.decision, Request{}, info, resp, nil, prev)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	return cert
}

func (f recordFixture) otherAgent(t *testing.T) *store.Agent {
	t.Helper()
	other := &store.Agent{Name: "web-02", KeyID: "agt_web02", PublicKey: "BBBB", Status: "ACTIVE"}
	if err := f.store.CreateAgent(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	return other
}

func TestAnAgentRenewalUpdatesTheRecordItReplaces(t *testing.T) {
	f := newRecordFixture(t)
	ctx := context.Background()
	first := f.issue(t, f.agent, nil, "01", "aa")

	prev, err := f.issuer.replaces(ctx, f.agent, "", hostNames, "ECDSA")
	if err != nil {
		t.Fatalf("replaces: %v", err)
	}
	if prev == nil || prev.ID != first.ID {
		t.Fatalf("the renewal was not matched to the certificate it replaces")
	}
	renewed := f.issue(t, f.agent, prev, "02", "bb")

	if renewed.ID != first.ID {
		t.Errorf("the renewal was recorded as certificate %s, a new record beside %s", renewed.ID, first.ID)
	}
	all, _, err := f.store.ListCertificates(ctx, store.CertificateFilter{CommonName: hostNames[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("%d records for one certificate on one host, want 1", len(all))
	}
	got := all[0]
	if got.SerialNumber != "02" || got.FingerprintSHA256 != "bb" || got.Status != "ISSUED" {
		t.Errorf("the record holds serial %s, fingerprint %s, status %s; want the renewed 02, bb, ISSUED",
			got.SerialNumber, got.FingerprintSHA256, got.Status)
	}
	if got.RenewalCount != 1 {
		t.Errorf("renewal_count = %d, want 1", got.RenewalCount)
	}
	if got.PreviousFingerprint != "aa" {
		t.Errorf("previous_fingerprint = %q, want the replaced certificate's (aa), which is what the verifier compares against", got.PreviousFingerprint)
	}
}

func TestRenewsNamesTheRecordExplicitly(t *testing.T) {
	f := newRecordFixture(t)
	first := f.issue(t, f.agent, nil, "01", "aa")
	prev, err := f.issuer.replaces(context.Background(), f.agent, first.ID, hostNames, "ECDSA")
	if err != nil || prev == nil || prev.ID != first.ID {
		t.Fatalf("renews=%s was not honoured: prev=%v err=%v", first.ID, prev, err)
	}
}

// A host naming another host's certificate is either a bug or a credential
// being tried against something it should not reach. Refused before the CA is
// asked for anything.
func TestAHostCannotRenewAnotherHostsCertificate(t *testing.T) {
	f := newRecordFixture(t)
	first := f.issue(t, f.agent, nil, "01", "aa")
	if _, err := f.issuer.replaces(context.Background(), f.otherAgent(t), first.ID, hostNames, "ECDSA"); err == nil {
		t.Fatal("a host was allowed to renew a certificate whose key another host holds")
	}
}

// Two hosts serving the same name each hold their own key, so each has its own
// certificate, and one renewing must not overwrite the other's record.
func TestAnotherHostWithTheSameNamesKeepsItsOwnRecord(t *testing.T) {
	f := newRecordFixture(t)
	f.issue(t, f.agent, nil, "01", "aa")
	prev, err := f.issuer.replaces(context.Background(), f.otherAgent(t), "", hostNames, "ECDSA")
	if err != nil || prev != nil {
		t.Fatalf("web-02's request was matched to web-01's certificate: prev=%v err=%v", prev, err)
	}
}

// nginx and others can serve an RSA and an ECDSA certificate for the same
// names side by side. An agent that keeps both is not renewing one with the
// other.
func TestADifferentKeyTypeIsNotARenewal(t *testing.T) {
	f := newRecordFixture(t)
	f.issue(t, f.agent, nil, "01", "aa")
	prev, err := f.issuer.replaces(context.Background(), f.agent, "", hostNames, "RSA")
	if err != nil || prev != nil {
		t.Fatalf("an RSA request was treated as renewing the ECDSA certificate: prev=%v err=%v", prev, err)
	}
}

// A revoked certificate's record is history. A new certificate is a new
// record, not an overwrite of the one that says what was revoked and why.
func TestARevokedCertificateIsNotRenewedInPlace(t *testing.T) {
	f := newRecordFixture(t)
	first := f.issue(t, f.agent, nil, "01", "aa")
	first.Status = "REVOKED"
	if err := f.store.UpdateCertificate(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	for _, renews := range []string{"", first.ID} {
		prev, err := f.issuer.replaces(context.Background(), f.agent, renews, hostNames, "ECDSA")
		if err != nil || prev != nil {
			t.Fatalf("renews=%q matched a revoked record: prev=%v err=%v", renews, prev, err)
		}
	}
}
