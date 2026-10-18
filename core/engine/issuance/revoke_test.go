package issuance

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

// revokeFixture is a revoker, a store holding one issued certificate bound to
// a CA account, and the gateway that account is served by.
func revokeFixture(t *testing.T) (*Revoker, store.Store, *store.Certificate, *fakeGateway) {
	t.Helper()
	signer, d, _, gw := signFixture(t, signsTheRequest)
	ctx := context.Background()

	st := store.NewMemoryStore()
	acc := d.Account
	if err := st.CreateCAAccount(ctx, acc); err != nil {
		t.Fatal(err)
	}
	pem := "-----BEGIN CERTIFICATE-----\nbm90IHBhcnNlZCBvbiB0aGlzIHBhdGg=\n-----END CERTIFICATE-----\n"
	cert := &store.Certificate{
		CommonName: "web.example.com", FingerprintSHA256: "ab12", Status: "ISSUED",
		CertificatePEM: &pem, CAAccountID: &acc.ID, DiscoveredVia: "REQUESTED",
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}
	return NewRevoker(st, signer.plugins, signer.keyring), st, cert, gw
}

func revokeKind(t *testing.T, err error) RevokeFailure {
	t.Helper()
	re, ok := AsRevokeError(err)
	if !ok {
		t.Fatalf("got %v, want a RevokeError", err)
	}
	return re.Kind
}

func statusOf(t *testing.T, st store.Store, id string) string {
	t.Helper()
	got, err := st.GetCertificate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return got.Status
}

func TestARevocationTheCAAcceptsIsRecorded(t *testing.T) {
	r, st, cert, gw := revokeFixture(t)
	got, err := r.Revoke(context.Background(), cert, 1, "acme:account-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if gw.revoked.Load() != 1 || gw.lastReason.Load() != 1 {
		t.Errorf("the CA was asked %d times with reason %d, want once with 1", gw.revoked.Load(), gw.lastReason.Load())
	}
	if got.Status != "REVOKED" || got.RevocationReason == nil || *got.RevocationReason != 1 || got.RevokedBy != "acme:account-1" {
		t.Errorf("recorded as %s, reason %v, by %q", got.Status, got.RevocationReason, got.RevokedBy)
	}
	if statusOf(t, st, cert.ID) != "REVOKED" {
		t.Error("the store does not say it is revoked")
	}
}

// The order is the point: a CA that says no leaves the record as it was, so a
// certificate never reads REVOKED while it still answers handshakes.
func TestARevocationTheCARefusesChangesNothing(t *testing.T) {
	r, st, cert, gw := revokeFixture(t)
	gw.refuseRevocation.Store(true)
	_, err := r.Revoke(context.Background(), cert, 1, "someone")
	if revokeKind(t, err) != RevokeCANotTold || !strings.Contains(err.Error(), "this account may not revoke that") {
		t.Fatalf("got %v, want the CA's refusal passed on", err)
	}
	if statusOf(t, st, cert.ID) != "ISSUED" {
		t.Error("a refused revocation was recorded")
	}
}

func TestAnUnreachableCAChangesNothing(t *testing.T) {
	r, st, cert, _ := revokeFixture(t)
	acc, _ := st.GetCAAccount(context.Background(), *cert.CAAccountID)
	acc.Name, acc.GatewayAddr = "nowhere", "127.0.0.1:1"
	if err := st.UpdateCAAccount(context.Background(), acc); err != nil {
		t.Fatal(err)
	}
	_, err := r.Revoke(context.Background(), cert, 1, "someone")
	if revokeKind(t, err) != RevokeCANotTold || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("got %v, want a not-connected refusal", err)
	}
	if statusOf(t, st, cert.ID) != "ISSUED" {
		t.Error("a revocation the CA never heard of was recorded")
	}
}

func TestWhatCannotBeRevokedIsRefusedWithoutAskingTheCA(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*store.Certificate)
		reason int
		want   RevokeFailure
	}{
		{"already revoked", func(c *store.Certificate) { c.Status = "REVOKED" }, 1, RevokeAlreadyRevoked},
		{"no copy held", func(c *store.Certificate) { c.CertificatePEM = nil }, 1, RevokeNotPossible},
		{"no CA account", func(c *store.Certificate) { c.CAAccountID = nil }, 1, RevokeNotPossible},
		{"a reason RFC 5280 does not have", func(*store.Certificate) {}, 7, RevokeBadReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, cert, gw := revokeFixture(t)
			tc.mutate(cert)
			_, err := r.Revoke(context.Background(), cert, tc.reason, "someone")
			if revokeKind(t, err) != tc.want {
				t.Fatalf("got %v, want kind %d", err, tc.want)
			}
			if gw.revoked.Load() != 0 {
				t.Error("the CA was asked anyway")
			}
		})
	}
}
