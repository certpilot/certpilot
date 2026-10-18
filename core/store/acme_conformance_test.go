package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The ACME server keeps three things: the credentials an administrator hands
// out, the accounts a client makes with them, and the nonces it has accepted.
// Each is tested against both stores, because the way a column is dropped or a
// uniqueness rule goes missing differs between them.

func acmeTemplate(t *testing.T, s Store) string {
	t.Helper()
	tpl := fullTemplate("acme-test", caAccountFor(t, s, "ACME test CA"))
	if err := s.CreateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatalf("create template: %v", err)
	}
	return tpl.ID
}

func TestAnACMECredentialKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		by := "admin@example.com"
		cred := &ACMEEABCredential{
			KID: "kid-1", Name: "web team", TemplateID: acmeTemplate(t, s),
			HMACKeySealed: "CPS1:sealed", CreatedBy: &by,
		}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatalf("create: %v", err)
		}
		if cred.ID == "" || cred.CreatedAt.IsZero() {
			t.Fatalf("create did not assign an id and a time: %+v", cred)
		}

		got, err := s.GetACMEEABCredentialByKID(ctx, "kid-1")
		if err != nil || got == nil {
			t.Fatalf("lookup by kid: %v, %v", got, err)
		}
		if got.Name != "web team" || got.TemplateID != cred.TemplateID ||
			got.HMACKeySealed != "CPS1:sealed" || got.CreatedBy == nil || *got.CreatedBy != by {
			t.Errorf("a field was dropped: wrote %+v, read back %+v", cred, got)
		}
		if got.AccountID != nil {
			t.Errorf("a credential nobody has used reports account %s", *got.AccountID)
		}

		if miss, err := s.GetACMEEABCredentialByKID(ctx, "nope"); err != nil || miss != nil {
			t.Errorf("a miss returned (%v, %v), want (nil, nil)", miss, err)
		}
	})
}

func TestACMECredentialKeyIdsAreUnique(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		first := &ACMEEABCredential{KID: "same", Name: "a", TemplateID: tpl, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, first); err != nil {
			t.Fatal(err)
		}
		second := &ACMEEABCredential{KID: "same", Name: "b", TemplateID: tpl, HMACKeySealed: "y"}
		if err := s.CreateACMEEABCredential(ctx, second); err == nil {
			t.Fatal("two credentials with one key id were accepted; the second would never be found")
		}
	})
}

func TestARevokedACMECredentialIsStillFoundAndSaysSo(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		cred := &ACMEEABCredential{KID: "k", Name: "n", TemplateID: acmeTemplate(t, s), HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		by := "admin"
		if _, err := s.RevokeACMEEABCredential(ctx, cred.ID, &by); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		got, _ := s.GetACMEEABCredentialByKID(ctx, "k")
		if got == nil || got.RevokedAt == nil {
			t.Fatalf("a revoked credential must be found and marked, got %+v", got)
		}
		if _, err := s.RevokeACMEEABCredential(ctx, missingID, &by); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoking a missing credential returned %v, want ErrNotFound", err)
		}
	})
}

func TestAnACMEAccountKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		cred := &ACMEEABCredential{KID: "k", Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}

		acct := &ACMEAccount{
			TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "thumb",
			JWK: `{"kty":"EC"}`, Contacts: []string{"mailto:ops@example.com"},
		}
		if err := s.CreateACMEAccount(ctx, acct); err != nil {
			t.Fatalf("create: %v", err)
		}
		if acct.ID == "" || acct.Status != ACMEAccountValid {
			t.Fatalf("create did not assign an id and a valid status: %+v", acct)
		}

		got, err := s.GetACMEAccount(ctx, acct.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.TemplateID != tpl || got.EABID != cred.ID || got.JWKThumbprint != "thumb" ||
			got.JWK != `{"kty":"EC"}` || len(got.Contacts) != 1 || got.Contacts[0] != "mailto:ops@example.com" {
			t.Errorf("a field was dropped: wrote %+v, read back %+v", acct, got)
		}

		byThumb, err := s.GetACMEAccountByThumbprint(ctx, tpl, "thumb")
		if err != nil || byThumb == nil || byThumb.ID != acct.ID {
			t.Errorf("by thumbprint: %v, %v", byThumb, err)
		}
		byEAB, err := s.GetACMEAccountByEAB(ctx, cred.ID)
		if err != nil || byEAB == nil || byEAB.ID != acct.ID {
			t.Errorf("by credential: %v, %v", byEAB, err)
		}

		// The credential now says which account used it.
		used, _ := s.GetACMEEABCredentialByKID(ctx, "k")
		if used.AccountID == nil || *used.AccountID != acct.ID {
			t.Errorf("the credential does not name the account that used it: %+v", used)
		}

		if _, err := s.GetACMEAccount(ctx, missingID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing account returned %v, want ErrNotFound", err)
		}
	})
}

func TestOneACMECredentialMakesOneAccount(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		cred := &ACMEEABCredential{KID: "k", Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateACMEAccount(ctx, &ACMEAccount{TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "one", JWK: "{}"}); err != nil {
			t.Fatal(err)
		}
		err := s.CreateACMEAccount(ctx, &ACMEAccount{TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "two", JWK: "{}"})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("a second account on one credential returned %v, want ErrConflict: "+
				"otherwise one leaked credential makes unlimited accounts", err)
		}
	})
}

func TestAnACMEAccountCanBeDeactivated(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		cred := &ACMEEABCredential{KID: "k", Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		acct := &ACMEAccount{TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "t", JWK: "{}"}
		if err := s.CreateACMEAccount(ctx, acct); err != nil {
			t.Fatal(err)
		}
		acct.Status = ACMEAccountDeactivated
		acct.Contacts = []string{"mailto:new@example.com"}
		if err := s.UpdateACMEAccount(ctx, acct); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, _ := s.GetACMEAccount(ctx, acct.ID)
		if got.Status != ACMEAccountDeactivated || len(got.Contacts) != 1 || got.Contacts[0] != "mailto:new@example.com" {
			t.Errorf("the update was not kept: %+v", got)
		}
	})
}

func TestAnACMENonceCanBeSpentOnce(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		hash := []byte("0123456789abcdef0123456789abcdef")
		first, err := s.ClaimACMENonce(ctx, hash, time.Now().Add(time.Hour))
		if err != nil || !first {
			t.Fatalf("first use: %v, %v", first, err)
		}
		again, err := s.ClaimACMENonce(ctx, hash, time.Now().Add(time.Hour))
		if err != nil || again {
			t.Fatalf("second use: %v, %v; a nonce that works twice is not a nonce", again, err)
		}

		n, err := s.SweepACMENonces(ctx, time.Now().Add(2*time.Hour))
		if err != nil || n != 1 {
			t.Errorf("sweep removed %d, %v; want the one expired nonce", n, err)
		}
	})
}

func acmeAccountFor(t *testing.T, s Store) *ACMEAccount {
	t.Helper()
	ctx := context.Background()
	tpl := acmeTemplate(t, s)
	cred := &ACMEEABCredential{KID: "order-kid", Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
	if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	acct := &ACMEAccount{TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "t", JWK: "{}"}
	if err := s.CreateACMEAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	return acct
}

func TestAnACMEOrderKeepsEveryFieldItWasGiven(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		expires := time.Now().Add(24 * time.Hour).Truncate(time.Second)
		order := &ACMEOrder{
			AccountID:   acct.ID,
			Status:      ACMEOrderReady,
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "web.example.com"}, {Type: "dns", Value: "api.example.com"}},
			ExpiresAt:   expires,
		}
		if err := s.CreateACMEOrder(ctx, order); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := s.GetACMEOrder(ctx, order.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.AccountID != acct.ID || got.Status != ACMEOrderReady || len(got.Identifiers) != 2 ||
			got.Identifiers[1].Value != "api.example.com" || !got.ExpiresAt.Equal(expires) {
			t.Errorf("a field was dropped: wrote %+v, read back %+v", order, got)
		}
		if _, err := s.GetACMEOrder(ctx, missingID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing order returned %v, want ErrNotFound", err)
		}

		list, err := s.ListACMEOrdersByAccount(ctx, acct.ID)
		if err != nil || len(list) != 1 || list[0].ID != order.ID {
			t.Errorf("list: %v, %v", list, err)
		}
	})
}

// Two replicas can receive the same finalize. Only one may go on to ask the CA,
// or the client is issued two certificates for one order.
func TestOnlyOneFinalizeClaimsAnOrder(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		order := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderReady,
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "a.example.com"}}, ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.CreateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
		first, err := s.ClaimACMEOrderForFinalize(ctx, order.ID)
		if err != nil || !first {
			t.Fatalf("first claim: %v, %v", first, err)
		}
		second, err := s.ClaimACMEOrderForFinalize(ctx, order.ID)
		if err != nil || second {
			t.Fatalf("second claim: %v, %v; an order must be finalised once", second, err)
		}
		got, _ := s.GetACMEOrder(ctx, order.ID)
		if got.Status != ACMEOrderProcessing {
			t.Errorf("status %q after the claim, want processing", got.Status)
		}
	})
}

func TestAFinishedACMEOrderRecordsItsCertificateOrItsError(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		ca := caAccountFor(t, s, "order CA")
		cert := &Certificate{CommonName: "a.example.com", Status: "ISSUED", DiscoveredVia: "ACME",
			CAAccountID: &ca, KeyCustody: KeyCustodyExternal, FingerprintSHA256: "fp-acme-1", KeyType: "ECDSA", KeySize: 256}
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatalf("an ACME certificate could not be recorded: %v", err)
		}

		ok := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderProcessing,
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "a.example.com"}}, ExpiresAt: time.Now().Add(time.Hour)}
		bad := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderProcessing,
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "b.example.com"}}, ExpiresAt: time.Now().Add(time.Hour)}
		for _, o := range []*ACMEOrder{ok, bad} {
			if err := s.CreateACMEOrder(ctx, o); err != nil {
				t.Fatal(err)
			}
		}

		ok.Status, ok.CertificateID = ACMEOrderValid, &cert.ID
		bad.Status, bad.Error = ACMEOrderInvalid, `{"type":"urn:ietf:params:acme:error:badCSR","detail":"no"}`
		for _, o := range []*ACMEOrder{ok, bad} {
			if err := s.UpdateACMEOrder(ctx, o); err != nil {
				t.Fatalf("update: %v", err)
			}
		}
		gotOK, _ := s.GetACMEOrder(ctx, ok.ID)
		gotBad, _ := s.GetACMEOrder(ctx, bad.ID)
		if gotOK.Status != ACMEOrderValid || gotOK.CertificateID == nil || *gotOK.CertificateID != cert.ID {
			t.Errorf("valid order lost its certificate: %+v", gotOK)
		}
		if gotBad.Status != ACMEOrderInvalid || gotBad.Error == "" {
			t.Errorf("invalid order lost its error: %+v", gotBad)
		}
	})
}

// Revocation by account key is allowed for the account that ordered the
// certificate, so the store has to answer which order produced one.
func TestAnACMEOrderIsFoundByTheCertificateItProduced(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		ca := caAccountFor(t, s, "lookup CA")
		cert := &Certificate{CommonName: "a.example.com", Status: "ISSUED", DiscoveredVia: "ACME",
			CAAccountID: &ca, KeyCustody: KeyCustodyExternal, FingerprintSHA256: "fp-acme-lookup", KeyType: "ECDSA", KeySize: 256}
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
		order := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderValid, CertificateID: &cert.ID,
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "a.example.com"}}, ExpiresAt: time.Now().Add(time.Hour)}
		if err := s.CreateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}

		got, err := s.GetACMEOrderByCertificate(ctx, cert.ID)
		if err != nil || got == nil || got.ID != order.ID || got.AccountID != acct.ID {
			t.Fatalf("got %+v, %v; want order %s", got, err, order.ID)
		}
		none, err := s.GetACMEOrderByCertificate(ctx, missingID)
		if err != nil || none != nil {
			t.Errorf("a certificate no order produced returned %+v, %v; want nil, nil", none, err)
		}
	})
}

// A key rollover replaces the key an account is found by. Two accounts on one
// template may not end up with the same key, or a request signed with it would
// name either.
func TestAnACMEAccountKeyCanBeChangedButNotToAnotherAccountsKey(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		a := acmeAccountFor(t, s)
		credB := &ACMEEABCredential{KID: "kid-b", Name: "b", TemplateID: a.TemplateID, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, credB); err != nil {
			t.Fatal(err)
		}
		b := &ACMEAccount{TemplateID: a.TemplateID, EABID: credB.ID, JWKThumbprint: "thumb-b", JWK: `{"b":1}`}
		if err := s.CreateACMEAccount(ctx, b); err != nil {
			t.Fatal(err)
		}

		if err := s.UpdateACMEAccountKey(ctx, a.ID, `{"new":1}`, "thumb-new"); err != nil {
			t.Fatalf("change key: %v", err)
		}
		got, err := s.GetACMEAccountByThumbprint(ctx, a.TemplateID, "thumb-new")
		if err != nil || got == nil || got.ID != a.ID || got.JWK != `{"new":1}` {
			t.Fatalf("by the new key: %+v, %v", got, err)
		}
		if old, _ := s.GetACMEAccountByThumbprint(ctx, a.TemplateID, a.JWKThumbprint); old != nil {
			t.Error("the account is still found by its old key")
		}

		if err := s.UpdateACMEAccountKey(ctx, a.ID, `{"b":1}`, "thumb-b"); !errors.Is(err, ErrConflict) {
			t.Errorf("taking another account's key: %v, want ErrConflict", err)
		}
		if err := s.UpdateACMEAccountKey(ctx, missingID, `{}`, "thumb-x"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing account: %v, want ErrNotFound", err)
		}
	})
}

// RFC 9773: an order may name the certificate it replaces, and a certificate
// can be replaced by one order that went ahead.
func TestAnACMEOrderKeepsWhatItReplaces(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		ca := caAccountFor(t, s, "replaces CA")
		cert := &Certificate{CommonName: "a.example.com", Status: "ISSUED", DiscoveredVia: "ACME",
			CAAccountID: &ca, KeyCustody: KeyCustodyExternal, FingerprintSHA256: "aki.serial-1", KeyType: "ECDSA", KeySize: 256}
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
		order := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderReady, ExpiresAt: time.Now().Add(time.Hour),
			Identifiers:           []ACMEIdentifier{{Type: "dns", Value: "a.example.com"}},
			ReplacesCertificateID: &cert.ID, Replaces: "aki.serial-1"}
		if err := s.CreateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetACMEOrder(ctx, order.ID)
		if err != nil || got.ReplacesCertificateID == nil || *got.ReplacesCertificateID != cert.ID || got.Replaces != "aki.serial-1" {
			t.Fatalf("read back %+v, %v; want what it replaces kept", got, err)
		}

		// Only an order that went ahead counts: one left ready may never be
		// finalised, and must not stop the client trying again.
		if o, err := s.GetACMEOrderReplacing(ctx, "aki.serial-1"); err != nil || o != nil {
			t.Errorf("a ready order counted as having replaced it: %+v, %v", o, err)
		}
		order.Status = ACMEOrderValid
		if err := s.UpdateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
		if o, err := s.GetACMEOrderReplacing(ctx, "aki.serial-1"); err != nil || o == nil || o.ID != order.ID {
			t.Errorf("the valid order that replaced it: %+v, %v", o, err)
		}
		if o, err := s.GetACMEOrderReplacing(ctx, "aki.serial-2"); err != nil || o != nil {
			t.Errorf("a certificate nothing replaced: %+v, %v", o, err)
		}
	})
}

// renewalInfo names a certificate by its issuer's key and its serial, so the
// inventory has to be searchable by serial. Serials are unique per issuer, not
// overall, so every match comes back.
func TestCertificatesAreFoundBySerial(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ca := caAccountFor(t, s, "serial CA")
		for i, fp := range []string{"fp-serial-1", "fp-serial-2", "fp-serial-3"} {
			serial := "0a1b2c"
			if i == 2 {
				serial = "ffff"
			}
			if err := s.CreateCertificate(ctx, &Certificate{CommonName: "s.example.com", Status: "ISSUED",
				DiscoveredVia: "ACME", CAAccountID: &ca, KeyCustody: KeyCustodyExternal,
				FingerprintSHA256: fp, SerialNumber: serial, KeyType: "ECDSA", KeySize: 256}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.GetCertificatesBySerial(ctx, "0a1b2c")
		if err != nil || len(got) != 2 {
			t.Fatalf("got %d, %v; want both certificates with that serial", len(got), err)
		}
		none, err := s.GetCertificatesBySerial(ctx, "0000")
		if err != nil || len(none) != 0 {
			t.Errorf("an unknown serial: %d, %v", len(none), err)
		}
	})
}

// Revoking a credential is how a client is cut off, so the account it made is
// deactivated in the same write: done as two, a failure between them left an
// account ordering on a revoked credential.
func TestRevokingAnACMECredentialDeactivatesItsAccount(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		deactivated, err := s.RevokeACMEEABCredential(ctx, acct.EABID, nil)
		if err != nil || deactivated != acct.ID {
			t.Fatalf("revoke: deactivated %q, %v; want the account %s", deactivated, err, acct.ID)
		}
		got, _ := s.GetACMEAccount(ctx, acct.ID)
		if got.Status != ACMEAccountDeactivated {
			t.Errorf("the account is %s after its credential was revoked", got.Status)
		}
		// Revoking again changes nothing and is not an error.
		if again, err := s.RevokeACMEEABCredential(ctx, acct.EABID, nil); err != nil || again != "" {
			t.Errorf("a second revoke: %q, %v", again, err)
		}
	})
}

// A registration that checked the credential before it was revoked must not
// then create an account with it.
func TestAnACMEAccountCannotBeMadeWithARevokedCredential(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		cred := &ACMEEABCredential{KID: "revoked-kid", Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RevokeACMEEABCredential(ctx, cred.ID, nil); err != nil {
			t.Fatal(err)
		}
		err := s.CreateACMEAccount(ctx, &ACMEAccount{TemplateID: tpl, EABID: cred.ID, JWKThumbprint: "t2", JWK: "{}"})
		if !errors.Is(err, ErrRevoked) {
			t.Fatalf("got %v, want ErrRevoked", err)
		}
	})
}

// A credential can say its client has to prove it controls each name.
func TestAnACMECredentialKeepsWhetherItRequiresChallenges(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		cred := &ACMEEABCredential{KID: "challenged", Name: "n", TemplateID: tpl, HMACKeySealed: "x", RequireChallenge: true}
		if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		byKID, err := s.GetACMEEABCredentialByKID(ctx, "challenged")
		if err != nil || byKID == nil || !byKID.RequireChallenge {
			t.Fatalf("by key id: %+v, %v", byKID, err)
		}
		byID, err := s.GetACMEEABCredential(ctx, cred.ID)
		if err != nil || !byID.RequireChallenge || byID.KID != "challenged" {
			t.Fatalf("by id: %+v, %v", byID, err)
		}
		if _, err := s.GetACMEEABCredential(ctx, missingID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing credential: %v, want ErrNotFound", err)
		}
	})
}

func TestACMEAuthorizationsKeepTheirChallengeState(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		acct := acmeAccountFor(t, s)
		order := &ACMEOrder{AccountID: acct.ID, Status: ACMEOrderPending, ExpiresAt: time.Now().Add(time.Hour),
			Identifiers: []ACMEIdentifier{{Type: "dns", Value: "a.example.com"}, {Type: "dns", Value: "*.example.com"}}}
		if err := s.CreateACMEOrder(ctx, order); err != nil {
			t.Fatal(err)
		}
		expires := time.Now().Add(time.Hour).Truncate(time.Second)
		for i, v := range []string{"a.example.com", "example.com"} {
			if err := s.CreateACMEAuthorization(ctx, &ACMEAuthorization{OrderID: order.ID, Index: i,
				Value: v, Wildcard: i == 1, Status: ACMEAuthzPending, Token: fmt.Sprintf("token-%d", i), ExpiresAt: expires}); err != nil {
				t.Fatalf("create authz %d: %v", i, err)
			}
		}
		list, err := s.ListACMEAuthorizations(ctx, order.ID)
		if err != nil || len(list) != 2 || list[0].Index != 0 || list[1].Value != "example.com" || !list[1].Wildcard ||
			list[1].Token != "token-1" || !list[1].ExpiresAt.Equal(expires) {
			t.Fatalf("list: %+v, %v", list, err)
		}

		authz := list[0]
		now := time.Now().Truncate(time.Second)
		authz.Status, authz.ValidatedWith, authz.ValidatedAt = ACMEAuthzValid, "http-01", &now
		if err := s.UpdateACMEAuthorization(ctx, authz); err != nil {
			t.Fatal(err)
		}
		bad := list[1]
		bad.Status, bad.Error = ACMEAuthzInvalid, `{"type":"urn:ietf:params:acme:error:unauthorized"}`
		if err := s.UpdateACMEAuthorization(ctx, bad); err != nil {
			t.Fatal(err)
		}
		list, _ = s.ListACMEAuthorizations(ctx, order.ID)
		if list[0].Status != ACMEAuthzValid || list[0].ValidatedWith != "http-01" || list[0].ValidatedAt == nil {
			t.Errorf("a validated authorization lost its state: %+v", list[0])
		}
		if list[1].Status != ACMEAuthzInvalid || list[1].Error == "" {
			t.Errorf("a failed authorization lost its error: %+v", list[1])
		}
		if none, err := s.ListACMEAuthorizations(ctx, missingID); err != nil || len(none) != 0 {
			t.Errorf("an order with none: %v, %v", none, err)
		}
	})
}

// A registration and a revocation of its credential, at the same instant, end
// one of two ways: no account, or a deactivated one. Never an active account
// on a revoked credential, which is a client nobody can cut off. Run many
// times, because the interleaving that breaks it is the rare one.
func TestARegistrationRacingTheRevocationNeverLeavesALiveAccount(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		tpl := acmeTemplate(t, s)
		const rounds = 150
		var refused, deactivated int
		for i := 0; i < rounds; i++ {
			cred := &ACMEEABCredential{KID: fmt.Sprintf("race-%d", i), Name: "n", TemplateID: tpl, HMACKeySealed: "x"}
			if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			var createErr, revokeErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				createErr = s.CreateACMEAccount(ctx, &ACMEAccount{TemplateID: tpl, EABID: cred.ID,
					JWKThumbprint: fmt.Sprintf("thumb-%d", i), JWK: "{}"})
			}()
			go func() {
				defer wg.Done()
				<-start
				_, revokeErr = s.RevokeACMEEABCredential(ctx, cred.ID, nil)
			}()
			close(start)
			wg.Wait()

			if revokeErr != nil {
				t.Fatalf("round %d: revoke: %v", i, revokeErr)
			}
			if createErr != nil && !errors.Is(createErr, ErrRevoked) {
				t.Fatalf("round %d: create: %v", i, createErr)
			}
			acct, err := s.GetACMEAccountByEAB(ctx, cred.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case acct == nil:
				refused++
			case acct.Status == ACMEAccountValid:
				t.Fatalf("round %d: an active account on a revoked credential", i)
			default:
				deactivated++
			}
		}
		t.Logf("%d rounds: %d registrations refused, %d accounts deactivated", rounds, refused, deactivated)
	})
}
