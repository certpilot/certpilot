package store

import (
	"context"
	"errors"
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
		if err := s.RevokeACMEEABCredential(ctx, cred.ID, &by); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		got, _ := s.GetACMEEABCredentialByKID(ctx, "k")
		if got == nil || got.RevokedAt == nil {
			t.Fatalf("a revoked credential must be found and marked, got %+v", got)
		}
		if err := s.RevokeACMEEABCredential(ctx, missingID, &by); !errors.Is(err, ErrNotFound) {
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
