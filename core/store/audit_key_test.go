package store

import (
	"context"
	"testing"

	"github.com/certpilot/certpilot/pkg/secrets"
)

// TestTheNewestAuditKeyConformance.
//
// The newest chained audit entry names the key that signed it. The core reads
// it at startup to tell whether the key it was given is the one this database
// was sealed with, so both stores must report it, and report the newest one
// after a rotation rather than the first.
func TestTheNewestAuditKeyConformance(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		seq, id, err := s.LatestAuditKey(ctx)
		if err != nil {
			t.Fatalf("an empty chain is not an error: %v", err)
		}
		if id != "" {
			t.Fatalf("a store with no chained entries reports key %q at seq %d", id, seq)
		}

		first, err := secrets.NewEphemeralKeyring()
		if err != nil {
			t.Fatal(err)
		}
		s.UseAuditChain(NewAuditChainer(first))
		for i := 0; i < 3; i++ {
			if err := s.CreateAuditLog(ctx, &AuditLog{Action: "certificate.issued", EntityType: "certificate", Details: "{}"}); err != nil {
				t.Fatal(err)
			}
		}
		seq, id, err = s.LatestAuditKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id != first.PrimaryKeyID() || seq != 3 {
			t.Fatalf("got key %q at seq %d, want %q at seq 3", id, seq, first.PrimaryKeyID())
		}

		second, err := secrets.NewEphemeralKeyring()
		if err != nil {
			t.Fatal(err)
		}
		s.UseAuditChain(NewAuditChainer(second))
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: "auth.login", EntityType: "session", Details: "{}"}); err != nil {
			t.Fatal(err)
		}
		seq, id, err = s.LatestAuditKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id != second.PrimaryKeyID() || seq != 4 {
			t.Fatalf("after a rotation got key %q at seq %d, want the new key %q at seq 4", id, seq, second.PrimaryKeyID())
		}
	})
}
