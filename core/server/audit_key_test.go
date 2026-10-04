package server

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// sealedWith returns a store whose audit chain was written under kr, as a
// database restored from a backup would be.
func sealedWith(t *testing.T, kr *secrets.Keyring) store.Store {
	t.Helper()
	st := store.NewMemoryStore()
	st.UseAuditChain(store.NewAuditChainer(kr))
	for _, action := range []string{"auth.login", "ca_account.created", "cert.issued"} {
		if err := st.CreateAuditLog(context.Background(), &store.AuditLog{Action: action, EntityType: "test", Details: "{}"}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func keyring(t *testing.T, primary byte, retired ...byte) *secrets.Keyring {
	t.Helper()
	key := func(b byte) []byte { k := make([]byte, secrets.KEKSize); k[0] = b; return k }
	var old [][]byte
	for _, r := range retired {
		old = append(old, key(r))
	}
	kr, err := secrets.NewKeyring(key(primary), old...)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// startWith wires kr into st the way NewServer does, then runs the guard.
func startWith(t *testing.T, st store.Store, kr *secrets.Keyring, abandon string) error {
	t.Helper()
	st.UseAuditChain(store.NewAuditChainer(kr))
	return guardAuditKey(context.Background(), st, kr, abandon)
}

// TestTheCoreRefusesADatabaseSealedWithAnotherKey.
//
// Restored with the wrong CERTPILOT_KEK, the core started as if nothing were
// wrong. Nothing sealed could be read, which was at least loud, but the first
// sign-in wrote an audit entry signed with the wrong key. Once the right key
// was back that entry could never be checked, so the chain reported itself
// broken for ever over a mistake nobody had made on purpose.
func TestTheCoreRefusesADatabaseSealedWithAnotherKey(t *testing.T) {
	sealedBy := keyring(t, 1)
	st := sealedWith(t, sealedBy)
	given := keyring(t, 2)

	err := startWith(t, st, given, "")
	if err == nil {
		t.Fatal("the core started on a database sealed with a key it was not given")
	}
	for _, want := range []string{sealedBy.PrimaryKeyID(), given.PrimaryKeyID(), "CERTPILOT_KEK_ABANDON=" + sealedBy.PrimaryKeyID()} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	_, latest, _ := st.LatestAuditKey(context.Background())
	if latest != sealedBy.PrimaryKeyID() {
		t.Errorf("the refusal wrote an audit entry under key %s; it must write nothing", latest)
	}
}

// TestARetiredKeyIsEnoughToStart is a rotation in progress: the database was
// sealed with the key that is now retired, and that is fine.
func TestARetiredKeyIsEnoughToStart(t *testing.T) {
	st := sealedWith(t, keyring(t, 1))
	if err := startWith(t, st, keyring(t, 2, 1), ""); err != nil {
		t.Fatalf("a keyring holding the sealing key as retired was refused: %v", err)
	}
}

// TestAFreshDatabaseStarts: nothing chained yet, so there is nothing to match.
func TestAFreshDatabaseStarts(t *testing.T) {
	if err := startWith(t, store.NewMemoryStore(), keyring(t, 1), ""); err != nil {
		t.Fatalf("a database with no chained audit entries was refused: %v", err)
	}
}

// TestAbandoningTheNamedKeyStartsAndRecordsIt.
//
// The key that sealed a database can be lost for good. Then everything it
// sealed is gone whatever the core does, and refusing to start for ever would
// only stop the operator reissuing what can be reissued. Naming the lost key
// says that on purpose, and the audit log says it happened.
func TestAbandoningTheNamedKeyStartsAndRecordsIt(t *testing.T) {
	sealedBy := keyring(t, 1)
	st := sealedWith(t, sealedBy)
	given := keyring(t, 2)

	if err := startWith(t, st, given, sealedBy.PrimaryKeyID()); err != nil {
		t.Fatalf("abandoning the named key did not let the core start: %v", err)
	}

	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{Actions: []string{"secrets.kek_abandoned"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 {
		t.Fatalf("abandoning a key wrote %d audit entries, want 1", len(logs))
	}
	if !strings.Contains(logs[0].Details, sealedBy.PrimaryKeyID()) {
		t.Errorf("the audit entry does not name the abandoned key: %s", logs[0].Details)
	}

	_, latest, _ := st.LatestAuditKey(context.Background())
	if latest != given.PrimaryKeyID() {
		t.Errorf("the record of the abandonment was signed with %s, want the new key %s", latest, given.PrimaryKeyID())
	}
	if err := startWith(t, st, given, ""); err != nil {
		t.Errorf("the next start, without the override, was refused: %v", err)
	}
}

// TestAbandoningSomeOtherKeyDoesNotHelp: the override names one key, so a
// stale value left in the environment cannot wave a different mismatch through.
func TestAbandoningSomeOtherKeyDoesNotHelp(t *testing.T) {
	st := sealedWith(t, keyring(t, 1))
	if err := startWith(t, st, keyring(t, 2), keyring(t, 3).PrimaryKeyID()); err == nil {
		t.Fatal("abandoning an unrelated key let the core start on a database sealed with another")
	}
}
