package store

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/google/uuid"
)

// The defects the in-memory store is structurally incapable of having.
//
// Everything in conformance_test.go runs against both implementations, because
// the interesting failures there were the two disagreeing. These two classes
// are different: they are properties of PostgreSQL itself, and the in-memory
// store cannot exhibit them even in principle.
//
//	D. A bound parameter PostgreSQL types differently from the driver.
//	E. A NULL column scanned into a non-pointer Go field.
//
// Both have shipped. Both were found by a person running the thing.

func postgresOnly(t *testing.T) *PostgresStore {
	t.Helper()
	url := os.Getenv("CERTPILOT_TEST_DB_URL")
	if url == "" {
		t.Skip("set CERTPILOT_TEST_DB_URL to exercise PostgreSQL")
	}
	store, ok := freshPostgres(t, url).(*PostgresStore)
	if !ok {
		t.Fatal("expected a PostgresStore")
	}
	return store
}

// TestQueriesWithBoundIntervalsRun — class D.
//
// Two of these have shipped. The CA expiry window was
// `not_after <= now() + ($1 || ' days')`, which leaves both sides of `||`
// untyped: PostgreSQL resolved it as `text || text` and reported the parameter
// as text while the driver held an int. Migration 018's staleness sweep was
// `$1 - <interval>`, where an untyped `$1` is inferred as an *interval* rather
// than a timestamp — and the identical predicate with a literal `now()` worked,
// which is why it survived to runtime.
//
// Neither is expressible in Go. There is no inference to get wrong, so the
// in-memory store runs the same logic correctly for ever while the database
// refuses the query. The only test that finds this class is one that runs the
// query.
func TestQueriesWithBoundIntervalsRun(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	t.Run("the CA expiry window", func(t *testing.T) {
		for _, days := range []int{1, 30, 365} {
			if _, err := store.ListCAAuthorities(ctx, CAFilter{ExpiringWithinDays: days}); err != nil {
				t.Fatalf("the CA expiry window with %d days did not run: %v", days, err)
			}
		}
	})

	t.Run("the agent staleness sweep", func(t *testing.T) {
		// The predicate that was inferred as an interval. Bound `now`, not a
		// literal — binding it is the whole of what broke.
		if _, err := store.GetStaleAgents(ctx, time.Now(), 50); err != nil {
			t.Fatalf("the staleness sweep did not run: %v", err)
		}
	})

	t.Run("the renewal sweep", func(t *testing.T) {
		if _, err := store.GetCertificatesDueForRenewal(ctx, 30); err != nil {
			t.Fatalf("the renewal sweep did not run: %v", err)
		}
	})
}

// TestOneNullColumnDoesNotBlankAWholeList — class E.
//
// Several nullable columns scan into non-pointer Go fields, and pgx fails the
// *whole query* rather than the row. One hand-inserted certificate with a null
// `key_size` would have blanked the certificate list for everybody — a single
// bad row taking out a page, which is a failure mode no amount of testing
// against a store that has no NULL will produce.
//
// Inserted with raw SQL on purpose. Going through CreateCertificate would write
// whatever the Go zero value is and prove nothing; the row that causes this
// arrives from a bulk import, a migration, or somebody's psql session.
func TestOneNullColumnDoesNotBlankAWholeList(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	healthy := sampleCertificate("healthy-neighbour")
	if err := store.CreateCertificate(ctx, healthy); err != nil {
		t.Fatal(err)
	}

	// Everything nullable, left null. This is the row somebody's import script
	// writes.
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO public.certificates (fingerprint_sha256, common_name, status)
		VALUES ('null-heavy-row', 'imported.example.com', 'ISSUED')`); err != nil {
		t.Fatalf("could not insert a sparse row: %v", err)
	}

	certs, total, err := store.ListCertificates(ctx, CertificateFilter{Limit: 100})
	if err != nil {
		t.Fatalf("one row with null columns took out the whole certificate list: %v", err)
	}
	if total < 2 {
		t.Fatalf("expected both certificates, got %d", total)
	}

	var found bool
	for _, cert := range certs {
		if cert.CommonName == "imported.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("the sparse row is missing from the list; it should be readable, not skipped")
	}

	// And it is readable on its own, which is what a detail page does.
	sparse, err := store.GetCertificateByFingerprint(ctx, "null-heavy-row")
	if err != nil {
		t.Fatalf("the sparse row could not be read individually: %v", err)
	}
	if sparse == nil {
		t.Fatal("the sparse row was not found by fingerprint")
	}
}

// TestTheMigrationsApplyTwice.
//
// Migration 001 had to be made rerunnable because `create policy` has no
// `if not exists`: applying the file to a database that already had the schema
// failed on the first policy and rolled everything back. Every migration since
// has been written to be idempotent, and nothing has ever checked that they
// still are.
//
// The migrator's own checksumming means a second `Migrate` skips them, so this
// re-applies the files directly — which is what happens when somebody runs the
// SQL by hand against a database that is already migrated, and it is exactly
// the situation migration 001's note was written about.
func TestTheMigrationsApplyTwice(t *testing.T) {
	store := postgresOnly(t)
	ctx := context.Background()

	dir := repoPath(t, "migrations")
	migrations, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("could not read the migrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("no migrations were found")
	}

	for _, migration := range migrations {
		if _, err := store.pool.Exec(ctx, migration.SQL); err != nil {
			t.Errorf("%s is not idempotent; applying it to a migrated database failed: %v",
				migration.Name, err)
		}
	}
}

// ── The audit chain against real PostgreSQL ─────────────

func chainedPostgres(t *testing.T) *PostgresStore {
	t.Helper()
	s := postgresOnly(t)
	kr, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	s.UseAuditChain(NewAuditChainer(kr))
	return s
}

// The whole chain rests on the row reading back exactly as it was signed.
//
// This is class D and E territory and the in-memory store cannot fail it:
// timestamptz truncates to microseconds, `details` is written through a
// *string, and `ip_address` is an inet read back through host(). Any of the
// three coming back a byte different from what the tag covered would make every
// entry read as tampered — and it would happen only against a real database.
func TestAuditChainSurvivesTheRoundTrip(t *testing.T) {
	s := chainedPostgres(t)
	ctx := context.Background()

	ip := "203.0.113.7"
	actor := "00uOKTAsubject001"
	email := "operator@example.test"
	for i := 0; i < 5; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{
			Action:     "certificate.revoked",
			EntityType: "certificate",
			ActorID:    &actor,
			ActorEmail: &email,
			// Several keys on purpose: jsonb would have reordered them, which is
			// why this column is text.
			Details:   `{"reason":"keyCompromise","serial":"0a1b2c","by":"me"}`,
			IPAddress: &ip,
		}); err != nil {
			t.Fatalf("CreateAuditLog: %v", err)
		}
	}

	report, err := s.VerifyAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !report.Intact {
		t.Fatalf("a chain written and read back by PostgreSQL must verify: %s", report.Reason)
	}
	if report.Verified != 5 {
		t.Errorf("expected 5 verified entries, got %d", report.Verified)
	}
}

// No leader election: any replica can write an audit entry, and two doing it at
// the same instant is ordinary. Without the advisory lock they read the same
// head and chain from it — one insert loses the unique index and the entry is
// gone, which is a worse failure than the one the chain was added to detect.
//
// A single pool with concurrent goroutines is the same race: each Begin takes
// its own connection.
func TestAuditChainIsSafeUnderConcurrentWrites(t *testing.T) {
	s := chainedPostgres(t)
	ctx := context.Background()

	const writers = 12
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			errs <- s.CreateAuditLog(ctx, &AuditLog{
				Action:     "certificate.issued",
				EntityType: "certificate",
				Details:    `{"writer":` + strconv.Itoa(n) + `}`,
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent audit write failed: %v", err)
		}
	}

	report, err := s.VerifyAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Fatalf("concurrent writers forked the chain: %s", report.Reason)
	}
	if report.Verified != writers {
		t.Errorf("expected %d entries, got %d — an entry was lost to the race",
			writers, report.Verified)
	}
}

// The table has claimed to be immutable since 001 and enforced nothing. The
// trigger is not a security boundary — anyone who can drop it can drop it — but
// it is what stops a mistyped UPDATE silently destroying the record.
func TestAuditLogRefusesUpdatesAndDeletes(t *testing.T) {
	s := chainedPostgres(t)
	ctx := context.Background()

	if err := s.CreateAuditLog(ctx, &AuditLog{Action: "ca.checked", EntityType: "ca_authority"}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.pool.Exec(ctx, "UPDATE public.audit_logs SET action = 'rewritten'"); err == nil {
		t.Error("an UPDATE against audit_logs must be refused")
	}
	if _, err := s.pool.Exec(ctx, "DELETE FROM public.audit_logs"); err == nil {
		t.Error("a DELETE against audit_logs must be refused")
	}

	report, err := s.VerifyAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Errorf("the refused statements must have left the record untouched: %s", report.Reason)
	}
}

// Retention is the one legitimate deletion. It has a documented door rather
// than teaching operators to drop the trigger — and going through it must still
// leave the gap visible, because a pruned chain is not an intact one.
func TestAuditPruningIsPossibleAndStillVisible(t *testing.T) {
	s := chainedPostgres(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{Action: "ca.checked", EntityType: "ca_authority"}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.pool.Exec(ctx, `
		BEGIN;
		SET LOCAL certpilot.audit_maintenance = 'on';
		DELETE FROM public.audit_logs WHERE seq = 2;
		COMMIT;`); err != nil {
		t.Fatalf("the documented retention path must work: %v", err)
	}

	report, err := s.VerifyAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("a pruned entry must leave the chain reading as broken, not intact")
	}
	if report.BrokenAt == nil || *report.BrokenAt != 2 {
		t.Fatalf("expected the gap reported at seq 2, got %v", report.BrokenAt)
	}
}

// The tag is keyed by a subkey of CERTPILOT_KEK, which lives in the core's
// environment and never in the database. Somebody holding only the database can
// rewrite a row — the trigger is theirs to drop — but cannot produce a tag that
// agrees with it. This is the property that distinguishes the design from a
// plain SHA-256 chain, so it is worth proving against real SQL rather than
// asserting in a comment.
func TestAuditChainDetectsTamperingDoneInSQL(t *testing.T) {
	s := chainedPostgres(t)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if err := s.CreateAuditLog(ctx, &AuditLog{
			Action: "certificate.revoked", EntityType: "certificate",
			Details: `{"reason":"keyCompromise"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Exactly what an attacker with database access would do: drop the guard,
	// edit the row, put the guard back.
	if _, err := s.pool.Exec(ctx, `
		ALTER TABLE public.audit_logs DISABLE TRIGGER trg_audit_logs_append_only;
		UPDATE public.audit_logs SET details = '{"reason":"superseded"}' WHERE seq = 3;
		ALTER TABLE public.audit_logs ENABLE TRIGGER trg_audit_logs_append_only;`); err != nil {
		t.Fatal(err)
	}

	report, err := s.VerifyAuditChain(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("an entry rewritten in SQL must not verify")
	}
	if report.BrokenAt == nil || *report.BrokenAt != 3 {
		t.Fatalf("expected the break at seq 3, got %v", report.BrokenAt)
	}
}

// TestAnIdThatIsNotAUuidReadsAsNotFound — class D from the other side.
//
// `id` reaches these lookups from a URL path, so it can be any text at all. A
// value PostgreSQL cannot read as a uuid comes back as SQLSTATE 22P02 rather
// than as zero rows, and that error used to be returned verbatim: an operator
// who mistyped a certificate id was shown
// `invalid input syntax for type uuid: "nope" (SQLSTATE 22P02)`, which reads as
// the database being broken rather than the request being wrong about which
// certificate it meant. It reached the revoke endpoint, of all of them.
//
// The in-memory store cannot have this. `m.certificates[id]` is a map miss for
// any string, so it answered correctly for ever while PostgreSQL did not —
// which is why this belongs here and not in the conformance suite.
func TestAnIdThatIsNotAUuidReadsAsNotFound(t *testing.T) {
	s := postgresOnly(t)
	ctx := context.Background()

	for _, id := range []string{
		"nope",
		"",
		"not-a-uuid-at-all",
		// A uuid with one character too many: the shape is right and the value
		// is still unreadable, which is the case a length check would miss.
		"3f2504e0-4f89-11d3-9a0c-0305e82c33011",
	} {
		cert, err := s.GetCertificate(ctx, id)
		if err == nil {
			t.Fatalf("GetCertificate(%q) returned no error and %v", id, cert)
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("GetCertificate(%q) said %q, want a not-found error", id, err)
		}
		if strings.Contains(err.Error(), "SQLSTATE") {
			t.Errorf("GetCertificate(%q) leaked the driver's error: %q", id, err)
		}

		acc, err := s.GetCAAccount(ctx, id)
		if err == nil {
			t.Fatalf("GetCAAccount(%q) returned no error and %v", id, acc)
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("GetCAAccount(%q) said %q, want a not-found error", id, err)
		}
		if strings.Contains(err.Error(), "SQLSTATE") {
			t.Errorf("GetCAAccount(%q) leaked the driver's error: %q", id, err)
		}
	}

	// A well-formed uuid that names nothing must still say the same thing, or
	// the fix above has only moved the inconsistency.
	if _, err := s.GetCertificate(ctx, uuid.NewString()); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Errorf("an absent but well-formed id said %v, want a not-found error", err)
	}
}
