package store

import (
	"context"
	"strings"
	"testing"
)

// TestTheRequiredSchemaIsTheNewestMigration keeps RequiredSchemaVersion honest.
// A migration added without raising it would let a core start on a database
// that lacks the very columns the new code reads.
func TestTheRequiredSchemaIsTheNewestMigration(t *testing.T) {
	migrations, err := LoadMigrations(repoPath(t, "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	newest := migrations[len(migrations)-1].Version
	if newest != RequiredSchemaVersion {
		t.Fatalf("the newest migration is %s and RequiredSchemaVersion is %s; raise it with the migration", newest, RequiredSchemaVersion)
	}
}

// TestACoreRefusesASchemaOlderThanItNeeds.
//
// Started before `--migrate`, a v0.2.1 core reported itself healthy against a
// v0.1.1 schema. The renewal sweep logged "nothing is being renewed", listing
// certificates answered 500, and fetching one that existed answered 404. An
// orchestrator routes traffic to a healthy core, so nothing outside the log
// said that the one job this system has was not being done.
func TestACoreRefusesASchemaOlderThanItNeeds(t *testing.T) {
	s := postgresOnly(t)
	ctx := context.Background()

	if err := s.CheckSchema(ctx); err != nil {
		t.Fatalf("a fully migrated database was refused: %v", err)
	}

	if _, err := s.pool.Exec(ctx, "DELETE FROM public.schema_migrations WHERE version = $1", RequiredSchemaVersion); err != nil {
		t.Fatal(err)
	}
	err := s.CheckSchema(ctx)
	if err == nil {
		t.Fatal("a database missing the newest migration was accepted")
	}
	for _, want := range []string{RequiredSchemaVersion, "--migrate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// TestACoreStartsOnANewerSchema is a rollback of the binary: migrations are
// additive, so an older core on a newer schema reads what it knows about.
// Measured with v0.1.1 on v0.2.1's schema: listing, reading and the audit
// check all worked. Refusing it would turn a working rollback into an outage.
func TestACoreStartsOnANewerSchema(t *testing.T) {
	s := postgresOnly(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx,
		"INSERT INTO public.schema_migrations (version, name, checksum) VALUES ('999', '999_from_a_newer_release.sql', 'x')"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchema(ctx); err != nil {
		t.Fatalf("a newer schema was refused: %v", err)
	}
}

// TestACoreRefusesADatabaseThatWasNeverMigrated: an empty database is the
// same mistake made earlier, and says so rather than failing on the first
// query that touches a table.
func TestACoreRefusesADatabaseThatWasNeverMigrated(t *testing.T) {
	s := postgresOnly(t)
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "DROP TABLE public.schema_migrations"); err != nil {
		t.Fatal(err)
	}
	err := s.CheckSchema(ctx)
	if err == nil {
		t.Fatal("a database with no migration record was accepted")
	}
	if !strings.Contains(err.Error(), "--migrate") {
		t.Errorf("the refusal does not say how to migrate:\n%v", err)
	}
}
