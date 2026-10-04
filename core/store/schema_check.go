package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5/pgconn"
)

// RequiredSchemaVersion is the newest migration this core's code depends on.
// TestTheRequiredSchemaIsTheNewestMigration fails when a migration is added
// without raising it.
const RequiredSchemaVersion = "043"

// CheckSchema refuses a database whose schema is older than this core needs.
//
// The server never migrates itself, which is right, but nothing used to check
// that somebody had. Started before `--migrate`, a v0.2.1 core reported itself
// healthy against a v0.1.1 schema while its renewal sweep logged "nothing is
// being renewed", listing certificates answered 500 and fetching one answered
// 404. An orchestrator sends traffic to a healthy core, so the outage was
// visible only in a log.
//
// A newer schema is accepted. Migrations are additive, so rolling the binary
// back onto a schema a later release migrated is how a bad upgrade is undone,
// and an older core reads the columns it knows about.
func (s *PostgresStore) CheckSchema(ctx context.Context) error {
	var newest *string
	err := s.pool.QueryRow(ctx, "SELECT max(version) FROM public.schema_migrations").Scan(&newest)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // undefined_table
		return fmt.Errorf("this database has never been migrated, and this core needs its schema at migration %s. "+
			"Run the migrations first: certpilot-core --migrate, make migrate, or the compose file's migrate job",
			RequiredSchemaVersion)
	}
	if err != nil {
		return fmt.Errorf("reading which migrations this database has: %w", err)
	}

	if newest == nil || schemaNumber(*newest) < schemaNumber(RequiredSchemaVersion) {
		at := "no migration"
		if newest != nil {
			at = "migration " + *newest
		}
		return fmt.Errorf("this database's schema is at %s, and this core needs migration %s. "+
			"Run the migrations before starting it: certpilot-core --migrate, make migrate, or the compose "+
			"file's migrate job. Started on the older schema it would report itself healthy and renew nothing",
			at, RequiredSchemaVersion)
	}
	return nil
}

// schemaNumber reads a migration version as a number. Versions are
// zero-padded, so text order agrees today, but a fourth digit would not.
func schemaNumber(version string) int {
	n, err := strconv.Atoi(version)
	if err != nil {
		return -1
	}
	return n
}
