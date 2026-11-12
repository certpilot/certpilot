package server

import (
	"context"
	"fmt"
	"os"

	"github.com/certpilot/certpilot/core/engine/rekey"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
)

// Reseal backs `certpilot-core --reseal`: it moves everything a retired key
// seals onto the primary key, and returns what it did with a report of what
// depends on each key afterwards.
//
// It opens the database the way the server does, including the check that this
// core holds the key the database was sealed with, and starts nothing else. A
// running core is not disturbed: see rekey.Reseal.
func Reseal(ctx context.Context, cfg *config.CoreConfig, dbConnStr string) (*rekey.Result, *rekey.Report, error) {
	if dbConnStr == "" {
		return nil, nil, fmt.Errorf("no database configured; pass --db or set CERTPILOT_DB_URL. " +
			"There is nothing to re-seal in the in-memory store")
	}
	st, err := store.NewPostgresStore(ctx, dbConnStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to the database: %w", err)
	}
	defer st.Close()
	if err := st.CheckSchema(ctx); err != nil {
		return nil, nil, err
	}

	kr, err := loadKeyring(ctx, cfg.Secrets, false)
	if err != nil {
		return nil, nil, err
	}
	// The re-seal writes an audit entry, so it is chained and guarded exactly
	// as the server's entries are.
	st.UseAuditChain(store.NewAuditChainer(kr))
	if err := guardAuditKey(ctx, st, kr, os.Getenv(abandonKeyEnv)); err != nil {
		return nil, nil, err
	}

	result, err := rekey.Reseal(ctx, st, kr)
	if err != nil {
		return result, nil, err
	}
	report, err := rekey.Survey(ctx, st, kr)
	return result, report, err
}
