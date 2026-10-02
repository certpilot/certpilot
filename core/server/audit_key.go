package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// abandonKeyEnv names the one key a core may start without. See guardAuditKey.
const abandonKeyEnv = "CERTPILOT_KEK_ABANDON"

// guardAuditKey refuses to start on a database sealed with a key this core was
// not given.
//
// The newest audit entry names the key that signed it, which makes it the
// cheapest reliable answer to "which key was this database sealed with": one
// indexed row, present on any database that has done anything. Restored with
// the wrong CERTPILOT_KEK, the core used to start as if nothing were wrong.
// Nothing sealed could be read, which was at least loud, but the first sign-in
// wrote an audit entry signed with the wrong key, and once the right key was
// back that entry could never be checked. The chain then reported itself broken
// for ever over a mistake nobody made on purpose. Refusing here, before
// anything is written, leaves the database exactly as it was restored.
//
// The key can also be lost for good, and then everything it sealed is gone
// whatever the core does. Refusing for ever would only stop the operator
// reissuing what can be reissued, so abandon, when it names exactly the key the
// database was sealed with, lets the core start, and the audit log records that
// the key was given up and by which key the chain continues.
func guardAuditKey(ctx context.Context, st store.Store, kr *secrets.Keyring, abandon string) error {
	seq, sealedBy, err := st.LatestAuditKey(ctx)
	if err != nil {
		return fmt.Errorf("reading the audit log to check the key encryption key: %w", err)
	}
	if sealedBy == "" || kr.Knows(sealedBy) {
		return nil
	}

	if strings.EqualFold(strings.TrimSpace(abandon), sealedBy) {
		slog.Warn("starting without the key this database was sealed with, because "+abandonKeyEnv+" names it. "+
			"Nothing it sealed can be read, and audit entries signed with it can no longer be checked",
			"abandoned_key_id", sealedBy, "key_id", kr.PrimaryKeyID())
		details, _ := json.Marshal(map[string]any{
			"abandoned_key_id":        sealedBy,
			"last_seq_signed_with_it": seq,
			"key_id":                  kr.PrimaryKeyID(),
		})
		if err := st.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "secrets.kek_abandoned",
			EntityType: "secrets",
			Details:    string(details),
		}); err != nil {
			return fmt.Errorf("recording that key %s was abandoned: %w", sealedBy, err)
		}
		return nil
	}

	return fmt.Errorf("this database was sealed with key encryption key %s, which signed its newest audit entry (%d), "+
		"and this core was given %s. Most likely the database was restored with the wrong CERTPILOT_KEK. "+
		"Starting would sign new audit entries with a key the existing chain cannot be checked against, "+
		"and nothing already sealed could be read. Set CERTPILOT_KEK to the key this database was sealed with, "+
		"or keep that key in CERTPILOT_KEK_RETIRED after a rotation. If it is lost for good, everything it sealed "+
		"is lost with it; to start anyway and reissue what can be reissued, set %s=%s once",
		sealedBy, seq, describeKeys(kr), abandonKeyEnv, sealedBy)
}

func describeKeys(kr *secrets.Keyring) string {
	ids := kr.KeyIDs()
	if len(ids) == 1 {
		return "key " + ids[0]
	}
	return "keys " + strings.Join(ids, ", ")
}
