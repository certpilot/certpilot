package store

import (
	"context"
	"fmt"
	"sort"

	"github.com/certpilot/certpilot/pkg/secrets"
)

// The kinds of record that hold a value sealed under the key encryption key.
const (
	SealedCAAccount           = "ca_account"
	SealedCertificate         = "certificate"
	SealedDeploymentTarget    = "deployment_target"
	SealedNotificationChannel = "notification_channel"
	SealedCloudConnection     = "cloud_connection"
	SealedACMECredential      = "acme_credential"
)

// SealedKind is one kind of record with a sealed value, and the context that
// value was sealed under.
type SealedKind struct {
	Name    string
	Context string
	// table and column are where PostgreSQL keeps it.
	table, column string
}

// SealedKinds is every sealed column there is. Re-sealing and the report of
// what depends on each key both walk this list and nothing else, so a sealed
// column missing from it is one that silently stays under a retired key.
var SealedKinds = []SealedKind{
	{SealedCAAccount, secrets.ContextCAAccountConfig, "ca_accounts", "config_encrypted"},
	{SealedCertificate, secrets.ContextCertificatePrivKey, "certificates", "private_key_encrypted"},
	{SealedDeploymentTarget, secrets.ContextDeploymentConfig, "deployment_targets", "config_encrypted"},
	{SealedNotificationChannel, secrets.ContextNotificationConfig, "notification_channels", "config_encrypted"},
	{SealedCloudConnection, secrets.ContextCloudConnectionConfig, "cloud_connections", "config_encrypted"},
	{SealedACMECredential, secrets.ContextACMEEABKey, "acme_eab_credentials", "hmac_key_sealed"},
}

func sealedKind(name string) (SealedKind, error) {
	for _, k := range SealedKinds {
		if k.Name == name {
			return k, nil
		}
	}
	return SealedKind{}, fmt.Errorf("%q is not a kind of sealed record", name)
}

// SealedValue is one record's sealed value, as stored.
type SealedValue struct {
	ID    string
	Value string
}

// AuditKeyUsage is how much of the audit chain one key signed.
type AuditKeyUsage struct {
	KeyID    string `json:"key_id"`
	Entries  int64  `json:"entries"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
}

// ── PostgreSQL ──────────────────────────────────────────

// ListSealed returns up to limit records of one kind that hold a sealed value,
// in id order, starting after the given id.
func (s *PostgresStore) ListSealed(ctx context.Context, kind, after string, limit int) ([]SealedValue, error) {
	k, err := sealedKind(kind)
	if err != nil {
		return nil, err
	}
	// Table and column come from SealedKinds, never from a caller.
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT id::text, %[2]s
		FROM public.%[1]s
		WHERE %[2]s IS NOT NULL AND %[2]s <> ''
		  AND ($1 = '' OR id > $1::uuid)
		ORDER BY id
		LIMIT $2`, k.table, k.column), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SealedValue{}
	for rows.Next() {
		var v SealedValue
		if err := rows.Scan(&v.ID, &v.Value); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SwapSealed replaces a record's sealed value with next, but only if it still
// holds old. It reports whether it did.
func (s *PostgresStore) SwapSealed(ctx context.Context, kind, id, old, next string) (bool, error) {
	k, err := sealedKind(kind)
	if err != nil {
		return false, err
	}
	tag, err := s.pool.Exec(ctx, fmt.Sprintf(`
		UPDATE public.%[1]s SET %[2]s = $3
		WHERE id = $1::uuid AND %[2]s = $2`, k.table, k.column), id, old, next)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// AuditKeyUsage reports, for each key that signed audit entries, how many and
// over which sequence numbers, oldest first.
func (s *PostgresStore) AuditKeyUsage(ctx context.Context) ([]AuditKeyUsage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT chain_key_id, count(*), min(seq), max(seq)
		FROM public.audit_logs
		WHERE seq IS NOT NULL AND coalesce(chain_key_id, '') <> ''
		GROUP BY chain_key_id
		ORDER BY min(seq)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditKeyUsage{}
	for rows.Next() {
		var u AuditKeyUsage
		if err := rows.Scan(&u.KeyID, &u.Entries, &u.FirstSeq, &u.LastSeq); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ── In memory ───────────────────────────────────────────

// sealedSlots returns a pointer to each record's sealed value for one kind.
// The caller holds the lock.
func (m *MemoryStore) sealedSlots(kind string) (map[string]*string, error) {
	if _, err := sealedKind(kind); err != nil {
		return nil, err
	}
	out := map[string]*string{}
	switch kind {
	case SealedCAAccount:
		for id, r := range m.caAccounts {
			out[id] = &r.ConfigEncrypted
		}
	case SealedCertificate:
		for id, r := range m.certificates {
			if r.PrivateKeyEncrypted != nil {
				out[id] = r.PrivateKeyEncrypted
			}
		}
	case SealedDeploymentTarget:
		for id, r := range m.targets {
			out[id] = &r.ConfigEncrypted
		}
	case SealedNotificationChannel:
		for id, r := range m.notifChannels {
			out[id] = &r.ConfigEncrypted
		}
	case SealedCloudConnection:
		for id, r := range m.cloudConnections {
			out[id] = &r.ConfigEncrypted
		}
	case SealedACMECredential:
		for id, r := range m.acmeCredentials {
			out[id] = &r.HMACKeySealed
		}
	}
	return out, nil
}

func (m *MemoryStore) ListSealed(ctx context.Context, kind, after string, limit int) ([]SealedValue, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	slots, err := m.sealedSlots(kind)
	if err != nil {
		return nil, err
	}
	out := []SealedValue{}
	for id, v := range slots {
		if *v != "" && id > after {
			out = append(out, SealedValue{ID: id, Value: *v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) SwapSealed(ctx context.Context, kind, id, old, next string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	slots, err := m.sealedSlots(kind)
	if err != nil {
		return false, err
	}
	v, ok := slots[id]
	if !ok || *v != old {
		return false, nil
	}
	*v = next
	return true, nil
}

func (m *MemoryStore) AuditKeyUsage(ctx context.Context) ([]AuditKeyUsage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byKey := map[string]*AuditKeyUsage{}
	for _, l := range m.auditLogs {
		if l.Seq == 0 || l.ChainKeyID == "" {
			continue
		}
		u, ok := byKey[l.ChainKeyID]
		if !ok {
			u = &AuditKeyUsage{KeyID: l.ChainKeyID, FirstSeq: l.Seq, LastSeq: l.Seq}
			byKey[l.ChainKeyID] = u
		}
		u.Entries++
		u.FirstSeq = min(u.FirstSeq, l.Seq)
		u.LastSeq = max(u.LastSeq, l.Seq)
	}
	out := make([]AuditKeyUsage, 0, len(byKey))
	for _, u := range byKey {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeq < out[j].FirstSeq })
	return out, nil
}
