package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The account a credential made is read alongside it, so "has this credential
// been used" is one query rather than a second one that can disagree.
const acmeCredentialColumns = `c.id, c.kid, c.name, c.template_id, c.hmac_key_sealed,
		(SELECT a.id FROM public.acme_accounts a WHERE a.eab_id = c.id),
		c.created_by, c.created_at, c.revoked_at, c.revoked_by`

const acmeAccountColumns = `id, template_id, eab_id, jwk_thumbprint, jwk, status, contacts, created_at, updated_at`

func scanACMECredential(row pgx.Row) (*ACMEEABCredential, error) {
	c := &ACMEEABCredential{}
	err := row.Scan(&c.ID, &c.KID, &c.Name, &c.TemplateID, &c.HMACKeySealed, &c.AccountID,
		&c.CreatedBy, &c.CreatedAt, &c.RevokedAt, &c.RevokedBy)
	return c, err
}

func scanACMEAccount(row pgx.Row) (*ACMEAccount, error) {
	a := &ACMEAccount{}
	var contacts []byte
	if err := row.Scan(&a.ID, &a.TemplateID, &a.EABID, &a.JWKThumbprint, &a.JWK, &a.Status,
		&contacts, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(contacts, &a.Contacts); err != nil {
		return nil, fmt.Errorf("store: could not read an ACME account's contacts: %w", err)
	}
	return a, nil
}

func (s *PostgresStore) CreateACMEEABCredential(ctx context.Context, c *ACMEEABCredential) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.acme_eab_credentials (kid, name, template_id, hmac_key_sealed, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`,
		c.KID, c.Name, c.TemplateID, c.HMACKeySealed, c.CreatedBy,
	).Scan(&c.ID, &c.CreatedAt)
}

func (s *PostgresStore) ListACMEEABCredentials(ctx context.Context) ([]*ACMEEABCredential, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+acmeCredentialColumns+" FROM public.acme_eab_credentials c ORDER BY c.created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ACMEEABCredential{}
	for rows.Next() {
		c, err := scanACMECredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetACMEEABCredentialByKID(ctx context.Context, kid string) (*ACMEEABCredential, error) {
	c, err := scanACMECredential(s.pool.QueryRow(ctx,
		"SELECT "+acmeCredentialColumns+" FROM public.acme_eab_credentials c WHERE c.kid = $1", kid))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func (s *PostgresStore) RevokeACMEEABCredential(ctx context.Context, id string, revokedBy *string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.acme_eab_credentials
		SET revoked_at = COALESCE(revoked_at, now()), revoked_by = COALESCE(revoked_by, $2)
		WHERE id = $1`, id, revokedBy)
	if noSuchRow(err) || (err == nil && tag.RowsAffected() == 0) {
		return fmt.Errorf("ACME credential %s %w", id, ErrNotFound)
	}
	return err
}

func (s *PostgresStore) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	contacts, err := json.Marshal(nonNilStrings(a.Contacts))
	if err != nil {
		return err
	}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO public.acme_accounts (template_id, eab_id, jwk_thumbprint, jwk, contacts)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, status, created_at, updated_at`,
		a.TemplateID, a.EABID, a.JWKThumbprint, a.JWK, contacts,
	).Scan(&a.ID, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if isUniqueViolation(err) {
		return fmt.Errorf("an ACME account already exists for this credential or key: %w", ErrConflict)
	}
	return err
}

func (s *PostgresStore) GetACMEAccount(ctx context.Context, id string) (*ACMEAccount, error) {
	a, err := scanACMEAccount(s.pool.QueryRow(ctx,
		"SELECT "+acmeAccountColumns+" FROM public.acme_accounts WHERE id = $1", id))
	if noSuchRow(err) {
		return nil, fmt.Errorf("ACME account %s %w", id, ErrNotFound)
	}
	return a, err
}

func (s *PostgresStore) GetACMEAccountByThumbprint(ctx context.Context, templateID, thumbprint string) (*ACMEAccount, error) {
	a, err := scanACMEAccount(s.pool.QueryRow(ctx,
		"SELECT "+acmeAccountColumns+" FROM public.acme_accounts WHERE template_id = $1 AND jwk_thumbprint = $2",
		templateID, thumbprint))
	if noSuchRow(err) {
		return nil, nil
	}
	return a, err
}

func (s *PostgresStore) GetACMEAccountByEAB(ctx context.Context, eabID string) (*ACMEAccount, error) {
	a, err := scanACMEAccount(s.pool.QueryRow(ctx,
		"SELECT "+acmeAccountColumns+" FROM public.acme_accounts WHERE eab_id = $1", eabID))
	if noSuchRow(err) {
		return nil, nil
	}
	return a, err
}

func (s *PostgresStore) UpdateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	contacts, err := json.Marshal(nonNilStrings(a.Contacts))
	if err != nil {
		return err
	}
	err = s.pool.QueryRow(ctx, `
		UPDATE public.acme_accounts SET status = $2, contacts = $3, updated_at = now()
		WHERE id = $1 RETURNING updated_at`, a.ID, a.Status, contacts).Scan(&a.UpdatedAt)
	if noSuchRow(err) {
		return fmt.Errorf("ACME account %s %w", a.ID, ErrNotFound)
	}
	return err
}

func (s *PostgresStore) UpdateACMEAccountKey(ctx context.Context, id, jwk, thumbprint string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.acme_accounts SET jwk = $2, jwk_thumbprint = $3, updated_at = now()
		WHERE id = $1`, id, jwk, thumbprint)
	if isUniqueViolation(err) {
		return fmt.Errorf("another ACME account on this template already has that key: %w", ErrConflict)
	}
	if noSuchRow(err) || (err == nil && tag.RowsAffected() == 0) {
		return fmt.Errorf("ACME account %s %w", id, ErrNotFound)
	}
	return err
}

func (s *PostgresStore) ClaimACMENonce(ctx context.Context, hash []byte, expiresAt time.Time) (bool, error) {
	// ON CONFLICT DO NOTHING rather than a SELECT then an INSERT: the same nonce
	// can arrive at two replicas in the same millisecond, and only the primary
	// key can say which was first.
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO public.acme_used_nonces (nonce_hash, expires_at) VALUES ($1, $2)
		ON CONFLICT (nonce_hash) DO NOTHING`, hash, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) SweepACMENonces(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM public.acme_used_nonces WHERE expires_at <= $1", now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

const acmeOrderColumns = `id, account_id, status, identifiers, expires_at, certificate_id, coalesce(error, ''), created_at, updated_at`

func scanACMEOrder(row pgx.Row) (*ACMEOrder, error) {
	o := &ACMEOrder{}
	var identifiers []byte
	if err := row.Scan(&o.ID, &o.AccountID, &o.Status, &identifiers, &o.ExpiresAt, &o.CertificateID,
		&o.Error, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(identifiers, &o.Identifiers); err != nil {
		return nil, fmt.Errorf("store: could not read an ACME order's identifiers: %w", err)
	}
	return o, nil
}

func (s *PostgresStore) CreateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	identifiers, err := json.Marshal(o.Identifiers)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.acme_orders (account_id, status, identifiers, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`,
		o.AccountID, o.Status, identifiers, o.ExpiresAt,
	).Scan(&o.ID, &o.CreatedAt, &o.UpdatedAt)
}

func (s *PostgresStore) GetACMEOrder(ctx context.Context, id string) (*ACMEOrder, error) {
	o, err := scanACMEOrder(s.pool.QueryRow(ctx,
		"SELECT "+acmeOrderColumns+" FROM public.acme_orders WHERE id = $1", id))
	if noSuchRow(err) {
		return nil, fmt.Errorf("ACME order %s %w", id, ErrNotFound)
	}
	return o, err
}

func (s *PostgresStore) GetACMEOrderByCertificate(ctx context.Context, certificateID string) (*ACMEOrder, error) {
	o, err := scanACMEOrder(s.pool.QueryRow(ctx,
		"SELECT "+acmeOrderColumns+" FROM public.acme_orders WHERE certificate_id = $1 LIMIT 1", certificateID))
	if noSuchRow(err) {
		return nil, nil
	}
	return o, err
}

func (s *PostgresStore) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]*ACMEOrder, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+acmeOrderColumns+" FROM public.acme_orders WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1000",
		accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ACMEOrder{}
	for rows.Next() {
		o, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ClaimACMEOrderForFinalize(ctx context.Context, id string) (bool, error) {
	// The state check is in the WHERE clause, so two replicas finalising the
	// same order cannot both see it ready.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.acme_orders SET status = 'processing', updated_at = now()
		WHERE id = $1 AND status = 'ready' AND expires_at > now()`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) UpdateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	var problem *string
	if o.Error != "" {
		problem = &o.Error
	}
	err := s.pool.QueryRow(ctx, `
		UPDATE public.acme_orders SET status = $2, certificate_id = $3, error = $4, updated_at = now()
		WHERE id = $1 RETURNING updated_at`, o.ID, o.Status, o.CertificateID, problem).Scan(&o.UpdatedAt)
	if noSuchRow(err) {
		return fmt.Errorf("ACME order %s %w", o.ID, ErrNotFound)
	}
	return err
}
