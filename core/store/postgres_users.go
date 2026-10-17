package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// userColumns is the projection every user read shares, so that a column added
// in one place cannot be forgotten in another.
const userColumns = `id, issuer, subject, COALESCE(email, ''), COALESCE(display_name, ''),
	role, status, role_source, COALESCE(must_change_password, false),
	last_seen_at, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	var lastSeen *time.Time
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName,
		&u.Role, &u.Status, &u.RoleSource, &u.MustChangePassword,
		&lastSeen, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.LastSeenAt = lastSeen
	return u, nil
}

// ResolveUser returns the stored user for an authenticated subject, creating
// the row on first sign-in.
//
// Read first, write only when something actually differs. This runs on every
// authenticated request, so an unconditional upsert would set updated_at on
// each one and leave a dead row version behind — a steady write load and
// autovacuum churn on the single table every request already touches, caused
// entirely by people looking at a dashboard.
//
// Nothing here writes role on an existing user. A sign-in must not be able to
// change one: if it could, a provider that began emitting a different email
// address would re-trigger the bootstrap grant below against an account
// somebody had deliberately demoted.
func (s *PostgresStore) ResolveUser(ctx context.Context, identity UserIdentity, bootstrapAdmins []string) (*User, error) {
	if identity.Issuer == "" || identity.Subject == "" {
		return nil, errors.New("store: a user needs both an issuer and a subject; an empty one " +
			"means a token was accepted without the claims that identify who holds it")
	}

	existing, err := scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM public.users WHERE issuer = $1 AND subject = $2`,
		identity.Issuer, identity.Subject))

	switch {
	case err == nil:
		// The provider owns these two fields, so a change there is worth
		// persisting — but only when there is one.
		email := firstNonEmpty(identity.Email, existing.Email)
		name := firstNonEmpty(identity.DisplayName, existing.DisplayName)
		if email == existing.Email && name == existing.DisplayName {
			return existing, nil
		}
		updated, err := scanUser(s.pool.QueryRow(ctx, `
			UPDATE public.users
			   SET email = NULLIF($2, ''), display_name = NULLIF($3, ''), updated_at = now()
			 WHERE id = $1
			RETURNING `+userColumns, existing.ID, email, name))
		if err != nil {
			return nil, fmt.Errorf("store: could not refresh the signed-in user: %w", err)
		}
		return updated, nil

	case !errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("store: could not look up the signed-in user: %w", err)
	}

	// First sign-in. The bootstrap grant is decided here, on the insert path
	// only, so that removing an address from bootstrap_admins does not demote
	// anybody and adding one does not promote an account that already exists.
	// The setting grants a first role; it does not maintain one.
	role, source := RoleViewer, RoleSourceDefault
	if identity.Email != "" {
		for _, candidate := range bootstrapAdmins {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(identity.Email)) {
				role, source = RoleAdmin, RoleSourceBootstrap
				break
			}
		}
	}

	// DO UPDATE rather than DO NOTHING purely so that RETURNING yields a row
	// when two of a user's first requests arrive together — a real race, since
	// a browser opens the dashboard and the event stream at the same moment.
	created, err := scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO public.users (issuer, subject, email, display_name, role, status, role_source, last_seen_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, 'ACTIVE', $6, now())
		ON CONFLICT (issuer, subject) DO UPDATE SET updated_at = now()
		RETURNING `+userColumns,
		identity.Issuer, identity.Subject, identity.Email, identity.DisplayName, role, source))
	if err != nil {
		return nil, fmt.Errorf("store: could not create the signed-in user: %w", err)
	}
	return created, nil
}

func (s *PostgresStore) GetUser(ctx context.Context, id string) (*User, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM public.users WHERE id = $1`, id)
	u, err := scanUser(row)
	if noSuchRow(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: could not read user %s: %w", id, err)
	}
	return u, nil
}

// ListUsers returns everyone, most privileged first.
//
// Ordered by role rather than by name because the question this list answers
// is "who can do damage here", and that reading should not require scrolling.
func (s *PostgresStore) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+`
		FROM public.users
		ORDER BY CASE role
		           WHEN 'admin' THEN 0 WHEN 'operator' THEN 1
		           WHEN 'auditor' THEN 2 ELSE 3 END,
		         lower(COALESCE(email, subject))`)
	if err != nil {
		return nil, fmt.Errorf("store: could not list users: %w", err)
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: could not read a user row: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *PostgresStore) SetUserRole(ctx context.Context, id, role string) (*User, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE public.users SET role = $2, role_source = 'ASSIGNED', updated_at = now()
		WHERE id = $1
		RETURNING `+userColumns, id, role)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: could not set the role on user %s: %w", id, err)
	}
	return u, nil
}

func (s *PostgresStore) SetUserStatus(ctx context.Context, id, status string) (*User, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE public.users SET status = $2, updated_at = now()
		WHERE id = $1
		RETURNING `+userColumns, id, status)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: could not set the status on user %s: %w", id, err)
	}
	return u, nil
}

// TouchUser records that a subject was seen.
//
// Guarded on the stored value rather than written unconditionally. This runs on
// every authenticated request, and a dashboard left open on a wall makes one
// every few seconds; an unguarded update would produce a row version per
// request, on the one table every request already touches.
//
// The ::timestamptz cast is load-bearing and must not be tidied away. Without
// it PostgreSQL has no type to infer $2 from except the interval it is being
// subtracted from, resolves the parameter as an interval, and rejects the
// comparison with "operator does not exist: timestamp with time zone <
// interval". The in-memory store has no such notion and agreed with the broken
// version, so only the conformance suite against a real database caught it.
func (s *PostgresStore) TouchUser(ctx context.Context, id string, seenAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE public.users SET last_seen_at = $2
		WHERE id = $1
		  AND (last_seen_at IS NULL OR last_seen_at < $2::timestamptz - interval '60 seconds')`, id, seenAt)
	if err != nil {
		return fmt.Errorf("store: could not record that user %s was seen: %w", id, err)
	}
	return nil
}

// MarkCertificateRevoked records a revocation the CA has already accepted.
//
// Guarded on the current status rather than written unconditionally, so that
// two operators revoking the same certificate at once produce one revocation
// and one clear "already revoked" rather than a silently overwritten reason and
// timestamp — the pair an incident review actually reads.
func (s *PostgresStore) MarkCertificateRevoked(ctx context.Context, id string, reason int, actorID string) (*Certificate, error) {
	if !ValidRevocationReason(reason) {
		return nil, fmt.Errorf("store: %d is not a revocation reason CertPilot accepts", reason)
	}

	row := s.pool.QueryRow(ctx, `
		UPDATE public.certificates
		   SET status = 'REVOKED', revoked_at = now(),
		       revocation_reason = $2, revoked_by = NULLIF($3, ''), updated_at = now()
		 WHERE id = $1 AND status <> 'REVOKED'
		RETURNING `+certificateColumns, id, reason, actorID)

	cert, err := scanCertificate(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either no such certificate or it was already revoked. The caller
		// distinguishes them by reading the row; both are refusals, not
		// failures.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: could not record the revocation of certificate %s: %w", id, err)
	}
	return cert, nil
}
