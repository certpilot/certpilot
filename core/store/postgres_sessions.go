package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/passwords"
	"github.com/jackc/pgx/v5"
)

const sessionColumns = `id, user_id, token_hash, expires_at, revoked_at,
	last_seen_at, COALESCE(last_seen_ip, ''), COALESCE(user_agent, ''), created_at`

func scanSession(row pgx.Row) (*Session, error) {
	s := &Session{}
	var revoked, lastSeen *time.Time
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.ExpiresAt, &revoked,
		&lastSeen, &s.LastSeenIP, &s.UserAgent, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.RevokedAt, s.LastSeenAt = revoked, lastSeen
	return s, nil
}

func (s *PostgresStore) UserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM public.users WHERE lower(email) = lower($1)`,
		strings.TrimSpace(email))
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: could not look up an account by email: %w", err)
	}
	return u, nil
}

func (s *PostgresStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM public.users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: could not count users: %w", err)
	}
	return n, nil
}

// AuthenticatePassword verifies a sign-in and records the attempt.
//
// The password is verified even when the account does not exist, against a
// throwaway hash. Returning early on an unknown address makes the response
// measurably faster for addresses that are not registered, and that timing
// difference is a working account-enumeration oracle on a login endpoint that
// is deliberately vague in every other respect.
func (s *PostgresStore) AuthenticatePassword(ctx context.Context, email, password string) (*User, LoginOutcome, error) {
	u, err := s.UserByEmail(ctx, email)
	if err != nil {
		return nil, LoginNoSuchAccount, err
	}

	if u == nil {
		_ = passwords.Verify(password, decoyHash)
		return nil, LoginNoSuchAccount, nil
	}

	var storedHash string
	var failed int
	var lockedUntil *time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT COALESCE(password_hash, ''), failed_logins, locked_until
		   FROM public.users WHERE id = $1`, u.ID).Scan(&storedHash, &failed, &lockedUntil)
	if err != nil {
		return nil, LoginNoSuchAccount, fmt.Errorf("store: could not read sign-in state: %w", err)
	}

	now := time.Now()
	// Checked before the password, so that a locked account costs an attacker a
	// lock rather than a guess.
	if lockedUntil != nil && now.Before(*lockedUntil) {
		return u, LoginLockedOut, nil
	}
	if !u.IsActive() {
		return u, LoginSuspended, nil
	}
	if storedHash == "" {
		_ = passwords.Verify(password, decoyHash)
		return u, LoginNoPasswordSet, nil
	}

	if err := passwords.Verify(password, storedHash); err != nil {
		if _, dbErr := s.pool.Exec(ctx, `
			UPDATE public.users
			   SET failed_logins = failed_logins + 1,
			       locked_until = CASE WHEN failed_logins + 1 >= $2
			                           THEN now() + $3::interval ELSE locked_until END
			 WHERE id = $1`, u.ID, MaxFailedLogins, LockoutWindow.String()); dbErr != nil {
			return u, LoginWrongPassword, fmt.Errorf("store: could not record a failed sign-in: %w", dbErr)
		}
		return u, LoginWrongPassword, nil
	}

	// Only cleared on success, and only when there is something to clear.
	if failed > 0 || lockedUntil != nil {
		if _, err := s.pool.Exec(ctx,
			`UPDATE public.users SET failed_logins = 0, locked_until = NULL WHERE id = $1`,
			u.ID); err != nil {
			return u, LoginOK, fmt.Errorf("store: could not reset the sign-in counter: %w", err)
		}
	}
	return u, LoginOK, nil
}

// decoyHash is a real Argon2id hash of a value nobody knows.
//
// Verified against when an account does not exist so that the work done is the
// same either way. Without it, "no such account" returns in microseconds while
// a real account costs a full Argon2id derivation, and the difference is
// trivially measurable over a network.
//
// Generated from random input and checked to reach a genuine mismatch rather
// than an early decode failure — a malformed constant here would return in
// microseconds and reinstate the very timing difference it removes.
const decoyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
	"htc3OGVgpx++8z+Ksixc4w$x6h6UyvjU3BPzkPPBY3fUy+ibI7MFBa3rfrnmDshark"

func (s *PostgresStore) SetUserPassword(ctx context.Context, id, password string, mustChange bool) error {
	hash, err := passwords.Hash(password)
	if err != nil {
		return err
	}
	// Setting a password clears the lock: an administrator resetting it for
	// somebody who locked themselves out should not leave them still locked.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.users
		   SET password_hash = $2, password_set_at = now(), must_change_password = $3,
		       failed_logins = 0, locked_until = NULL, updated_at = now()
		 WHERE id = $1`, id, hash, mustChange)
	if err != nil {
		return fmt.Errorf("store: could not set the password on user %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: no user %s to set a password on", id)
	}
	return nil
}

func (s *PostgresStore) CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (*Session, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO public.sessions (user_id, token_hash, expires_at, user_agent, last_seen_ip, last_seen_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), now())
		RETURNING `+sessionColumns, userID, tokenHash, expiresAt, userAgent, ip)

	sess, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("store: could not create a session: %w", err)
	}
	return sess, nil
}

// SessionByHash returns the session and its user together.
//
// One query rather than two on purpose: fetched separately, a session could be
// validated a moment before its account was suspended and still be honoured.
func (s *PostgresStore) SessionByHash(ctx context.Context, tokenHash string) (*Session, *User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT s.id, s.user_id, s.token_hash, s.expires_at, s.revoked_at,
		       s.last_seen_at, COALESCE(s.last_seen_ip, ''), COALESCE(s.user_agent, ''), s.created_at,
		       u.id, u.issuer, u.subject, COALESCE(u.email, ''), COALESCE(u.display_name, ''),
		       u.role, u.status, u.role_source, COALESCE(u.must_change_password, false),
		       u.last_seen_at, u.created_at, u.updated_at
		  FROM public.sessions s
		  JOIN public.users u ON u.id = s.user_id
		 WHERE s.token_hash = $1`, tokenHash)
	if err != nil {
		return nil, nil, fmt.Errorf("store: could not look up a session: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		// No row, or a read that failed: pgx reports the second through
		// rows.Err() once Next has returned false. Reading it as "no such
		// session" signed out every browser that made a request while the
		// database was unreachable, because the middleware clears a cookie
		// that does not resolve.
		if err := rows.Err(); err != nil {
			return nil, nil, fmt.Errorf("store: could not look up a session: %w", err)
		}
		return nil, nil, nil
	}

	sess := &Session{}
	u := &User{}
	var revoked, lastSeen, userLastSeen *time.Time
	if err := rows.Scan(
		&sess.ID, &sess.UserID, &sess.TokenHash, &sess.ExpiresAt, &revoked,
		&lastSeen, &sess.LastSeenIP, &sess.UserAgent, &sess.CreatedAt,
		&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName,
		&u.Role, &u.Status, &u.RoleSource, &u.MustChangePassword,
		&userLastSeen, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, nil, fmt.Errorf("store: could not read a session row: %w", err)
	}
	sess.RevokedAt, sess.LastSeenAt, u.LastSeenAt = revoked, lastSeen, userLastSeen
	return sess, u, nil
}

func (s *PostgresStore) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE public.sessions SET revoked_at = now()
		  WHERE token_hash = $1 AND revoked_at IS NULL`, tokenHash)
	if err != nil {
		return fmt.Errorf("store: could not revoke a session: %w", err)
	}
	return nil
}

func (s *PostgresStore) RevokeSessionsForUser(ctx context.Context, userID string) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE public.sessions SET revoked_at = now()
		  WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, fmt.Errorf("store: could not revoke sessions for user %s: %w", userID, err)
	}
	return int(tag.RowsAffected()), nil
}

// TouchSession records that a session was used, guarded for the same reason
// TouchUser is: this runs on every authenticated request.
func (s *PostgresStore) TouchSession(ctx context.Context, id string, seenAt time.Time, ip string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE public.sessions
		   SET last_seen_at = $2, last_seen_ip = COALESCE(NULLIF($3, ''), last_seen_ip)
		 WHERE id = $1
		   AND (last_seen_at IS NULL OR last_seen_at < $2::timestamptz - interval '60 seconds')`,
		id, seenAt, ip)
	if err != nil {
		return fmt.Errorf("store: could not record session activity: %w", err)
	}
	return nil
}

func (s *PostgresStore) CountPasswordAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM public.users
		  WHERE password_hash IS NOT NULL AND status = 'ACTIVE'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: could not count accounts with a password: %w", err)
	}
	return n, nil
}
