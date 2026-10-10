package store

import (
	"context"
	"testing"
	"time"
)

// TestASessionReadThatFailsIsAnErrorNotAnUnknownSession.
//
// pgx reports a failure that arrives while rows are being read through
// rows.Err(), after rows.Next() has returned false. SessionByHash read a false
// Next as "no such session" without asking why, so a database that dropped
// mid-read made every signed-in browser's session look unknown: the middleware
// cleared the cookie and answered 401, and the user stayed signed out once the
// database was back. Seen with the database stopped under a running core.
//
// The view stands in for a connection lost mid-read: it fails while producing
// the matching row, which is after pgx has handed back the rows.
func TestASessionReadThatFailsIsAnErrorNotAnUnknownSession(t *testing.T) {
	s := postgresOnly(t)
	ctx := context.Background()

	u, err := s.ResolveUser(ctx, UserIdentity{Issuer: LocalIssuer, Subject: "reader", Email: "reader@example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	const hash = "8a1f9c0d2e3b4a5f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
	if _, err := s.CreateSession(ctx, u.ID, hash, time.Now().Add(time.Hour), "test", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if sess, _, err := s.SessionByHash(ctx, hash); err != nil || sess == nil {
		t.Fatalf("the session does not read back before the failure is introduced: %v", err)
	}

	for _, stmt := range []string{
		`ALTER TABLE public.sessions RENAME TO sessions_kept`,
		`CREATE FUNCTION public.cp_test_read_fails() RETURNS uuid LANGUAGE plpgsql AS
		   $$ BEGIN RAISE EXCEPTION 'the connection was lost while reading'; END $$`,
		`CREATE VIEW public.sessions AS
		   SELECT public.cp_test_read_fails() AS id, user_id, token_hash, expires_at, revoked_at,
		          last_seen_at, last_seen_ip, user_agent, created_at
		     FROM public.sessions_kept`,
	} {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	sess, user, err := s.SessionByHash(ctx, hash)
	if err == nil {
		t.Fatalf("a read that failed returned (%v, %v, nil): the session reads as unknown, so the browser is signed out", sess, user)
	}
}
