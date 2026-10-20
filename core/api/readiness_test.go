package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

type unreachableStore struct{ store.Store }

func (unreachableStore) Ping(context.Context) error {
	return errors.New("dial tcp 10.0.0.5:5432: connect: connection refused")
}

func readyz(t *testing.T, st store.Store) *httptest.ResponseRecorder {
	t.Helper()
	r, _, _ := realRouterOn(t, st)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestACoreThatCanReachItsDatabaseIsReady(t *testing.T) {
	if rec := readyz(t, store.NewMemoryStore()); rec.Code != http.StatusOK {
		t.Fatalf("/readyz = %d %s, want 200", rec.Code, rec.Body)
	}
}

// A load balancer sends traffic to whatever answers its probe. /healthz says
// the process is alive, which it is with the database gone; /readyz is the one
// that has to stop answering 200 then.
func TestACoreThatCannotReachItsDatabaseIsNotReady(t *testing.T) {
	rec := readyz(t, unreachableStore{store.NewMemoryStore()})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with the database unreachable = %d, want 503", rec.Code)
	}
	// Unauthenticated, so it must not hand out the database's address.
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("/readyz leaked the cause to an unauthenticated caller: %s", rec.Body)
	}
}
