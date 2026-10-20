package store

import (
	"context"
	"testing"
)

// The readiness probe asks the store whether it can still answer. A store that
// can is ready.
func TestAStoreThatIsUpAnswersAPing(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		if err := s.Ping(context.Background()); err != nil {
			t.Fatalf("Ping on a working store: %v", err)
		}
	})
}

// And one that cannot reach its database says so, which is the whole reason the
// probe exists: /healthz answered "ok" from a core whose database was gone.
func TestAPostgresStoreThatLostItsDatabaseFailsAPing(t *testing.T) {
	s := postgresOnly(t)
	s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded on a store whose pool is closed")
	}
}
