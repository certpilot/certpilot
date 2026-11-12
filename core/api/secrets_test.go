package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/engine/rekey"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/golang-jwt/jwt/v5"
)

// viewerToken signs in somebody who is not an administrator.
func viewerToken(t *testing.T, st store.Store) string {
	t.Helper()
	viewer, err := st.ResolveUser(context.Background(), store.UserIdentity{
		Issuer: apiTestIssuer, Subject: "00uAPITESTviewer02", Email: "viewer2@certpilot.test",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if viewer.Role == store.RoleAdmin {
		t.Fatal("the harness gave the viewer an admin role, which would make this test vacuous")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &middleware.UserClaims{
		Email: "viewer2@certpilot.test",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "00uAPITESTviewer02", Issuer: apiTestIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	})
	signed, err := token.SignedString([]byte(apiTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The report is what an operator reads before dropping a retired key, so it
// has to name a key this core does not hold as well as the one it does.
func TestKeyReportNamesEveryKeyTheDatabaseDependsOn(t *testing.T) {
	r, st := realRouter(t)
	ctx := context.Background()

	foreign, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := foreign.EncryptString(`{"url":"https://hooks.example.test"}`, secrets.ContextNotificationConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateNotificationChannel(ctx, &store.NotificationChannel{Name: "from-another-key",
		ChannelType: "webhook", IsEnabled: true, SeverityThreshold: "WARNING", ConfigEncrypted: sealed}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateAuditLog(ctx, &store.AuditLog{Action: "test.entry", EntityType: "test"}); err != nil {
		t.Fatal(err)
	}

	w := do(r, http.MethodGet, "/api/v1/secrets/keys", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /secrets/keys = %d, want 200: %s", w.Code, w.Body.String())
	}
	report := &rekey.Report{}
	if err := json.Unmarshal(w.Body.Bytes(), report); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(report.Keys) < 2 || report.Keys[0].Status != rekey.StatusPrimary || report.Keys[0].KeyID != report.PrimaryKeyID {
		t.Fatalf("the primary key is not first: %s", w.Body.String())
	}
	if report.Keys[0].Audit == nil || report.Keys[0].Audit.Entries < 1 {
		t.Errorf("the primary key is not credited with the audit entries it signed: %s", w.Body.String())
	}
	var missing *rekey.KeyUsage
	for i := range report.Keys {
		if report.Keys[i].KeyID == foreign.PrimaryKeyID() {
			missing = &report.Keys[i]
		}
	}
	if missing == nil || missing.Status != rekey.StatusMissing || missing.Sealed[store.SealedNotificationChannel] != 1 {
		t.Errorf("the key this core does not hold is not reported as missing with one channel: %s", w.Body.String())
	}
}

// Which keys exist and how much each protects is a map of what to steal.
func TestKeyReportIsAdminOnly(t *testing.T) {
	r, st := realRouter(t)
	w := do(r, http.MethodGet, "/api/v1/secrets/keys", nil,
		map[string]string{"Authorization": "Bearer " + viewerToken(t, st)})
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET /secrets/keys as a viewer = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestKeyReportRefusesADisplayToken(t *testing.T) {
	r, _ := realRouter(t)
	raw, _ := mintToken(t, r, "corridor screen", 30)
	w := do(r, http.MethodGet, "/api/v1/secrets/keys", nil, map[string]string{"X-Display-Token": raw})
	if w.Code == http.StatusOK {
		t.Fatalf("a display token read the key report: %s", w.Body.String())
	}
}
