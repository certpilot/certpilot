package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme"
)

// acmeTemplate seeds a template to hand ACME access to.
func acmeTemplate(t *testing.T, st store.Store) *store.CertificateTemplate {
	t.Helper()
	ca := &store.CAAccount{Name: "ACME test CA", ProviderType: "selfsigned", GatewayAddr: "127.0.0.1:1",
		ConfigEncrypted: "x", Status: "CONNECTED"}
	if err := st.CreateCAAccount(context.Background(), ca); err != nil {
		t.Fatal(err)
	}
	tpl := &store.CertificateTemplate{
		Slug: "web", Name: "Web", Version: 1, IsEnabled: true, CAAccountID: ca.ID,
		SubjectMode: store.SubjectModeSupplied, AllowedKeyTypes: []string{"ECDSA"},
		KeyCustodyRequired: store.KeyCustodyAny, RenewBeforeDays: 30,
	}
	if err := st.CreateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}
	return tpl
}

type mintedCredential struct {
	Data struct {
		ID   string `json:"id"`
		KID  string `json:"kid"`
		Name string `json:"name"`
	} `json:"data"`
	HMACKey      string `json:"hmac_key"`
	DirectoryURL string `json:"directory_url"`
}

func mintACMECredential(t *testing.T, r *gin.Engine, template string) mintedCredential {
	t.Helper()
	w := do(r, http.MethodPost, "/api/v1/acme/credentials", gin.H{"name": "web team", "template": template}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var out mintedCredential
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func acmeEnabled(c *config.CoreConfig) { c.ACME.Enabled = true }

func TestAnAdministratorCanMintACredentialForATemplate(t *testing.T) {
	r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	acmeTemplate(t, st)

	got := mintACMECredential(t, r, "web")
	if got.Data.KID == "" || got.Data.Name != "web team" {
		t.Fatalf("no key id or name: %+v", got)
	}
	key, err := base64.RawURLEncoding.DecodeString(got.HMACKey)
	if err != nil || len(key) != 32 {
		t.Fatalf("hmac_key %q is not 32 bytes of base64url: %v", got.HMACKey, err)
	}
	if !strings.HasSuffix(got.DirectoryURL, "/acme/web/directory") {
		t.Errorf("directory_url %q does not point at the template's directory", got.DirectoryURL)
	}

	// The key was shown once and is not kept in a form that can be shown again.
	stored, _ := st.GetACMEEABCredentialByKID(context.Background(), got.Data.KID)
	if stored == nil || strings.Contains(stored.HMACKeySealed, got.HMACKey) {
		t.Errorf("the credential is stored with its key readable: %+v", stored)
	}

	w := do(r, http.MethodGet, "/api/v1/acme/credentials", nil, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), got.HMACKey) {
		t.Errorf("the list shows the key, or failed: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), got.Data.KID) {
		t.Errorf("the list does not show the credential: %s", w.Body.String())
	}
}

func TestACredentialNeedsAnExistingTemplate(t *testing.T) {
	r, _, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	w := do(r, http.MethodPost, "/api/v1/acme/credentials", gin.H{"name": "x", "template": "nope"}, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d %s, want 404", w.Code, w.Body.String())
	}
	w = do(r, http.MethodPost, "/api/v1/acme/credentials", gin.H{"template": "web"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a credential with no name: %d, want 400", w.Code)
	}
}

func TestMintingACredentialIsAudited(t *testing.T) {
	r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	acmeTemplate(t, st)
	got := mintACMECredential(t, r, "web")
	logs, _, err := st.ListAuditLogs(context.Background(), store.AuditLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range logs {
		if l.Action == "acme_credential.created" {
			if strings.Contains(l.Details, got.HMACKey) {
				t.Fatalf("the audit entry holds the key: %s", l.Details)
			}
			return
		}
	}
	t.Fatal("minting a credential left no audit entry")
}

// The path an operator takes: mint a credential, give it to a client, and the
// client registers.
func TestAMintedCredentialRegistersAClientThroughTheRealRouter(t *testing.T) {
	r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	acmeTemplate(t, st)
	got := mintACMECredential(t, r, "web")
	srv := httptest.NewServer(r)
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hmac, _ := base64.RawURLEncoding.DecodeString(got.HMACKey)
	client := &acme.Client{Key: key, DirectoryURL: srv.URL + "/acme/web/directory"}
	acct, err := client.Register(context.Background(), &acme.Account{
		ExternalAccountBinding: &acme.ExternalAccountBinding{KID: got.Data.KID, Key: hmac},
	}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	w := do(r, http.MethodGet, "/api/v1/acme/credentials", nil, nil)
	if !strings.Contains(w.Body.String(), acct.URI[strings.LastIndex(acct.URI, "/")+1:]) {
		t.Errorf("the list does not say which account used the credential: %s", w.Body.String())
	}
}

func TestARevokedCredentialStopsWorking(t *testing.T) {
	r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	acmeTemplate(t, st)
	got := mintACMECredential(t, r, "web")

	if w := do(r, http.MethodDelete, "/api/v1/acme/credentials/"+got.Data.ID, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	srv := httptest.NewServer(r)
	defer srv.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hmac, _ := base64.RawURLEncoding.DecodeString(got.HMACKey)
	_, err := (&acme.Client{Key: key, DirectoryURL: srv.URL + "/acme/web/directory"}).Register(context.Background(), &acme.Account{
		ExternalAccountBinding: &acme.ExternalAccountBinding{KID: got.Data.KID, Key: hmac},
	}, acme.AcceptTOS)
	if err == nil {
		t.Fatal("a revoked credential still registered an account")
	}
}

func TestACMEIsNotServedUnlessTheOperatorTurnedItOn(t *testing.T) {
	r, st, _ := realRouterOn(t, store.NewMemoryStore())
	acmeTemplate(t, st)
	for _, path := range []string{"/acme/web/directory", "/acme/web/new-nonce"} {
		if w := do(r, http.MethodGet, path, nil, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d with ACME off; the endpoints must not exist", path, w.Code)
		}
	}
}

// Revoking is how an administrator cuts a client off. Leaving the account it
// already made able to order would make revoking stop only a client that had
// not registered yet, which is nobody worth revoking.
func TestRevokingACredentialEndsTheAccountItMade(t *testing.T) {
	r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), acmeEnabled)
	acmeTemplate(t, st)
	got := mintACMECredential(t, r, "web")
	srv := httptest.NewServer(r)
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hmac, _ := base64.RawURLEncoding.DecodeString(got.HMACKey)
	client := &acme.Client{Key: key, DirectoryURL: srv.URL + "/acme/web/directory"}
	if _, err := client.Register(context.Background(), &acme.Account{
		ExternalAccountBinding: &acme.ExternalAccountBinding{KID: got.Data.KID, Key: hmac},
	}, acme.AcceptTOS); err != nil {
		t.Fatal(err)
	}

	if w := do(r, http.MethodDelete, "/api/v1/acme/credentials/"+got.Data.ID, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if _, err := client.AuthorizeOrder(context.Background(), acme.DomainIDs("web.example.com")); err == nil {
		t.Fatal("the account made with a revoked credential can still order")
	}
}

// The console screen needs to know whether the endpoint is on at all, and the
// directory address to hand a client for each credential.
func TestTheCredentialListSaysWhetherACMEIsOnAndWhereToPointAClient(t *testing.T) {
	for _, on := range []bool{true, false} {
		tweak := func(c *config.CoreConfig) { c.ACME.Enabled = on }
		r, st, _ := realRouterConfigured(t, store.NewMemoryStore(), tweak)
		acmeTemplate(t, st)
		mintACMECredential(t, r, "web")

		w := do(r, http.MethodGet, "/api/v1/acme/credentials", nil, nil)
		var list struct {
			Enabled bool `json:"enabled"`
			Data    []struct {
				DirectoryURL string `json:"directory_url"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if list.Enabled != on {
			t.Errorf("enabled %v with acme.enabled %v", list.Enabled, on)
		}
		if len(list.Data) != 1 || !strings.HasSuffix(list.Data[0].DirectoryURL, "/acme/web/directory") {
			t.Errorf("list %s", w.Body.String())
		}
	}
}
