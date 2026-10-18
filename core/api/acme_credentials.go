package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot/core/acmeserver"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// ACMECredentialHandler hands out the External Account Binding credentials an
// ACME client needs to register (RFC 8555 §7.3.4).
//
// Registration on the ACME server is closed. A credential is the permission to
// register, it belongs to one template, and the account made with it can only
// ask for what that template allows. So handing one out is choosing who may
// obtain certificates under that template, and it is admin only.
type ACMECredentialHandler struct {
	store   store.Store
	keyring *secrets.Keyring
	cfg     *config.CoreConfig
}

func NewACMECredentialHandler(st store.Store, kr *secrets.Keyring, cfg *config.CoreConfig) *ACMECredentialHandler {
	return &ACMECredentialHandler{store: st, keyring: kr, cfg: cfg}
}

type mintACMECredentialRequest struct {
	Name string `json:"name"`
	// Template is a slug or an id.
	Template string `json:"template"`
	// RequireChallenge makes the client prove each name by HTTP-01 or DNS-01.
	RequireChallenge bool `json:"require_challenge"`
}

// acmeCredentialView is a credential as the console lists it. The key is not
// here and cannot be: it was shown once, when the credential was made.
type acmeCredentialView struct {
	*store.ACMEEABCredential
	TemplateSlug string `json:"template"`
	// DirectoryURL is what to hand the client, so the console can show it
	// again for a credential made earlier. The key it cannot show again.
	DirectoryURL string `json:"directory_url,omitempty"`
}

// Create handles POST /api/v1/acme/credentials.
func (h *ACMECredentialHandler) Create(c *gin.Context) {
	var req mintACMECredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || strings.TrimSpace(req.Template) == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "a name and a template are required — the name is what identifies which client to revoke",
		})
		return
	}

	ctx := c.Request.Context()
	tpl, err := h.store.GetCertificateTemplate(ctx, req.Template)
	if errors.Is(err, store.ErrNotFound) {
		tpl, err = h.store.GetCertificateTemplateBySlug(ctx, req.Template)
	}
	if err != nil {
		respondLookup(c, err, "template")
		return
	}

	key := make([]byte, 32)
	kidBytes := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a key"})
		return
	}
	if _, err := rand.Read(kidBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a key id"})
		return
	}
	sealed, err := h.keyring.Encrypt(key, secrets.ContextACMEEABKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not seal the key"})
		return
	}

	actor, _ := actorOf(c)
	cred := &store.ACMEEABCredential{
		KID:              base64.RawURLEncoding.EncodeToString(kidBytes),
		Name:             req.Name,
		TemplateID:       tpl.ID,
		HMACKeySealed:    sealed,
		CreatedBy:        actor,
		RequireChallenge: req.RequireChallenge,
	}
	if err := h.store.CreateACMEEABCredential(ctx, cred); err != nil {
		slog.Error("could not store an ACME credential", "path", c.FullPath(), "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not store the credential"})
		return
	}
	h.audit(c, "acme_credential.created", cred.ID,
		fmt.Sprintf(`{"name":%q,"template":%q,"kid":%q,"require_challenge":%t}`, cred.Name, tpl.Slug, cred.KID, cred.RequireChallenge))

	c.JSON(http.StatusCreated, gin.H{
		"data": acmeCredentialView{cred, tpl.Slug, ""},
		// base64url, which is what certbot's --eab-hmac-key and acme.sh's
		// --eab-hmac-key take. Shown here and nowhere else.
		"hmac_key":      base64.RawURLEncoding.EncodeToString(key),
		"directory_url": h.directoryURL(c, tpl.Slug),
		"message":       "Copy the hmac_key now. It is not kept in a form that can be shown again.",
	})
}

// List handles GET /api/v1/acme/credentials.
func (h *ACMECredentialHandler) List(c *gin.Context) {
	ctx := c.Request.Context()
	creds, err := h.store.ListACMEEABCredentials(ctx)
	if err != nil {
		respondLookup(c, err, "ACME credentials")
		return
	}
	templates, err := h.store.ListCertificateTemplates(ctx)
	if err != nil {
		respondLookup(c, err, "templates")
		return
	}
	slugs := make(map[string]string, len(templates))
	for _, t := range templates {
		slugs[t.ID] = t.Slug
	}
	out := make([]acmeCredentialView, 0, len(creds))
	for _, cred := range creds {
		slug := slugs[cred.TemplateID]
		view := acmeCredentialView{cred, slug, ""}
		if slug != "" {
			view.DirectoryURL = h.directoryURL(c, slug)
		}
		out = append(out, view)
	}
	// Said, because a credential minted while ACME is switched off is one no
	// client can use, and the screen should say why rather than let somebody
	// find out from certbot.
	c.JSON(http.StatusOK, gin.H{"data": out, "enabled": h.cfg.ACME.Enabled})
}

// Revoke handles DELETE /api/v1/acme/credentials/:id.
func (h *ACMECredentialHandler) Revoke(c *gin.Context) {
	actor, _ := actorOf(c)
	id := c.Param("id")
	// One write: the credential, and the account it made, which is the one a
	// client cut off would otherwise go on ordering with.
	deactivated, err := h.store.RevokeACMEEABCredential(c.Request.Context(), id, actor)
	if err != nil {
		respondLookup(c, err, "ACME credential")
		return
	}
	h.audit(c, "acme_credential.revoked", id, fmt.Sprintf(`{"account_deactivated":%q}`, deactivated))
	c.JSON(http.StatusOK, gin.H{
		"message": "Revoked. The account it made can no longer order, and no new one can be made with it.",
	})
}

// directoryURL is the address to give a client for a template's directory.
//
// From acme.external_url when it is set. Without it, the only other source is
// the request, whose Host and X-Forwarded-Proto are whatever the sender chose:
// trusted on a developer's machine, and in production left empty rather than
// show an administrator an address somebody else picked, to paste into a
// client. Production with ACME switched on cannot get here, because
// configuration refuses to start without an external_url.
func (h *ACMECredentialHandler) directoryURL(c *gin.Context, slug string) string {
	if h.cfg.ACME.ExternalURL == "" && h.cfg.Server.IsProduction() {
		return ""
	}
	return acmeserver.DirectoryURL(h.cfg.ACME.ExternalURL, c.Request, slug)
}

func (h *ACMECredentialHandler) audit(c *gin.Context, action, entityID, details string) {
	actor, email := actorOf(c)
	entity := entityID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "acme_credential",
		EntityID:   &entity,
		ActorID:    actor,
		ActorEmail: email,
		Details:    details,
	})
}

// acmeValidation is how the ACME server checks challenges, from configuration.
func acmeValidation(c config.ACMEChallengeConfig) acmeserver.Validation {
	v := acmeserver.Validation{HTTPPort: c.Port()}
	if c.DNSResolver != "" {
		// Every lookup, both challenges', goes to the configured resolver.
		// "tcp://" forces TCP, for a resolver UDP cannot reach; Go's resolver
		// speaks whichever the connection it is handed is.
		addr, forceTCP := strings.CutPrefix(c.DNSResolver, "tcp://")
		v.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if forceTCP {
					network = "tcp"
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	}
	return v
}
