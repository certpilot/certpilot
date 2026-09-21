package api

import (
	"encoding/json"
	"net/http"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
)

// SessionHandler serves what a browser needs in order to sign in, and who it
// is once it has.
type SessionHandler struct {
	store store.Store
	auth  config.AuthConfig
	// authenticator verifies ID tokens for the federated sign-in callback. It
	// is the same one the request path uses, so a sign-in and a request agree
	// on issuer, signing keys and how an identity becomes a CertPilot user.
	authenticator *middleware.Authenticator
}

func NewSessionHandler(s store.Store, auth config.AuthConfig, authenticator *middleware.Authenticator) *SessionHandler {
	return &SessionHandler{store: s, auth: auth, authenticator: authenticator}
}

// AuthConfigResponse tells the frontend how to authenticate against this
// instance.
//
// Served rather than compiled in, so that one deployment is described by one
// configuration file. A frontend carrying its own build-time copy of the issuer
// and client id can disagree with the core it is talking to, and the way that
// disagreement presents is a login that appears to succeed followed by 401 on
// every subsequent request — which reads as a broken API rather than as a
// mismatched setting.
//
// Everything here is public by construction. In authorization code with PKCE
// there is no client secret: the issuer and client id are sent to the provider
// in a URL the user can read.
type AuthConfigResponse struct {
	// Mode is "oidc" when single sign-on is configured, otherwise "password".
	// There is no longer an "anonymous" mode: an instance that nobody has to
	// sign in to was a development convenience that made the authorisation
	// paths the least exercised code in the system, and it attributed every
	// action in the audit log to a subject nobody could be asked about.
	Mode string `json:"mode"`
	// PasswordLogin is true whenever local accounts can be used, which is
	// always — single sign-on is offered alongside it, never instead of it, so
	// that a provider outage does not lock a team out of its own CA hierarchy.
	PasswordLogin bool     `json:"password_login"`
	Issuer        string   `json:"issuer,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	Audience      string   `json:"audience,omitempty"`
}

// Config handles GET /api/v1/auth/config.
//
// Deliberately unauthenticated: it is what a browser reads before it has any
// credential at all.
func (h *SessionHandler) Config(c *gin.Context) {
	switch {
	case h.auth.Issuer != "" && h.auth.ClientID != "":
		c.JSON(http.StatusOK, AuthConfigResponse{
			Mode:          "oidc",
			PasswordLogin: true,
			Issuer:        h.auth.Issuer,
			ClientID:      h.auth.ClientID,
			Scopes:        h.auth.Scopes,
			Audience:      h.auth.Audience,
		})

	default:
		// No identity provider configured: local accounts only. This is a
		// complete, supported configuration rather than a degraded one.
		c.JSON(http.StatusOK, AuthConfigResponse{Mode: "password", PasswordLogin: true})
	}
}

// MeResponse is the caller's own identity and role.
type MeResponse struct {
	Subject     string `json:"subject"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	// AuthMethod distinguishes a person signed in with a password or a bearer
	// token from a wall display, which the UI needs in order to decide what to
	// offer.
	AuthMethod string `json:"auth_method"`
	// UserID is CertPilot's own identifier, absent for a display token, which
	// is the one credential with no user row behind it.
	UserID     string `json:"user_id,omitempty"`
	RoleSource string `json:"role_source,omitempty"`
	// MustChangePassword is set for a generated credential the account holder
	// has not replaced — the one printed at first start.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// Me handles GET /api/v1/me.
//
// The frontend must not decide a role by reading the token itself. The role
// that governs a request is the one in CertPilot's users table, and this is the
// only endpoint that reports it — a UI that decoded the JWT would show controls
// matching a claim the API stopped honouring the moment somebody was demoted.
func (h *SessionHandler) Me(c *gin.Context) {
	resp := MeResponse{
		Subject:     c.GetString(middleware.ContextUserID),
		Email:       c.GetString(middleware.ContextUserEmail),
		Role:        c.GetString(middleware.ContextUserRole),
		AuthMethod:  c.GetString(middleware.ContextAuthMethod),
		UserID:      c.GetString(middleware.ContextUserDBID),
		DisplayName: "",
	}

	if resp.UserID != "" {
		if u, err := h.store.GetUser(c.Request.Context(), resp.UserID); err == nil && u != nil {
			resp.DisplayName = u.DisplayName
			resp.RoleSource = u.RoleSource
			resp.MustChangePassword = u.MustChangePassword
		}
	}

	c.JSON(http.StatusOK, resp)
}

// audit records an authentication event.
//
// Sign-in and sign-out are exactly the events an incident review reads first,
// and a failed sign-in is the one that says somebody is trying. Failures are
// deliberately recorded with their real reason even though the caller is told
// nothing — the distinction belongs to the operator, not to whoever is guessing.
func (h *SessionHandler) audit(c *gin.Context, subject, action string, details map[string]any) {
	if subject == "" {
		return
	}

	ip := c.ClientIP()
	email := c.GetString(middleware.ContextUserEmail)

	encoded := "{}"
	if len(details) > 0 {
		if raw, err := json.Marshal(details); err == nil {
			encoded = string(raw)
		}
	}

	entry := &store.AuditLog{
		Action:     action,
		EntityType: "session",
		ActorID:    &subject,
		IPAddress:  &ip,
		Details:    encoded,
	}
	if email != "" {
		entry.ActorEmail = &email
	}

	// Best effort. Failing to write an audit row must not stop somebody
	// signing out.
	_ = h.store.CreateAuditLog(c.Request.Context(), entry)
}
