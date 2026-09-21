// Package middleware provides authentication, authorization, and request
// hygiene for the CertPilot HTTP API.
package middleware

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
	"log/slog"

	"github.com/certpilot/certpilot/core/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RBAC roles, in ascending order of privilege for write operations.
const (
	RoleViewer   = "viewer"
	RoleAuditor  = "auditor"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Context keys set by AuthMiddleware.
const (
	ContextUserID    = "user_id"
	ContextUserEmail = "user_email"
	ContextUserRole  = "user_role"
	// ContextAuthMethod records how the caller proved who they are. It is what
	// lets a later middleware tell "already authenticated" from "not yet
	// looked at", and it is worth recording in its own right: an audit entry
	// attributed to a corridor screen means something different from one
	// attributed to a person.
	ContextAuthMethod = "auth_method"
	// ContextUserDBID is the primary key of the row in CertPilot's users
	// table, as distinct from ContextUserID which is the provider's subject.
	// Actor columns keep storing the subject: it is what the audit log has
	// always held, and it survives the users table being rebuilt.
	ContextUserDBID = "user_db_id"
	// ContextSessionID identifies the browser session, so signing out can end
	// this one specifically rather than every session the account holds.
	ContextSessionID = "session_id"
)

// identityIssuer prefers the issuer the token asserts.
//
// A legacy HS256 token need not carry one, and there is no JWKS to infer it
// from, so the configured issuer stands in. The constant last resort keeps a
// subject from being stored against an empty issuer, where it would collide
// with every other provider's subjects.
func identityIssuer(claims *UserClaims, configured string) string {
	if iss, err := claims.GetIssuer(); err == nil && iss != "" {
		return iss
	}
	if configured != "" {
		return configured
	}
	return "legacy-shared-secret"
}

// Authentication methods recorded in ContextAuthMethod.
const (
	AuthMethodBearer = "bearer"
	// There is no AuthMethodAnonymous. There was, and nothing assigned it for
	// a long time after the fallback below was removed — which is how
	// docs/architecture.md came to keep listing anonymous as an auth method
	// the chain could resolve.
	AuthMethodDisplayToken = "display_token"
	AuthMethodSession      = "session"
)

// UserClaims represents the claims inside an identity provider's JWT.
type UserClaims struct {
	Email string `json:"email"`
	// Name and PreferredUsername are the OIDC profile claims that let a users
	// list show a person rather than an opaque subject. Both are optional, and
	// a provider configured without the profile scope sends neither.
	Name              string         `json:"name"`
	PreferredUsername string         `json:"preferred_username"`
	AppMetadata       map[string]any `json:"app_metadata"`
	// Nonce binds an ID token to the one authorization request that asked for
	// it. Present only on ID tokens, and checked only there: without it, a
	// token captured from one sign-in can be replayed into another.
	Nonce string `json:"nonce"`
	jwt.RegisteredClaims
}

// DisplayName is the friendliest label the token offers, or empty.
func (c *UserClaims) DisplayName() string {
	if c.Name != "" {
		return c.Name
	}
	return c.PreferredUsername
}

// Role returns the RBAC role from app_metadata, defaulting to viewer.
//
// The role is read from app_metadata rather than user_metadata deliberately:
// user_metadata is writable by the user the token belongs to, so trusting it
// would let any account promote itself to admin.
func (c *UserClaims) Role(claimName string) string {
	if claimName == "" {
		claimName = "certpilot_role"
	}
	if c.AppMetadata != nil {
		if role, ok := c.AppMetadata[claimName].(string); ok {
			switch role {
			case RoleAdmin, RoleOperator, RoleAuditor, RoleViewer:
				return role
			}
		}
	}
	return RoleViewer
}

// UserDirectory is the slice of the store the authenticator needs.
//
// Narrow on purpose: this middleware runs on every request and should be able
// to look a user up and record that they were seen, and nothing else. Handing
// it the whole Store would let a future edit here change a role during a
// sign-in, which is exactly what must never happen.
type UserDirectory interface {
	ResolveUser(ctx context.Context, identity store.UserIdentity, bootstrapAdmins []string) (*store.User, error)
	TouchUser(ctx context.Context, id string, seenAt time.Time) error
}

// Authenticator verifies bearer tokens.
type Authenticator struct {
	cfg   config.AuthConfig
	cache *jwk.Cache

	// users resolves a verified token's subject to the role CertPilot holds
	// for that person. When nil the role falls back to the token's own claim,
	// which is how the middleware tests and any deployment without a store
	// continue to work.
	users UserDirectory
}

// NewAuthenticator builds an Authenticator. When a JWKS URL is configured, its
// keys are fetched and refreshed in the background.
func NewAuthenticator(ctx context.Context, cfg config.AuthConfig) (*Authenticator, error) {
	a := &Authenticator{cfg: cfg}

	if cfg.JWKSURL != "" {
		cache, err := jwk.NewCache(ctx, httprc.NewClient())
		if err != nil {
			return nil, fmt.Errorf("auth: failed to create JWKS cache: %w", err)
		}
		if err := cache.Register(ctx, cfg.JWKSURL, jwk.WithMinInterval(15*time.Minute)); err != nil {
			return nil, fmt.Errorf("auth: failed to register JWKS endpoint %s: %w", cfg.JWKSURL, err)
		}
		a.cache = cache
	}

	// A build with neither is still valid: local accounts sign in with a
	// password and a session cookie, which needs no token verification at all.
	// What must not happen is a *token* arriving with nothing to check it
	// against, and Verify refuses that case on its own.

	return a, nil
}

// WithUserDirectory makes CertPilot's own users table the authority on role.
//
// Separate from the constructor because the authenticator is built before the
// store is opened, and because the middleware package's own tests exercise
// token verification with no database at all.
func (a *Authenticator) WithUserDirectory(dir UserDirectory) *Authenticator {
	a.users = dir
	return a
}

// Middleware returns the Gin handler that authenticates each request.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// An earlier middleware may already have established an identity — in
		// practice, a display token. That path grants nothing but read-only
		// viewer access and enforces its own restrictions, so there is nothing
		// left to check here.
		if c.GetString(ContextAuthMethod) != "" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			// No anonymous fallback. There used to be one, gated to
			// development mode on a loopback address, and the gate worked —
			// but running every local session as an unnamed superuser made the
			// authorisation paths the least exercised code in the system, and
			// wrote an audit log attributing everything to a subject nobody
			// could be asked about. Sign in locally instead; it costs one
			// password and buys a system that is exercised the way it ships.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "this request carried no credential: sign in, or present a bearer token or display token",
			})
			return
		}

		tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || strings.TrimSpace(tokenString) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header must be of the form 'Bearer <token>'",
			})
			return
		}

		claims, err := a.Verify(c.Request.Context(), tokenString)
		if err != nil {
			// The reason is deliberately not echoed back: it tells an attacker
			// which part of their forgery to fix.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			return
		}

		c.Set(ContextUserID, claims.Subject)
		c.Set(ContextUserEmail, claims.Email)
		c.Set(ContextAuthMethod, AuthMethodBearer)

		if a.users == nil {
			// No directory configured: the token's own claim is the only
			// available answer.
			c.Set(ContextUserRole, claims.Role(a.cfg.RoleClaim))
			c.Next()
			return
		}

		user, err := a.users.ResolveUser(c.Request.Context(), store.UserIdentity{
			// The issuer from the token, not from configuration. A subject is
			// unique only within the issuer that minted it, and taking the
			// issuer from config would merge two providers' users if an
			// operator ever pointed the core at a second one.
			Issuer:      identityIssuer(claims, a.cfg.Issuer),
			Subject:     claims.Subject,
			Email:       claims.Email,
			DisplayName: claims.DisplayName(),
		}, a.cfg.BootstrapAdmins)
		if err != nil {
			// Fail closed. A role that cannot be established is not a role,
			// and defaulting to viewer here would silently strip an operator
			// mid-incident rather than telling them the lookup broke.
			slog.Error("could not resolve the signed-in user", "error", err, "subject", claims.Subject)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "your identity could not be resolved against CertPilot's user directory, " +
					"so no role could be established for this request",
			})
			return
		}

		if !user.IsActive() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "this account is suspended in CertPilot; the identity provider still " +
					"accepts it, so sign-in succeeds and every request is refused here",
			})
			return
		}

		c.Set(ContextUserRole, user.Role)
		c.Set(ContextUserDBID, user.ID)
		if user.Email != "" {
			c.Set(ContextUserEmail, user.Email)
		}

		// Best effort: being unable to record a timestamp is not a reason to
		// refuse a request that is otherwise fully authorised.
		if err := a.users.TouchUser(c.Request.Context(), user.ID, time.Now()); err != nil {
			slog.Warn("could not record last-seen", "error", err, "user_id", user.ID)
		}

		c.Next()
	}
}

// Verify validates a token and returns its claims.
func (a *Authenticator) Verify(ctx context.Context, tokenString string) (*UserClaims, error) {
	claims := &UserClaims{}

	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
	}
	if a.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(a.cfg.Issuer))
	}
	if a.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(a.cfg.Audience))
	}

	// Pinning the accepted algorithms is what stops an attacker swapping the
	// header to "none", or to HS256 signed with the public key of an RS256
	// keypair.
	var allowed []string
	if a.cache != nil {
		allowed = append(allowed, "RS256", "RS512", "ES256", "ES384", "ES512", "EdDSA")
	}
	if a.cfg.JWTSecret != "" {
		allowed = append(allowed, "HS256")
	}
	opts = append(opts, jwt.WithValidMethods(allowed))

	token, err := jwt.ParseWithClaims(tokenString, claims, a.keyFunc(ctx), opts...)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("auth: token is not valid")
	}

	return claims, nil
}

// VerifyIDToken validates an ID token returned by an authorization code
// exchange.
//
// Separate from Verify because an ID token is a different document with
// different rules, and conflating them is how audience checks get skipped. Its
// audience is the *client id* — not the API audience an access token carries —
// so verifying one with the other's expectations either rejects every valid
// token or, worse, accepts a token minted for a different application.
//
// The nonce is required and compared here. It is the only thing tying the token
// to the browser that started this particular sign-in; a provider will happily
// re-issue an ID token that is valid in every other respect.
func (a *Authenticator) VerifyIDToken(ctx context.Context, tokenString, clientID, nonce string) (*UserClaims, error) {
	if clientID == "" {
		return nil, fmt.Errorf("auth: no client id is configured, so an ID token cannot be verified")
	}
	if nonce == "" {
		return nil, fmt.Errorf("auth: this sign-in carried no nonce, so its ID token cannot be tied to it")
	}

	claims := &UserClaims{}
	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
		jwt.WithAudience(clientID),
		// Pinned for the same reason as in Verify: an unpinned parser accepts
		// "none", and accepts HS256 signed with the public half of an RS256
		// keypair.
		jwt.WithValidMethods([]string{"RS256", "RS512", "ES256", "ES384", "ES512", "EdDSA"}),
	}
	if a.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(a.cfg.Issuer))
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, a.keyFunc(ctx), opts...)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("auth: ID token is not valid")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("auth: the ID token's nonce does not match the sign-in that requested it")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("auth: the ID token carries no subject, so there is nobody to sign in")
	}
	return claims, nil
}

// ResolveIdentity turns verified claims into a CertPilot user.
//
// Shared with the middleware so that a federated sign-in and a federated
// request establish identity by exactly the same rules — including taking the
// issuer from the token rather than from configuration.
func (a *Authenticator) ResolveIdentity(ctx context.Context, claims *UserClaims) (*store.User, error) {
	if a.users == nil {
		return nil, fmt.Errorf("auth: no user directory is configured")
	}
	return a.users.ResolveUser(ctx, store.UserIdentity{
		Issuer:      identityIssuer(claims, a.cfg.Issuer),
		Subject:     claims.Subject,
		Email:       claims.Email,
		DisplayName: claims.DisplayName(),
	}, a.cfg.BootstrapAdmins)
}

func (a *Authenticator) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, isHMAC := token.Method.(*jwt.SigningMethodHMAC); isHMAC {
			if a.cfg.JWTSecret == "" {
				return nil, fmt.Errorf("auth: HMAC-signed token presented but no shared secret is configured")
			}
			return []byte(a.cfg.JWTSecret), nil
		}

		if a.cache == nil {
			return nil, fmt.Errorf("auth: asymmetrically signed token presented but no JWKS endpoint is configured")
		}

		set, err := a.cache.Lookup(ctx, a.cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("auth: failed to fetch JWKS: %w", err)
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("auth: token header has no key ID")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("auth: no key in the JWKS matches key ID %q", kid)
		}

		var pubKey any
		if err := jwk.Export(key, &pubKey); err != nil {
			return nil, fmt.Errorf("auth: failed to export signing key: %w", err)
		}
		return pubKey, nil
	}
}

// RequireRole enforces that the authenticated user holds one of the allowed
// roles. Admin passes every check.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString(ContextUserRole)
		if role == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No role in request context"})
			return
		}

		if role == RoleAdmin {
			c.Next()
			return
		}
		for _, allowed := range allowedRoles {
			if role == allowed {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Role %q is not permitted to perform this operation", role),
		})
	}
}

// CORS restricts browser access to the configured origins.
//
// The previous implementation paired a wildcard origin with credentials, a
// combination the Fetch specification rejects outright — so it did not work in
// any browser while looking permissive enough to discourage anyone from
// checking.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimSuffix(strings.TrimSpace(o), "/")] = true
	}

	return func(c *gin.Context) {
		origin := strings.TrimSuffix(c.GetHeader("Origin"), "/")

		if origin != "" && allowed[origin] {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Headers",
				"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Origin, Cache-Control, X-Requested-With")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Max-Age", "600")
			// Responses vary by origin, so caches must not share them.
			h.Add("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeaders sets conservative response headers for an API that serves
// certificate material.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Nothing this API returns should ever be stored by an intermediary.
		h.Set("Cache-Control", "no-store")
		c.Next()
	}
}
