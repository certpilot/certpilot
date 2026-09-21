package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// DisplayTokenPrefix marks a raw kiosk token.
//
// A fixed, distinctive prefix is what makes a leaked token findable: secret
// scanners can match it, and anyone grepping a log or a config file recognises
// what they are looking at rather than seeing anonymous base64.
const DisplayTokenPrefix = "cpd_"

// displayTokenEntropyBytes is the size of the random part of a token. 256 bits
// puts brute force out of reach without a rate limiter having to be the thing
// standing between a corridor screen and the API.
const displayTokenEntropyBytes = 32

// displayTokenTouchInterval throttles last-seen writes.
//
// The field exists to make a leaked token visible, which minute-granularity
// answers just as well as per-request precision — and per-request precision
// would mean a database write on every poll from every screen.
const displayTokenTouchInterval = time.Minute

// Context key holding the ID of the display token that authenticated a request,
// when one did.
const ContextDisplayTokenID = "display_token_id"

// DisplayTokenStore is the slice of the store this middleware needs.
//
// Narrowed to two methods so the authentication path cannot reach anything that
// writes certificates or CAs, and so its tests do not need a full store.
type DisplayTokenStore interface {
	GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*store.DisplayToken, error)
	TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error
}

// GenerateDisplayToken returns a new raw token and its hash.
//
// The raw value is returned to the caller once and never persisted; only the
// hash goes to the database.
func GenerateDisplayToken() (raw, hash string, err error) {
	buf := make([]byte, displayTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("could not generate a display token: %w", err)
	}
	raw = DisplayTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashDisplayToken(raw), nil
}

// HashDisplayToken returns the hex-encoded SHA-256 of a raw token.
//
// SHA-256 rather than a password hash is deliberate. A password hash is slow on
// purpose because passwords are guessable; a token is 256 bits of CSPRNG output
// with no dictionary behind it, so the slowness would buy nothing and would be
// paid on every request. It would also force the lookup to scan every row
// instead of hitting an index.
func HashDisplayToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// displayTokenForbiddenPaths are refused even on GET.
//
// The role gate on these routes already stops a viewer, so this is a second,
// independent barrier: if a future change loosens one of those gates, a
// credential sitting on an unattended screen still cannot reach it.
var displayTokenForbiddenPaths = []string{
	// Removing a private key from the system's custody is the single most
	// sensitive operation the API has.
	"/private-key",
	// A kiosk enumerating kiosk credentials is the pivot that turns one leaked
	// screen token into knowledge of every other screen.
	"/display-tokens",
	// The activity feed carries actor identity. "alice@example.com deleted a
	// certificate" is not something to put on a screen in a corridor.
	"/dashboard/activity",
}

// DisplayTokenAuth authenticates unattended screens.
//
// It runs ahead of bearer authentication and takes effect only when a display
// token is presented and no Authorization header is. Three properties are
// enforced here rather than per-route, because a rule that has to be remembered
// at every call site is a rule that will eventually be forgotten at one:
//
//   - the role granted is the constant RoleViewer, not derived from any input;
//   - anything but GET is refused, whatever the route;
//   - the paths above are refused, whatever their own role gate says.
//
// An invalid token aborts rather than falling through. That mattered most when
// anonymous access was still available for local evaluation, because falling
// through would have handed a rejected token an admin identity; it is kept
// because "invalid credential" and "no credential" are different answers.
func DisplayTokenAuth(st DisplayTokenStore) gin.HandlerFunc {
	seen := &lastSeenTracker{at: make(map[string]time.Time)}

	return func(c *gin.Context) {
		// A real session takes precedence, so that a display token left in a
		// bookmark cannot quietly mask an operator's identity in the audit log.
		if c.GetHeader("Authorization") != "" {
			c.Next()
			return
		}

		raw := displayTokenFromRequest(c)
		if raw == "" {
			c.Next()
			return
		}

		if c.Request.Method != http.MethodGet {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "display tokens are read-only and may not be used for this operation",
			})
			return
		}

		if forbiddenForDisplayToken(c.Request.URL.Path) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "display tokens may not access this resource",
			})
			return
		}

		hash := HashDisplayToken(raw)
		tok, err := st.GetDisplayTokenByHash(c.Request.Context(), hash)
		if err != nil || tok == nil {
			rejectDisplayToken(c, "unknown")
			return
		}
		// Belt and braces over the store's own lookup, and the real comparison
		// for any implementation that resolves tokens by scanning.
		if subtle.ConstantTimeCompare([]byte(tok.TokenHash), []byte(hash)) != 1 {
			rejectDisplayToken(c, "hash mismatch")
			return
		}

		now := time.Now()
		if !tok.IsUsable(now) {
			// Logged with the distinction, returned without it: an operator
			// needs to know a revoked screen is still calling, while the caller
			// learns only that it failed.
			rejectDisplayToken(c, strings.ToLower(tok.Status(now)))
			return
		}

		c.Set(ContextUserID, "display-token:"+tok.ID)
		c.Set(ContextUserEmail, "display:"+tok.Name)
		c.Set(ContextUserRole, RoleViewer)
		c.Set(ContextAuthMethod, AuthMethodDisplayToken)
		c.Set(ContextDisplayTokenID, tok.ID)

		seen.record(c.Request.Context(), st, tok.ID, now, c.ClientIP())
		c.Next()
	}
}

func rejectDisplayToken(c *gin.Context, reason string) {
	slog.Warn("display token rejected", "reason", reason,
		"path", c.Request.URL.Path, "client_ip", c.ClientIP())
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error": "invalid or expired display token",
	})
}

// displayTokenFromRequest reads the token from a header, or from the query
// string for clients that cannot set one.
//
// The query parameter exists solely for EventSource, which has no way to send
// headers. It is the weaker channel — query strings reach access logs and
// referrers — which is why RequestLogger redacts it, and why this credential
// grants nothing but read access in the first place.
func displayTokenFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader("X-Display-Token")); v != "" {
		return v
	}
	return strings.TrimSpace(c.Query("display_token"))
}

func forbiddenForDisplayToken(path string) bool {
	for _, forbidden := range displayTokenForbiddenPaths {
		if strings.Contains(path, forbidden) {
			return true
		}
	}
	return false
}

// lastSeenTracker throttles last-seen writes and performs them off the request
// path.
type lastSeenTracker struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (t *lastSeenTracker) record(reqCtx context.Context, st DisplayTokenStore, id string, now time.Time, ip string) {
	t.mu.Lock()
	if last, ok := t.at[id]; ok && now.Sub(last) < displayTokenTouchInterval {
		t.mu.Unlock()
		return
	}
	t.at[id] = now
	t.mu.Unlock()

	// WithoutCancel because the write outlives the request that triggered it —
	// on a long-lived event stream in particular, the request context is not
	// done until the screen disconnects, and on a short one it is done almost
	// immediately.
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), 5*time.Second)
		defer cancel()
		if err := st.TouchDisplayToken(ctx, id, now, ip); err != nil {
			slog.Warn("could not record display token last-seen", "token_id", id, "error", err)
		}
	}()
}
