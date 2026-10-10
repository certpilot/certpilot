package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// Bounds on how long a kiosk credential may live.
//
// There is no unlimited option. A screen that outlives its token gets noticed
// and re-provisioned; a token that outlives its screen is a live credential
// nobody is watching, and that is the failure this whole feature is meant to
// avoid rather than introduce.
const (
	defaultDisplayTokenDays = 90
	maxDisplayTokenDays     = 365
)

// DisplayTokenHandler manages kiosk display credentials.
type DisplayTokenHandler struct {
	store store.Store
}

// NewDisplayTokenHandler creates the handler.
func NewDisplayTokenHandler(s store.Store) *DisplayTokenHandler {
	return &DisplayTokenHandler{store: s}
}

// displayTokenView is a token as returned to an API client: the stored record
// with its lifecycle state resolved, and without the hash.
type displayTokenView struct {
	*store.DisplayToken
	Status string `json:"status"`
}

func viewOf(t *store.DisplayToken, now time.Time) displayTokenView {
	return displayTokenView{DisplayToken: t, Status: t.Status(now)}
}

// List handles GET /api/v1/display-tokens.
func (h *DisplayTokenHandler) List(c *gin.Context) {
	tokens, err := h.store.ListDisplayTokens(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	views := make([]displayTokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, viewOf(t, now))
	}
	c.JSON(http.StatusOK, gin.H{"data": views, "total": len(views)})
}

type createDisplayTokenRequest struct {
	Name string `json:"name" binding:"required"`
	// ExpiresInDays defaults to 90 and is capped at 365.
	ExpiresInDays int `json:"expires_in_days"`
}

// Create handles POST /api/v1/display-tokens.
//
// The raw token is returned exactly once, in this response, and is not
// recoverable afterwards. That is the point: a credential the server can hand
// out again is a credential the server is storing.
func (h *DisplayTokenHandler) Create(c *gin.Context) {
	var req createDisplayTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "a name is required — it is what identifies which screen to revoke",
		})
		return
	}

	days := req.ExpiresInDays
	if days == 0 {
		days = defaultDisplayTokenDays
	}
	if days < 1 || days > maxDisplayTokenDays {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("expires_in_days must be between 1 and %d", maxDisplayTokenDays),
		})
		return
	}

	raw, hash, err := middleware.GenerateDisplayToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)

	token := &store.DisplayToken{
		Name:      req.Name,
		TokenHash: hash,
		ExpiresAt: time.Now().AddDate(0, 0, days),
		CreatedBy: &actorID,
	}
	if err := h.store.CreateDisplayToken(c.Request.Context(), token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "display_token.created",
		EntityType: "display_token",
		EntityID:   &token.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"name": %q, "expires_at": %q}`,
			token.Name, token.ExpiresAt.Format(time.RFC3339)),
	})

	c.JSON(http.StatusCreated, gin.H{
		"token":   raw,
		"display": viewOf(token, time.Now()),
		"warning": "This token is shown once and cannot be retrieved again. It grants read-only access to dashboard data — treat it as a credential and revoke it when the screen is decommissioned.",
	})
}

// Revoke handles DELETE /api/v1/display-tokens/:id.
//
// The row is kept and marked rather than deleted. A revoked kiosk credential is
// a thing someone will want to ask questions about later — when it was issued,
// when it was last used, and from where — and none of that survives a delete.
func (h *DisplayTokenHandler) Revoke(c *gin.Context) {
	id := c.Param("id")

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)

	if err := h.store.RevokeDisplayToken(c.Request.Context(), id, &actorID); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			slog.Error("could not revoke a display token", "id", id, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke the display token"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "display_token.revoked",
		EntityType: "display_token",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
	})

	c.JSON(http.StatusOK, gin.H{"message": "display token revoked"})
}
