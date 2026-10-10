package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// maxSilenceDays bounds how long delivery can be suppressed.
//
// There is no indefinite option, deliberately. A permanent silence is
// indistinguishable from deleting the alert, and the CA it covers goes on
// expiring while the team believes it is monitored. Ninety days is long enough
// to cover a planned replacement and short enough that nobody forgets.
const maxSilenceDays = 90

// AcknowledgementHandler records that a human has seen an alert.
type AcknowledgementHandler struct {
	store store.Store
}

// NewAcknowledgementHandler creates the handler.
func NewAcknowledgementHandler(s store.Store) *AcknowledgementHandler {
	return &AcknowledgementHandler{store: s}
}

type acknowledgeRequest struct {
	// Note is why. The most useful field here: "replacement issued, cutover
	// Thursday" turns a red row from an unanswered alarm into a status, and is
	// what stops the next person re-investigating it.
	Note string `json:"note"`
	// SilenceDays suppresses *delivery* for this many days. Zero means
	// acknowledge without silencing, which is the common case: the alert stops
	// being new, and still goes out.
	SilenceDays int `json:"silence_days"`
	// Threshold pins the acknowledgement to one expiry threshold. Defaults to
	// the CA's current one, so a later, tighter threshold is not covered.
	Threshold *int `json:"threshold"`
}

// Acknowledge handles POST /api/v1/pki/authorities/:id/acknowledge.
//
// The rule this endpoint exists to uphold, stated once here because it is the
// thing most likely to be "simplified" later:
//
//	**Silencing suppresses delivery, never display.**
//
// An acknowledged CA still appears on the dashboard and in the wall view,
// marked as acknowledged and by whom. Nothing in this handler hides a row.
func (h *AcknowledgementHandler) Acknowledge(c *gin.Context) {
	id := c.Param("id")

	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "CA authority")
		return
	}

	var req acknowledgeRequest
	// An empty body is a valid acknowledgement — "seen, no note, no silence".
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	if req.SilenceDays < 0 || req.SilenceDays > maxSilenceDays {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"silence_days must be between 0 and %d; there is no indefinite silence, because a permanent one is indistinguishable from deleting the alert",
				maxSilenceDays),
		})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)

	ack := &store.AlertAcknowledgement{
		EntityType:          store.AckEntityCAAuthority,
		EntityID:            ca.ID,
		Note:                strings.TrimSpace(req.Note),
		AcknowledgedBy:      &actorID,
		AcknowledgedByEmail: &actorEmail,
	}

	// Default to the threshold the CA has actually alerted at. Without this an
	// acknowledgement would be unbounded and would cover every future alert,
	// including the 7-day one nobody has seen yet.
	ack.Threshold = req.Threshold
	if ack.Threshold == nil {
		ack.Threshold = ca.LastAlertThreshold
	}

	if req.SilenceDays > 0 {
		until := time.Now().AddDate(0, 0, req.SilenceDays)
		ack.SilenceUntil = &until
	}

	if err := h.store.CreateAcknowledgement(c.Request.Context(), ack); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca.acknowledged",
		EntityType: "ca_authority",
		EntityID:   &ca.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"ca_name":%q,"threshold":%s,"silence_days":%d,"note":%q}`,
			ca.Name, jsonInt(ack.Threshold), req.SilenceDays, ack.Note),
	})

	c.JSON(http.StatusCreated, gin.H{
		"data": ack,
		"note": acknowledgementEffect(ack),
	})
}

// acknowledgementEffect states in words exactly what was and was not changed,
// because "acknowledged" is ambiguous and the ambiguity is dangerous.
func acknowledgementEffect(ack *store.AlertAcknowledgement) string {
	var b strings.Builder
	b.WriteString("This certificate authority still appears on the dashboard and the wall display, now marked as acknowledged. ")

	if ack.SilenceUntil == nil {
		b.WriteString("Alerts continue to be delivered — acknowledging does not silence.")
		return b.String()
	}

	fmt.Fprintf(&b, "Delivery is suppressed until %s",
		ack.SilenceUntil.Format("2 January 2006 15:04 MST"))
	if ack.Threshold != nil {
		fmt.Fprintf(&b, ", but only for the %d-day threshold: if it crosses a tighter one, it alerts again", *ack.Threshold)
	}
	b.WriteString(".")
	return b.String()
}

// History handles GET /api/v1/pki/authorities/:id/acknowledgements.
func (h *AcknowledgementHandler) History(c *gin.Context) {
	id := c.Param("id")

	acks, err := h.store.ListAcknowledgements(c.Request.Context(), store.AckEntityCAAuthority, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": acks, "total": len(acks)})
}

// Withdraw handles DELETE /api/v1/pki/authorities/:id/acknowledge.
//
// Withdrawal marks rather than deletes. A CA that was acknowledged in error and
// then un-acknowledged is something an incident review wants to see, not a row
// that quietly disappeared.
func (h *AcknowledgementHandler) Withdraw(c *gin.Context) {
	id := c.Param("id")

	ack, err := h.store.GetActiveAcknowledgement(c.Request.Context(), store.AckEntityCAAuthority, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ack == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "this certificate authority is not acknowledged"})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)

	if err := h.store.RevokeAcknowledgement(c.Request.Context(), ack.ID, &actorID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca.acknowledgement_withdrawn",
		EntityType: "ca_authority",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
	})

	c.JSON(http.StatusOK, gin.H{"message": "acknowledgement withdrawn; alerts resume"})
}

type ownerRequest struct {
	// Both are free text and both are clearable by sending an empty string —
	// ownership moving to nobody is a real state, and one worth seeing on the
	// dashboard rather than silently keeping the old team's name.
	OwnerTeam  *string `json:"owner_team"`
	OwnerEmail *string `json:"owner_email"`
}

// SetOwner handles PUT /api/v1/pki/authorities/:id/owner.
func (h *AcknowledgementHandler) SetOwner(c *gin.Context) {
	id := c.Param("id")

	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "CA authority")
		return
	}

	var req ownerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.OwnerTeam != nil {
		ca.OwnerTeam = trimmedOrNil(*req.OwnerTeam)
	}
	if req.OwnerEmail != nil {
		email := strings.TrimSpace(*req.OwnerEmail)
		// Checked rather than trusted: this address is where someone goes
		// looking when a CA is hours from expiry, and a typo discovered then is
		// discovered too late.
		if email != "" && !strings.Contains(email, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("%q is not an email address", email)})
			return
		}
		ca.OwnerEmail = trimmedOrNil(email)
	}

	if err := h.store.UpdateCAAuthority(c.Request.Context(), ca); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca.owner_changed",
		EntityType: "ca_authority",
		EntityID:   &ca.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"ca_name":%q,"owner_team":%q,"owner_email":%q}`,
			ca.Name, derefOr(ca.OwnerTeam, ""), derefOr(ca.OwnerEmail, "")),
	})

	c.JSON(http.StatusOK, gin.H{"data": ca})
}

func trimmedOrNil(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func derefOr(s *string, or string) string {
	if s == nil {
		return or
	}
	return *s
}

// jsonInt renders an optional int for a JSON detail string.
func jsonInt(v *int) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%d", *v)
}
