package api

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// RevokeCertificateInput names the reason. It is required rather than
// defaulted: "unspecified" is a legitimate answer, but it should be one
// somebody chose, because the reason is what tells the next reader whether a
// key was compromised or a service was simply retired.
type RevokeCertificateInput struct {
	Reason *int `json:"reason" binding:"required"`
}

// Revoke handles POST /api/v1/certificates/:id/revoke.
//
// The CA is told first and CertPilot's record is updated only if it agrees.
// The opposite order is what the old DELETE effectively did: it removed the
// local record while the certificate stayed live and valid at the CA until its
// own notAfter, so the operation that appeared to deal with a compromised key
// was the one that made it invisible.
func (h *CertificateHandler) Revoke(c *gin.Context) {
	id := c.Param("id")

	var input RevokeCertificateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "a revocation reason is required: " + revocationReasonHelp(),
		})
		return
	}
	if !store.ValidRevocationReason(*input.Reason) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%d is not a revocation reason CertPilot accepts: %s",
				*input.Reason, revocationReasonHelp()),
		})
		return
	}

	// Both stores report a missing certificate as an error rather than a nil
	// result, so a 500 here told an operator who mistyped an id that the server
	// was broken. Every other handler in this package reads the same error as a
	// 404; this one did not, and nothing tested it. The nil branch is kept
	// because Store is an interface and the other convention is legal.
	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "certificate")
		return
	}
	if cert == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such certificate"})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	revoked, err := h.revoker.Revoke(c.Request.Context(), cert, *input.Reason, actorID)
	if err != nil {
		status := http.StatusInternalServerError
		body := gin.H{"error": err.Error()}
		if re, ok := issuance.AsRevokeError(err); ok {
			switch re.Kind {
			case issuance.RevokeBadReason, issuance.RevokeNotPossible:
				status = http.StatusBadRequest
			case issuance.RevokeAlreadyRevoked:
				status = http.StatusConflict
				if cert.RevokedAt != nil {
					body["revoked_at"] = cert.RevokedAt
				}
			case issuance.RevokeCANotTold:
				status = http.StatusBadGateway
			}
		}
		c.JSON(status, body)
		return
	}

	h.auditRevocation(c, revoked, *input.Reason, actorID)

	// Published so a wall display reflects it without waiting for a sweep. A
	// revocation is the one certificate event where the delay between it
	// happening and it being visible is the whole risk.
	if h.broker != nil {
		h.broker.Publish(events.Event{
			Topic:    "cert.revoked",
			Severity: "WARNING",
			EntityID: revoked.ID,
			Payload: map[string]any{
				"common_name": revoked.CommonName,
				"reason":      store.RevocationReasons[*input.Reason],
				"revoked_by":  actorID,
			},
			Timestamp: time.Now(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     fmt.Sprintf("revoked at the CA and recorded (%s)", store.RevocationReasons[*input.Reason]),
		"certificate": revoked,
	})
}

func (h *CertificateHandler) auditRevocation(c *gin.Context, cert *store.Certificate, reason int, actorID string) {
	ip := c.ClientIP()
	email := c.GetString(middleware.ContextUserEmail)

	entry := &store.AuditLog{
		Action:     "certificate.revoked",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    &actorID,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"common_name": %q, "reason": %q, "reason_code": %d, "fingerprint": %q}`,
			cert.CommonName, store.RevocationReasons[reason], reason, cert.FingerprintSHA256),
	}
	if email != "" {
		entry.ActorEmail = &email
	}
	_ = h.store.CreateAuditLog(c.Request.Context(), entry)
}

// revocationReasonHelp lists the accepted codes, so an operator reading a 400
// does not have to find RFC 5280 to fix their request.
func revocationReasonHelp() string {
	codes := make([]int, 0, len(store.RevocationReasons))
	for code := range store.RevocationReasons {
		codes = append(codes, code)
	}
	sort.Ints(codes)

	out := ""
	for i, code := range codes {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d=%s", code, store.RevocationReasons[code])
	}
	return out
}
