package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
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

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cert == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such certificate"})
		return
	}
	if cert.Status == "REVOKED" {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "this certificate is already revoked",
			"revoked_at": cert.RevokedAt,
		})
		return
	}
	if cert.CertificatePEM == nil || *cert.CertificatePEM == "" {
		// Discovered certificates can reach here with no PEM stored. A CA
		// cannot be asked to revoke a certificate that cannot be shown to it.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "CertPilot holds no copy of this certificate, so it cannot ask a CA to revoke it. " +
				"Revoke it directly at the issuing CA",
		})
		return
	}
	if cert.CAAccountID == nil || *cert.CAAccountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this certificate is not bound to a CA account, so there is nowhere to send a revocation. " +
				"It was most likely discovered rather than issued here",
		})
		return
	}

	caAccount, err := h.store.GetCAAccount(c.Request.Context(), *cert.CAAccountID)
	if err != nil || caAccount == nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "the CA account this certificate was issued by could not be read",
		})
		return
	}

	gw, err := h.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		gw, err = h.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			// Deliberately not recorded as revoked. An unreachable gateway
			// means the CA has not been told, and marking it here would leave
			// a certificate that reads REVOKED in the console and answers
			// handshakes in production.
			c.JSON(http.StatusBadGateway, gin.H{
				"error": fmt.Sprintf("gateway for CA %s is not connected, so the CA has not been told; "+
					"nothing has been changed", caAccount.Name),
			})
			return
		}
	}

	providerConfig, err := h.decryptCAConfig(caAccount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resp, err := gw.Client.RevokeCertificate(c.Request.Context(), &providerv1.RevokeCertificateRequest{
		CertificatePem:        []byte(*cert.CertificatePEM),
		ProviderCertificateId: cert.FingerprintSHA256,
		Reason:                int32(*input.Reason),
		ProviderConfig:        providerConfig,
	})
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("the CA refused the revocation, so nothing has been changed: %v", err),
		})
		return
	}
	if !resp.Success {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("the CA did not revoke this certificate, so nothing has been changed: %s",
				resp.Message),
		})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	revoked, err := h.store.MarkCertificateRevoked(c.Request.Context(), id, *input.Reason, actorID)
	if err != nil {
		// The CA has revoked it and CertPilot could not write that down. This
		// is the one genuinely dangerous outcome here, so it is stated plainly
		// rather than reported as a generic failure: the estate is now safe and
		// the record is wrong, which is the opposite of the usual problem.
		slog.Error("the CA revoked a certificate but the record could not be updated",
			"error", err, "certificate_id", id, "common_name", cert.CommonName)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "the CA has revoked this certificate, but CertPilot could not record it. " +
				"The certificate is no longer valid; this record will be wrong until the write succeeds",
		})
		return
	}
	if revoked == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "this certificate is already revoked"})
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
