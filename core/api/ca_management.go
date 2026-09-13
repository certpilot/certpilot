package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// CAHandler handles CA inventory, health inspection, and trust chain resolution.
type CAHandler struct {
	store         store.Store
	caMonitor     *pki.CAMonitor
	caImporter    *pki.Importer
	chainResolver *pki.ChainResolver
}

// NewCAHandler creates a new CAHandler.
func NewCAHandler(s store.Store, mon *pki.CAMonitor, imp *pki.Importer, cr *pki.ChainResolver) *CAHandler {
	return &CAHandler{
		store:         s,
		caMonitor:     mon,
		caImporter:    imp,
		chainResolver: cr,
	}
}

// ImportIssuers handles POST /api/v1/pki/authorities/import.
//
// The importer runs on a timer, and twelve hours is a long time to wait to see
// whether a CA account's issuers arrived. This is the same sweep, on demand,
// reporting what it did rather than what it found — an operator who has just
// rotated a Vault issuer wants to know it was recorded, not to read a list.
func (h *CAHandler) ImportIssuers(c *gin.Context) {
	if h.caImporter == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the issuer importer is not running"})
		return
	}
	if unknown := unexpectedQuery(c, "account"); unknown != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf(
			"%q is not a parameter this endpoint understands", unknown)})
		return
	}

	ctx := c.Request.Context()
	var results []pki.Result

	if name := strings.TrimSpace(c.Query("account")); name != "" {
		accounts, err := h.store.ListCAAccounts(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var target *store.CAAccount
		for _, account := range accounts {
			if account.Name == name || account.ID == name {
				target = account
				break
			}
		}
		if target == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no CA account named %q", name)})
			return
		}
		results = []pki.Result{h.caImporter.ImportAccount(ctx, target)}
	} else {
		var err error
		results, err = h.caImporter.SweepAll(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	added, refreshed := 0, 0
	for _, result := range results {
		added += result.Added()
		refreshed += result.Refreshed()
	}
	c.JSON(http.StatusOK, gin.H{
		"data":    results,
		"summary": gin.H{"added": added, "refreshed": refreshed},
	})
}

// List handles GET /api/v1/pki/authorities.
//
// Supports `status`, `expiring_within_days`, and `sort=urgency|name`. The
// urgency ordering is what the CA health view is built on: for a team watching
// a wall display the useful question is which CA fails first, and an
// alphabetical list answers a different one.
func (h *CAHandler) List(c *gin.Context) {
	filter := store.CAFilter{
		Status: strings.ToUpper(c.Query("status")),
		Sort:   c.Query("sort"),
		// The certificate PEM is several kilobytes per CA and no client renders
		// it. The detail endpoint still returns it.
		IncludePEM: false,
	}
	if raw := c.Query("expiring_within_days"); raw != "" {
		days, err := strconv.Atoi(raw)
		if err != nil || days < 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "expiring_within_days must be a non-negative whole number of days",
			})
			return
		}
		filter.ExpiringWithinDays = days
	}

	cas, err := h.store.ListCAAuthorities(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.attachAcknowledgements(c.Request.Context(), cas)
	c.JSON(http.StatusOK, gin.H{"data": cas, "total": len(cas)})
}

// attachAcknowledgements resolves who has already looked at each CA.
//
// Resolved for the whole page in one query rather than one per row. It is
// attached to the *list* on purpose: acknowledgement has to be visible wherever
// the CA is, because an acknowledged CA still appears — that is the difference
// between "someone is handling this" and a row silently disappearing.
//
// A failure here degrades to showing no acknowledgements rather than failing the
// request. Losing the annotation costs a reader some context; losing the CA list
// costs them the dashboard.
func (h *CAHandler) attachAcknowledgements(ctx context.Context, cas []*store.CAAuthority) {
	if len(cas) == 0 {
		return
	}

	ids := make([]string, 0, len(cas))
	for _, ca := range cas {
		ids = append(ids, ca.ID)
	}

	acks, err := h.store.GetActiveAcknowledgements(ctx, store.AckEntityCAAuthority, ids)
	if err != nil {
		slog.Warn("could not resolve CA acknowledgements", "error", err)
		return
	}

	now := time.Now()
	for _, ca := range cas {
		ack := acks[ca.ID]
		// Checked against the CA's *current* threshold: an acknowledgement made
		// at 30 days does not describe a CA that has since crossed 7. Showing it
		// as still acknowledged would be the exact false reassurance this
		// feature is supposed to avoid creating.
		if ack.IsActive(now, ca.LastAlertThreshold) {
			ca.Acknowledgement = ack
		}
	}
}

// Get handles GET /api/v1/pki/authorities/:id.
func (h *CAHandler) Get(c *gin.Context) {
	id := c.Param("id")
	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.attachAcknowledgements(c.Request.Context(), []*store.CAAuthority{ca})
	c.JSON(http.StatusOK, ca)
}

// HierarchyTree handles GET /api/v1/pki/tree.
func (h *CAHandler) HierarchyTree(c *gin.Context) {
	tree, err := h.chainResolver.BuildHierarchyTree(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tree})
}

// Chain handles GET /api/v1/pki/authorities/:id/chain.
func (h *CAHandler) Chain(c *gin.Context) {
	id := c.Param("id")
	chain, err := h.store.GetCAChain(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": chain})
}

// CreateCAInput represents the payload to register a new CA Authority.
type CreateCAInput struct {
	Name               string  `json:"name" binding:"required"`
	CertificatePEM     string  `json:"certificate_pem" binding:"required"`
	ParentCAID         *string `json:"parent_ca_id"`
	CAAccountID        *string `json:"ca_account_id"`
	CRLDistributionURL string  `json:"crl_distribution_url"`
	OCSPResponderURL   string  `json:"ocsp_responder_url"`
	Notes              string  `json:"notes"`
}

// Create handles POST /api/v1/pki/authorities.
func (h *CAHandler) Create(c *gin.Context) {
	var input CreateCAInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse CA certificate
	certInfo, err := x509util.ParseCertificatePEM([]byte(input.CertificatePEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid certificate PEM: %v", err)})
		return
	}

	caType := "ROOT"
	if input.ParentCAID != nil && *input.ParentCAID != "" {
		caType = "INTERMEDIATE"
	}

	crlURL := input.CRLDistributionURL
	if crlURL == "" && len(certInfo.CRLURLs) > 0 {
		crlURL = certInfo.CRLURLs[0]
	}

	ocspURL := input.OCSPResponderURL
	if ocspURL == "" && len(certInfo.OCSPURLs) > 0 {
		ocspURL = certInfo.OCSPURLs[0]
	}

	ca := &store.CAAuthority{
		Name:               input.Name,
		CAType:             caType,
		SubjectDN:          certInfo.SubjectDN,
		IssuerDN:           certInfo.IssuerDN,
		SerialNumber:       certInfo.SerialNumber,
		NotBefore:          certInfo.NotBefore,
		NotAfter:           certInfo.NotAfter,
		DaysRemaining:      certInfo.DaysRemaining,
		KeyType:            certInfo.KeyType,
		KeySize:            certInfo.KeySize,
		FingerprintSHA256:  certInfo.FingerprintSHA256,
		CertificatePEM:     input.CertificatePEM,
		ParentCAID:         input.ParentCAID,
		CRLDistributionURL: crlURL,
		OCSPResponderURL:   ocspURL,
		CAAccountID:        input.CAAccountID,
		Status:             "HEALTHY",
		Notes:              input.Notes,
	}

	if certInfo.DaysRemaining <= 30 {
		ca.Status = "CRITICAL"
	} else if certInfo.DaysRemaining <= 180 {
		ca.Status = "WARNING"
	}

	if err := h.store.CreateCAAuthority(c.Request.Context(), ca); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save CA authority: %v", err)})
		return
	}

	// Run the first health check in the background so CRL and OCSP state is
	// populated without making the operator wait on network round trips.
	//
	// The context must be detached from the request: c.Request.Context() is
	// cancelled the moment this handler returns, so the check was racing a dead
	// context and almost always aborted before reaching the CRL endpoint.
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 2*time.Minute)
	go func() {
		defer cancel()
		if err := h.caMonitor.CheckCA(checkCtx, ca); err != nil {
			slog.Warn("initial CA health check failed", "ca_name", ca.Name, "error", err)
		}
	}()

	c.JSON(http.StatusCreated, ca)
}

// CheckHealth handles POST /api/v1/pki/authorities/:id/check.
func (h *CAHandler) CheckHealth(c *gin.Context) {
	id := c.Param("id")
	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.caMonitor.CheckCA(c.Request.Context(), ca); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ca)
}

// Delete handles DELETE /api/v1/pki/authorities/:id.
func (h *CAHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCAAuthority(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "CA authority removed"})
}
