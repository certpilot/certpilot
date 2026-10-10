package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// CTHandler manages Certificate Transparency monitoring.
type CTHandler struct {
	store   store.Store
	monitor *ctlog.Monitor
}

// NewCTHandler creates the handler.
func NewCTHandler(s store.Store, m *ctlog.Monitor) *CTHandler {
	return &CTHandler{store: s, monitor: m}
}

// ListMonitors handles GET /api/v1/ct/monitors.
//
// Every monitor carries `last_checked_at` *and* `last_success_at`, plus a
// `stale` flag derived from them. Reporting only "last checked" would let a
// monitor that has been unable to reach the log for a week read exactly like
// one that has found nothing for a week — and one of those means nobody is
// being told about certificates issued in their name.
func (h *CTHandler) ListMonitors(c *gin.Context) {
	monitors, err := h.store.ListCTMonitors(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	stale := make([]string, 0)
	for _, m := range monitors {
		if m.Stale(now) {
			stale = append(stale, m.Domain)
		}
	}

	body := gin.H{
		"data":                 monitors,
		"total":                len(monitors),
		"min_interval_minutes": ctlog.MinCheckIntervalMinutes,
		"stale_domains":        stale,
	}
	if len(stale) > 0 {
		body["warning"] = fmt.Sprintf(
			"%d domain(s) have not been checked successfully in some time: %s. Nothing is watching them for certificates issued in your name.",
			len(stale), strings.Join(stale, ", "))
	}
	c.JSON(http.StatusOK, body)
}

type ctMonitorRequest struct {
	Domain            string `json:"domain" binding:"required"`
	IncludeSubdomains *bool  `json:"include_subdomains"`
	IsEnabled         *bool  `json:"is_enabled"`
	// CheckIntervalMinutes defaults to six hours. Certificates appear in the
	// logs within minutes of issuance, but nobody acts on this within minutes,
	// and the index is a service somebody else pays for.
	CheckIntervalMinutes int `json:"check_interval_minutes"`
}

// CreateMonitor handles POST /api/v1/ct/monitors.
func (h *CTHandler) CreateMonitor(c *gin.Context) {
	var req ctMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	monitor := &store.CTMonitor{
		Domain:               req.Domain,
		IncludeSubdomains:    true,
		IsEnabled:            true,
		CheckIntervalMinutes: req.CheckIntervalMinutes,
	}
	if monitor.CheckIntervalMinutes == 0 {
		monitor.CheckIntervalMinutes = 360
	}
	if req.IncludeSubdomains != nil {
		monitor.IncludeSubdomains = *req.IncludeSubdomains
	}
	if req.IsEnabled != nil {
		monitor.IsEnabled = *req.IsEnabled
	}

	if err := ctlog.ValidateMonitor(monitor); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	if actorID != "" {
		monitor.CreatedBy = &actorID
	}

	if err := h.store.CreateCTMonitor(c.Request.Context(), monitor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "ct.monitor_created", monitor)

	c.JSON(http.StatusCreated, gin.H{
		"data": monitor,
		"next": "The first check runs within the minute and will report everything currently in the logs for this domain. " +
			"Expect that first run to be long; later ones only report what is new.",
	})
}

// UpdateMonitor handles PUT /api/v1/ct/monitors/:id.
func (h *CTHandler) UpdateMonitor(c *gin.Context) {
	id := c.Param("id")

	monitor, err := h.store.GetCTMonitor(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "CT monitor")
		return
	}

	var req ctMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	monitor.Domain = req.Domain
	if req.CheckIntervalMinutes > 0 {
		monitor.CheckIntervalMinutes = req.CheckIntervalMinutes
	}
	if req.IncludeSubdomains != nil {
		monitor.IncludeSubdomains = *req.IncludeSubdomains
	}
	if req.IsEnabled != nil {
		monitor.IsEnabled = *req.IsEnabled
	}

	if err := ctlog.ValidateMonitor(monitor); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.UpdateCTMonitor(c.Request.Context(), monitor); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "ct.monitor_updated", monitor)
	c.JSON(http.StatusOK, gin.H{"data": monitor})
}

// DeleteMonitor handles DELETE /api/v1/ct/monitors/:id.
func (h *CTHandler) DeleteMonitor(c *gin.Context) {
	id := c.Param("id")

	monitor, err := h.store.GetCTMonitor(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "CT monitor")
		return
	}
	if err := h.store.DeleteCTMonitor(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "ct.monitor_deleted", monitor)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"No longer watching %s. Certificates issued for it will not be reported.", monitor.Domain),
	})
}

// CheckMonitor handles POST /api/v1/ct/monitors/:id/check — poll it now.
//
// Synchronous, because the answer is the point: somebody who has just added a
// domain wants to see what is out there, and a 202 would leave them refreshing
// a list to find out whether the query even worked.
func (h *CTHandler) CheckMonitor(c *gin.Context) {
	id := c.Param("id")

	monitor, err := h.store.GetCTMonitor(c.Request.Context(), id)
	if err != nil {
		respondLookup(c, err, "CT monitor")
		return
	}

	// Bounded well under the HTTP server's 30-second write timeout.
	//
	// Found by running this against a real index: the first check of a busy
	// domain can take longer than that, and the server then cuts the response
	// off mid-write. The caller gets an empty body — which reads as "nothing
	// happened", the one conclusion that must never be reachable by accident.
	// The background poller keeps its longer budget, because nobody is waiting
	// on it.
	checkCtx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	h.monitor.Check(checkCtx, monitor)

	// Re-read: Check records the outcome, and the outcome is what the caller
	// needs — including that it failed.
	updated, err := h.store.GetCTMonitor(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if updated.LastError != "" {
		// 502, not 500: CertPilot worked, the transparency index did not, and
		// the distinction is the whole content of the answer.
		c.JSON(http.StatusBadGateway, gin.H{
			"data":  updated,
			"error": updated.LastError,
			"message": "The check did not complete, so nothing was learned about this domain. " +
				"It is not the same as finding no certificates.",
		})
		return
	}

	certs, total, err := h.store.ListCTCertificates(c.Request.Context(), store.CTCertificateFilter{
		MonitorID: id, ExcludePrecertificates: true, Limit: 50,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    updated,
		"found":   certs,
		"total":   total,
		"summary": summarizeCT(updated, total),
	})
}

// ListCertificates handles GET /api/v1/ct/certificates.
func (h *CTHandler) ListCertificates(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filter := store.CTCertificateFilter{
		MonitorID:       c.Query("monitor_id"),
		ManagementState: strings.ToUpper(c.Query("management_state")),
		// A precertificate and its final certificate are two log entries for
		// one certificate. Counting both doubles every finding, so the default
		// hides the pre-issuance entry when the real one is present.
		ExcludePrecertificates: c.DefaultQuery("include_precertificates", "false") != "true",
		Limit:                  limit,
		Offset:                 offset,
	}

	certs, total, err := h.store.ListCTCertificates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": certs, "total": total})
}

// summarizeCT states the outcome in a sentence, because the counts alone cannot
// distinguish "we looked and found nothing" from "we could not look".
func summarizeCT(monitor *store.CTMonitor, total int64) string {
	switch {
	case monitor.LastSuccessAt == nil:
		return fmt.Sprintf("%s has never been checked successfully, so nothing is known about what has been issued for it.", monitor.Domain)
	case monitor.UnmanagedSeen > 0:
		return fmt.Sprintf(
			"%d certificate(s) have been issued for %s that CertPilot did not issue and does not manage. Somebody holds their private keys.",
			monitor.UnmanagedSeen, monitor.Domain)
	case total == 0:
		return fmt.Sprintf("The logs report no unexpired certificates for %s.", monitor.Domain)
	default:
		return fmt.Sprintf("All %d certificate(s) the logs report for %s are ones CertPilot manages.", total, monitor.Domain)
	}
}

func (h *CTHandler) audit(c *gin.Context, action string, monitor *store.CTMonitor) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := monitor.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "ct_monitor",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"domain":%q,"include_subdomains":%t,"interval_minutes":%d,"enabled":%t}`,
			monitor.Domain, monitor.IncludeSubdomains, monitor.CheckIntervalMinutes, monitor.IsEnabled),
	})
}
