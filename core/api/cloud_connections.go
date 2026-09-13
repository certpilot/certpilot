package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// CloudHandler manages cloud certificate inventory.
type CloudHandler struct {
	store   store.Store
	engine  *cloudsync.Engine
	keyring *secrets.Keyring
}

// NewCloudHandler creates the handler.
func NewCloudHandler(s store.Store, e *cloudsync.Engine, k *secrets.Keyring) *CloudHandler {
	return &CloudHandler{store: s, engine: e, keyring: k}
}

// ListConnections handles GET /api/v1/cloud/connections.
//
// Every connection carries `last_synced_at` *and* `last_success_at`, plus the
// scopes the last successful sync actually covered. Both are here for the same
// reason: a list of certificates is only as trustworthy as the account it came
// from, and "we could not reach this account" and "this account holds nothing"
// look identical unless something says otherwise.
func (h *CloudHandler) ListConnections(c *gin.Context) {
	connections, err := h.store.ListCloudConnections(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	stale := make([]string, 0)
	for _, conn := range connections {
		if conn.Stale(now) {
			stale = append(stale, conn.Name)
		}
	}

	body := gin.H{
		"data":                 connections,
		"total":                len(connections),
		"providers":            cloudsync.Providers(),
		"min_interval_minutes": cloudsync.MinSyncIntervalMinutes,
		"stale_connections":    stale,
	}
	if len(stale) > 0 {
		body["warning"] = fmt.Sprintf(
			"%d cloud connection(s) have not synced successfully in some time: %s. Whatever is stored in them is not being watched.",
			len(stale), strings.Join(stale, ", "))
	}
	c.JSON(http.StatusOK, body)
}

type cloudConnectionRequest struct {
	Name     string `json:"name" binding:"required"`
	Provider string `json:"provider" binding:"required"`
	// Config is the provider's credentials and coordinates. Sealed with the
	// keyring before it is stored and never returned by any handler.
	Config              map[string]any `json:"config"`
	IsEnabled           *bool          `json:"is_enabled"`
	SyncIntervalMinutes int            `json:"sync_interval_minutes"`
}

// CreateConnection handles POST /api/v1/cloud/connections.
func (h *CloudHandler) CreateConnection(c *gin.Context) {
	var req cloudConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn := &store.CloudConnection{
		Name:                req.Name,
		Provider:            req.Provider,
		IsEnabled:           true,
		SyncIntervalMinutes: req.SyncIntervalMinutes,
		Scopes:              []string{},
	}
	if conn.SyncIntervalMinutes == 0 {
		conn.SyncIntervalMinutes = 360
	}
	if req.IsEnabled != nil {
		conn.IsEnabled = *req.IsEnabled
	}

	if err := cloudsync.ValidateConnection(conn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validated before it is sealed, so a missing region or a malformed service
	// account key is a 400 now rather than a sync failure six hours from now
	// that reads on a dashboard like the account rejecting us.
	sealed, err := h.sealConfig(conn.Provider, req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	conn.ConfigEncrypted = sealed

	actorID := c.GetString(middleware.ContextUserID)
	if actorID != "" {
		conn.CreatedBy = &actorID
	}

	if err := h.store.CreateCloudConnection(c.Request.Context(), conn); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "cloud.connection_created", conn)

	c.JSON(http.StatusCreated, gin.H{
		"data": conn,
		"next": "The first sync runs within the minute. Use POST /cloud/connections/{id}/sync to run one now and see whether the credentials work.",
	})
}

// UpdateConnection handles PUT /api/v1/cloud/connections/:id.
func (h *CloudHandler) UpdateConnection(c *gin.Context) {
	id := c.Param("id")

	conn, err := h.store.GetCloudConnection(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req cloudConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conn.Name = req.Name
	conn.Provider = req.Provider
	if req.SyncIntervalMinutes > 0 {
		conn.SyncIntervalMinutes = req.SyncIntervalMinutes
	}
	if req.IsEnabled != nil {
		conn.IsEnabled = *req.IsEnabled
	}

	if err := cloudsync.ValidateConnection(conn); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Config != nil {
		sealed, err := h.sealConfig(conn.Provider, req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		conn.ConfigEncrypted = sealed
	} else {
		// No new credentials supplied. The stored ones are kept — but they are
		// checked against the provider that is now set, because changing the
		// provider without changing the config leaves a connection that cannot
		// possibly work and would only say so at the next sync.
		if err := h.checkStoredConfig(conn); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		conn.ConfigEncrypted = ""
	}

	if err := h.store.UpdateCloudConnection(c.Request.Context(), conn); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	updated, err := h.store.GetCloudConnection(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "cloud.connection_updated", updated)
	c.JSON(http.StatusOK, gin.H{"data": updated})
}

// DeleteConnection handles DELETE /api/v1/cloud/connections/:id.
func (h *CloudHandler) DeleteConnection(c *gin.Context) {
	id := c.Param("id")

	conn, err := h.store.GetCloudConnection(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.DeleteCloudConnection(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "cloud.connection_deleted", conn)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"No longer inventorying %s. Certificates stored there will not be reported, including the ones nothing renews.",
			conn.Name),
	})
}

// SyncConnection handles POST /api/v1/cloud/connections/:id/sync — run it now.
//
// Synchronous, because the answer is the point: somebody who has just pasted a
// set of credentials wants to know whether they work, and a 202 would leave
// them refreshing a list to find out.
func (h *CloudHandler) SyncConnection(c *gin.Context) {
	id := c.Param("id")

	conn, err := h.store.GetCloudConnection(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Bounded well under the HTTP server's 30-second write timeout. Over it,
	// the server cuts the response off mid-write and the caller gets an empty
	// body — which reads as "nothing happened", the one conclusion that must
	// never be reachable by accident. The background loop keeps its longer
	// budget, because nobody is waiting on it.
	syncCtx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	h.engine.Sync(syncCtx, conn)

	// Re-read: Sync records the outcome, and the outcome is what the caller
	// needs — including that it failed.
	updated, err := h.store.GetCloudConnection(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if updated.LastError != "" {
		// 502, not 500: CertPilot worked, the cloud provider did not, and that
		// distinction is the whole content of the answer.
		c.JSON(http.StatusBadGateway, gin.H{
			"data":  updated,
			"error": updated.LastError,
			"message": "The sync did not complete, so nothing was learned about this account. " +
				"It is not the same as finding no certificates.",
		})
		return
	}

	certs, total, err := h.store.ListCloudCertificates(c.Request.Context(), store.CloudCertificateFilter{
		ConnectionID: id, Limit: 50,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Counted in the database rather than over the page just fetched. A
	// summary that says "2 of the 3" while counting only the first fifty rows
	// is a headline number that is wrong for exactly the accounts big enough
	// for the summary to be the only thing anybody reads.
	c.JSON(http.StatusOK, gin.H{
		"data":    updated,
		"found":   certs,
		"total":   total,
		"scopes":  updated.Scopes,
		"summary": summarizeCloud(updated, h.countWithFinding(c, id, cloudsync.FindingWillNotRenew), h.countWithFinding(c, id, cloudsync.FindingExpired)),
	})
}

// countWithFinding counts the certificates in one connection carrying a
// finding. A failed count yields zero, and the summary then falls back to
// wording that makes no claim about it.
func (h *CloudHandler) countWithFinding(c *gin.Context, connectionID, code string) int64 {
	_, total, err := h.store.ListCloudCertificates(c.Request.Context(), store.CloudCertificateFilter{
		ConnectionID: connectionID, FindingCode: code, Limit: 1,
	})
	if err != nil {
		return 0
	}
	return total
}

// ListCertificates handles GET /api/v1/cloud/certificates.
func (h *CloudHandler) ListCertificates(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Validated rather than passed through. connection_id lands in a uuid
	// column, so a value that is not one makes PostgreSQL refuse the whole
	// query — which arrived as a 500 carrying the raw driver error, telling the
	// caller the column type and the SQLSTATE for what is a plain typo.
	if raw := c.Query("connection_id"); raw != "" && !isUUID(raw) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "connection_id must be a uuid",
		})
		return
	}

	filter := store.CloudCertificateFilter{
		ConnectionID:    c.Query("connection_id"),
		ManagementState: strings.ToUpper(c.Query("management_state")),
		FindingCode:     c.Query("finding"),
		// Off by default: the list answers "what is in these accounts now".
		IncludeRemoved: c.Query("include_removed") == "true",
		UnimportedOnly: c.Query("unimported") == "true",
		Limit:          limit,
		Offset:         offset,
	}

	certs, total, err := h.store.ListCloudCertificates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": certs, "total": total})
}

type cloudImportRequest struct {
	CloudCertificateID string `json:"cloud_certificate_id" binding:"required"`
	Environment        string `json:"environment"`
	Team               string `json:"team"`
	RenewalLeadDays    int    `json:"renewal_lead_days"`
}

// ImportCertificate handles POST /api/v1/cloud/import — adopt a found
// certificate into inventory.
//
// As with a scan result, this does not give the certificate a renewal path.
// CertPilot holds no private key for something it merely read out of somebody
// else's store, so the record is watched and reported on, and replacing it
// still means issuing a new certificate. `auto_renew` is false whatever was
// asked for: a record that claims it will renew itself is the failure this
// product exists to prevent.
func (h *CloudHandler) ImportCertificate(c *gin.Context) {
	var req cloudImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	found, err := h.store.GetCloudCertificate(c.Request.Context(), req.CloudCertificateID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if found.CertificatePEM == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "that record holds no certificate body — the provider did not return one, so there is nothing to import",
		})
		return
	}

	info, err := x509util.ParseCertificatePEM([]byte(found.CertificatePEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("that is not a readable certificate: %v", err)})
		return
	}

	// Already managed is a success, not a conflict: two people adopting the
	// same finding should converge on one record.
	if existing, err := h.store.GetCertificateByFingerprint(c.Request.Context(), info.FingerprintSHA256); err == nil && existing != nil {
		_ = h.store.MarkCloudCertificateImported(c.Request.Context(), found.ID, existing.ID)
		c.JSON(http.StatusOK, gin.H{
			"data":    existing,
			"message": fmt.Sprintf("This certificate was already managed as %q; the cloud record now points at it.", existing.CommonName),
		})
		return
	}

	notBefore, notAfter := info.NotBefore, info.NotAfter
	pemCopy := found.CertificatePEM
	actorID := c.GetString(middleware.ContextUserID)
	var createdBy *string
	if actorID != "" {
		createdBy = &actorID
	}

	cert := &store.Certificate{
		FingerprintSHA256: info.FingerprintSHA256,
		CommonName:        info.CommonName,
		SANs:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDN:          info.IssuerDN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		Status:            importedStatus(info.NotAfter, time.Now()),
		AutoRenew:         false,
		RenewalLeadDays:   req.RenewalLeadDays,
		CertificatePEM:    &pemCopy,
		DiscoveredVia:     "CLOUD",
		Environment:       req.Environment,
		Team:              req.Team,
		CreatedBy:         createdBy,
	}

	if err := h.store.CreateCertificate(c.Request.Context(), cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.MarkCloudCertificateImported(c.Request.Context(), found.ID, cert.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("the certificate was imported as %s but the cloud record could not be linked to it: %v", cert.ID, err),
		})
		return
	}

	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cloud.imported",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    createdBy,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"cn":%q,"fingerprint":%q,"not_after":%q,"resource":%q}`,
			cert.CommonName, cert.FingerprintSHA256, notAfter.Format(time.RFC3339), found.ResourceID),
	})

	message := "Imported and now watched for expiry. CertPilot holds no private key for it, " +
		"so it cannot be renewed automatically — replacing it means issuing a new certificate."
	if found.WillRenew != nil && !*found.WillRenew {
		message += " Note that the provider does not renew it either, which is why it appeared here."
	}

	c.JSON(http.StatusCreated, gin.H{"data": cert, "message": message})
}

// sealConfig validates a provider configuration and encrypts it.
func (h *CloudHandler) sealConfig(provider string, config map[string]any) (string, error) {
	if h.keyring == nil {
		return "", fmt.Errorf("no keyring is configured, so cloud credentials cannot be stored safely")
	}
	raw, err := cloudsync.ValidateConfig(provider, config)
	if err != nil {
		return "", err
	}
	return h.keyring.EncryptString(string(raw), secrets.ContextCloudConnectionConfig)
}

// checkStoredConfig confirms the existing sealed config still builds a provider,
// which is how a provider change with no new credentials is caught.
func (h *CloudHandler) checkStoredConfig(conn *store.CloudConnection) error {
	if conn.ConfigEncrypted == "" {
		return fmt.Errorf("this connection has no stored credentials; supply config")
	}
	if h.keyring == nil {
		return fmt.Errorf("no keyring is configured, so the stored credentials cannot be checked")
	}
	plain, err := h.keyring.DecryptString(conn.ConfigEncrypted, secrets.ContextCloudConnectionConfig)
	if err != nil {
		return fmt.Errorf("the stored credentials could not be decrypted: %w", err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(plain), &config); err != nil {
		return fmt.Errorf("the stored credentials are not valid JSON")
	}
	if _, err := cloudsync.ValidateConfig(conn.Provider, config); err != nil {
		return fmt.Errorf("the stored credentials do not work for provider %q: %w", conn.Provider, err)
	}
	return nil
}

// summarizeCloud states the outcome in a sentence, because counts alone cannot
// distinguish "we looked and found nothing" from "we could not look".
func summarizeCloud(conn *store.CloudConnection, willNotRenew, expired int64) string {
	if conn.LastSuccessAt == nil {
		return fmt.Sprintf("%s has never synced successfully, so nothing is known about what is stored in it.", conn.Name)
	}

	switch {
	case conn.CertificatesSeen == 0:
		return fmt.Sprintf("%s holds no certificates in the places this connection looked. Those places are listed in `scopes`.", conn.Name)

	case willNotRenew > 0:
		// Leads with renewal rather than with expiry, because expiry is a date
		// and this is a decision: somebody has to replace these, and nothing
		// else is going to.
		sentence := fmt.Sprintf(
			"%d of the %d certificate(s) in %s are ones the provider itself does not renew. They expire on their own schedule and stop working.",
			willNotRenew, conn.CertificatesSeen, conn.Name)
		if expired == 1 {
			sentence += " 1 of them already has."
		} else if expired > 1 {
			sentence += fmt.Sprintf(" %d of them already have.", expired)
		}
		return sentence

	case expired > 0:
		return fmt.Sprintf("%d of the %d certificate(s) in %s have expired.",
			expired, conn.CertificatesSeen, conn.Name)

	case conn.UnmanagedSeen > 0:
		return fmt.Sprintf("%d of the %d certificate(s) in %s are not managed by CertPilot.",
			conn.UnmanagedSeen, conn.CertificatesSeen, conn.Name)

	default:
		return fmt.Sprintf("All %d certificate(s) in %s are ones CertPilot manages.", conn.CertificatesSeen, conn.Name)
	}
}

func (h *CloudHandler) audit(c *gin.Context, action string, conn *store.CloudConnection) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := conn.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "cloud_connection",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		// The configuration is deliberately absent. It holds cloud credentials,
		// and an audit log is the one table most likely to be exported.
		Details: fmt.Sprintf(`{"name":%q,"provider":%q,"interval_minutes":%d,"enabled":%t}`,
			conn.Name, conn.Provider, conn.SyncIntervalMinutes, conn.IsEnabled),
	})
}
