package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// CAAccountHandler handles CA account configurations and gateway plugin inspections.
type CAAccountHandler struct {
	store      store.Store
	pluginMgr  *pluginmgr.Manager
	keyring    *secrets.Keyring
	caImporter *pki.Importer
}

// NewCAAccountHandler creates a new CAAccountHandler.
func NewCAAccountHandler(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, imp *pki.Importer) *CAAccountHandler {
	return &CAAccountHandler{
		store:      s,
		pluginMgr:  pm,
		keyring:    kr,
		caImporter: imp,
	}
}

// List handles GET /api/v1/ca-accounts.
func (h *CAAccountHandler) List(c *gin.Context) {
	accounts, err := h.store.ListCAAccounts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": len(accounts)})
}

// ListGateways handles GET /api/v1/gateways (active connected plugin binaries).
func (h *CAAccountHandler) ListGateways(c *gin.Context) {
	gws := h.pluginMgr.ListGateways()
	type GatewaySummary struct {
		Name         string      `json:"name"`
		Addr         string      `json:"addr"`
		Type         string      `json:"type"`
		IsConnected  bool        `json:"is_connected"`
		Capabilities interface{} `json:"capabilities"`
		LastChecked  string      `json:"last_checked"`
	}

	summaries := make([]GatewaySummary, 0, len(gws))
	for _, gw := range gws {
		summaries = append(summaries, GatewaySummary{
			Name:         gw.Name,
			Addr:         gw.Addr,
			Type:         gw.Type,
			IsConnected:  gw.IsConnected,
			Capabilities: gw.Capabilities,
			LastChecked:  gw.LastChecked.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": summaries, "total": len(summaries)})
}

// CreateCAAccountInput is the payload for registering a CA account.
type CreateCAAccountInput struct {
	Name         string `json:"name" binding:"required"`
	ProviderType string `json:"provider_type" binding:"required"`
	GatewayAddr  string `json:"gateway_addr" binding:"required"`
	// ServerName overrides the name expected in the gateway's TLS certificate.
	ServerName string `json:"server_name"`
	// Config carries provider-specific settings — directory URLs, API tokens,
	// DNS credentials. It is validated by the gateway and then sealed before
	// it reaches the database; it is never returned by any endpoint.
	Config    map[string]any `json:"config"`
	IsDefault bool           `json:"is_default"`
	// RenewalRateLimit is how many certificates this account may successfully
	// renew inside the window. Zero, the default, means unlimited.
	RenewalRateLimit int `json:"renewal_rate_limit"`
	// RenewalRateWindowHours is the rolling window, defaulting to a week.
	RenewalRateWindowHours int `json:"renewal_rate_window_hours"`
}

// Create handles POST /api/v1/ca-accounts.
func (h *CAAccountHandler) Create(c *gin.Context) {
	var input CreateCAAccountInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON := ""
	if len(input.Config) > 0 {
		encoded, err := json.Marshal(input.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("config is not serializable: %v", err)})
			return
		}
		configJSON = string(encoded)
	}

	acc := &store.CAAccount{
		Name:                   input.Name,
		ProviderType:           input.ProviderType,
		GatewayAddr:            input.GatewayAddr,
		IsDefault:              input.IsDefault,
		Status:                 "DISCONNECTED",
		RenewalRateLimit:       input.RenewalRateLimit,
		RenewalRateWindowHours: input.RenewalRateWindowHours,
	}

	// Connect first, so the gateway can vet the configuration before it is
	// stored. Discovering that a DNS token is wrong at configuration time is
	// far cheaper than discovering it during a renewal.
	var warnings []string
	gw, err := h.pluginMgr.RegisterGateway(c.Request.Context(), input.Name, input.GatewayAddr, input.ProviderType, input.ServerName)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("could not connect to the gateway at %s: %v", input.GatewayAddr, err),
		})
		return
	}
	acc.Status = "CONNECTED"

	validation, err := gw.Client.ValidateConfig(c.Request.Context(), &providerv1.ValidateConfigRequest{ConfigJson: configJSON})
	switch {
	case err != nil:
		warnings = append(warnings, fmt.Sprintf("gateway could not validate the configuration: %v", err))
	case !validation.Valid:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "the gateway rejected this configuration",
			"validation_error": validation.Errors,
			"warnings":         validation.Warnings,
		})
		return
	default:
		warnings = append(warnings, validation.Warnings...)
	}

	if configJSON != "" {
		sealed, err := h.keyring.EncryptString(configJSON, secrets.ContextCAAccountConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("failed to encrypt the CA credentials; refusing to store them in the clear: %v", err),
			})
			return
		}
		acc.ConfigEncrypted = sealed
	}

	if err := h.store.CreateCAAccount(c.Request.Context(), acc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// The default template for this account, matching what migration 037 wrote
	// for every account that already existed.
	//
	// Without it a request that names no template has nothing to resolve to,
	// and the first request against a newly connected CA fails for a reason
	// that has nothing to do with the CA. The account is still usable if this
	// fails — an operator can write a template by hand — so it warns rather
	// than unwinding an account the gateway has already validated.
	if err := h.createDefaultTemplate(c, acc); err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"the account was created and its default certificate template was not: %v. "+
				"Requests that name no template will be refused until one exists", err))
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca_account.created",
		EntityType: "ca_account",
		EntityID:   &acc.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		Details:    fmt.Sprintf(`{"name": %q, "provider_type": %q}`, acc.Name, acc.ProviderType),
	})

	// Ask the gateway what it signs with, now rather than at the next sweep.
	//
	// The account has just been validated against the CA, so the connection is
	// known to work and the credential is known to be good — this is the one
	// moment where asking costs nothing and the answer is most wanted. An
	// operator who has just connected a Vault mount wants to see its issuing CA
	// appear in the inventory, not to wonder for twelve hours whether it will.
	issuers := h.importIssuers(c, acc)

	c.JSON(http.StatusCreated, gin.H{"data": acc, "warnings": warnings, "issuers": issuers})
}

// importIssuers records the CAs behind a newly created account.
//
// Failure here is not failure of the account. The account exists, its
// configuration validated, and it can issue; not having learned its issuers yet
// is a smaller thing than that, and the timer will try again.
func (h *CAAccountHandler) importIssuers(c *gin.Context, acc *store.CAAccount) *pki.Result {
	if h.caImporter == nil {
		return nil
	}
	result := h.caImporter.ImportAccount(c.Request.Context(), acc)
	if result.Error != "" {
		slog.Warn("could not import the issuers behind a new CA account",
			"account", acc.Name, "error", result.Error)
	}
	return &result
}

// HealthCheck handles POST /api/v1/ca-accounts/:id/health.
func (h *CAAccountHandler) HealthCheck(c *gin.Context) {
	id := c.Param("id")
	acc, err := h.store.GetCAAccount(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	gw, err := h.pluginMgr.GetGateway(acc.Name)
	if err != nil {
		// Try to register/reconnect
		gw, err = h.pluginMgr.RegisterGateway(c.Request.Context(), acc.Name, acc.GatewayAddr, acc.ProviderType, "")
		if err != nil {
			acc.Status = "ERROR"
			_ = h.store.UpdateCAAccount(c.Request.Context(), acc)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("failed to reach gateway: %v", err)})
			return
		}
	}

	resp, err := gw.Client.HealthCheck(c.Request.Context(), &providerv1.HealthCheckRequest{})
	if err != nil {
		acc.Status = "ERROR"
		_ = h.store.UpdateCAAccount(c.Request.Context(), acc)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("gateway health check failed: %v", err)})
		return
	}

	acc.Status = "CONNECTED"
	_ = h.store.UpdateCAAccount(c.Request.Context(), acc)

	c.JSON(http.StatusOK, gin.H{
		"status":     resp.Status.String(),
		"message":    resp.Message,
		"latency_ms": resp.LatencyMs,
	})
}

// Delete handles DELETE /api/v1/ca-accounts/:id.
func (h *CAAccountHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCAAccount(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "CA account removed"})
}

// RateLimitInput sets how hard this account may be renewed against.
type RateLimitInput struct {
	// Limit is certificates per window. Zero means unlimited.
	Limit *int `json:"renewal_rate_limit" binding:"required"`
	// WindowHours defaults to a week when not given.
	WindowHours int `json:"renewal_rate_window_hours"`
}

// SetRateLimit handles PUT /api/v1/ca-accounts/:id/rate-limit.
//
// A narrow endpoint rather than a general update, because this is the only
// field on a CA account that is safe to change without re-validating the
// configuration through the gateway and re-sealing the credentials.
//
// It matters enough to be settable at all: a public CA counts certificates per
// week, and exceeding that suspends issuance for the whole organisation — at
// exactly the moment somebody is trying to fix an outage by reissuing.
func (h *CAAccountHandler) SetRateLimit(c *gin.Context) {
	id := c.Param("id")

	acc, err := h.store.GetCAAccount(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var input RateLimitInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if *input.Limit < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "renewal_rate_limit cannot be negative; use 0 for unlimited"})
		return
	}
	if input.WindowHours < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "renewal_rate_window_hours cannot be negative"})
		return
	}

	acc.RenewalRateLimit = *input.Limit
	if input.WindowHours > 0 {
		acc.RenewalRateWindowHours = input.WindowHours
	}
	if acc.RenewalRateWindowHours <= 0 {
		acc.RenewalRateWindowHours = 168
	}

	if err := h.store.UpdateCAAccount(c.Request.Context(), acc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca.rate_limit_changed",
		EntityType: "ca_account",
		EntityID:   &acc.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"name":%q,"limit":%d,"window_hours":%d}`,
			acc.Name, acc.RenewalRateLimit, acc.RenewalRateWindowHours),
	})

	message := fmt.Sprintf("%s may now renew %d certificate(s) per %d hours. Renewals beyond that wait for a slot rather than being refused.",
		acc.Name, acc.RenewalRateLimit, acc.RenewalRateWindowHours)
	if acc.RenewalRateLimit == 0 {
		// Said explicitly, because "0" reading as "none allowed" would be a
		// catastrophic misunderstanding of this field.
		message = fmt.Sprintf("%s is now unlimited: CertPilot will not hold back any renewal against it.", acc.Name)
	}
	c.JSON(http.StatusOK, gin.H{"data": acc, "message": message})
}

// createDefaultTemplate writes the unconstrained template a new CA account
// needs, so the compatibility path has somewhere to land.
//
// Deliberately identical to what migration 037 generates. Two places producing
// the same row is a duplication worth one comment each: an account created
// before the upgrade and one created after it must behave the same way, and a
// migration cannot run for an account that does not exist yet.
func (h *CAAccountHandler) createDefaultTemplate(c *gin.Context, acc *store.CAAccount) error {
	return h.store.CreateCertificateTemplate(c.Request.Context(), &store.CertificateTemplate{
		Slug: issuance.DefaultSlug(acc.ID),
		Name: fmt.Sprintf("Default (%s)", acc.Name),
		Description: "Generated when this CA account was connected. Constrains nothing, so " +
			"requests that name no template behave exactly as they did before templates " +
			"existed. Safe to tighten; the estate-wide floor in Policies still applies " +
			"either way.",
		Version:            1,
		IsEnabled:          true,
		CAAccountID:        acc.ID,
		SubjectMode:        store.SubjectModeSupplied,
		AllowedKeyTypes:    []string{"RSA", "ECDSA", "Ed25519"},
		ECDSACurves:        []string{"P-256", "P-384", "P-521"},
		KeyCustodyRequired: store.KeyCustodyAny,
		RenewBeforeDays:    30,
		AutoRenew:          true,
	})
}
