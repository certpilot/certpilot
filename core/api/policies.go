package api

import (
	"net/http"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// PolicyHandler handles policy rule management.
type PolicyHandler struct {
	store store.Store
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(s store.Store) *PolicyHandler {
	return &PolicyHandler{store: s}
}

// List handles GET /api/v1/policies.
func (h *PolicyHandler) List(c *gin.Context) {
	policies, err := h.store.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": policies, "total": len(policies)})
}

// Get handles GET /api/v1/policies/:id.
func (h *PolicyHandler) Get(c *gin.Context) {
	id := c.Param("id")
	p, err := h.store.GetPolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

// PolicyInput is what a caller may set on a policy.
//
// Narrow rather than binding store.Policy, which is what both handlers used to
// do. That accepted id, created_by, created_at and updated_at from the request
// body — so a caller could choose a policy's identifier and assert when it was
// written, and Create handed whatever arrived straight to the store.
//
// The binding tags carry the CHECK constraints that migration 001 put on this
// table. Without them an unknown rule_type reaches PostgreSQL and comes back
// as a raw SQLSTATE 23514, which tells an operator nothing about which of the
// values they should have sent.
//
// rule_type is deliberately narrower than the CHECK constraint. The column
// still permits approval_required, because rows using it may already exist and
// a migration that deleted somebody's policy would be worse than one that
// refuses new ones. Nothing can approve or reject a request in this build, so
// accepting a new policy that claims to gate on approval would be promising a
// control that does not exist. The engine reports any surviving row rather than
// passing it.
type PolicyInput struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// IsEnabled is a pointer so that omitting it leaves the column's default of
	// true, rather than a Go zero value quietly creating every policy disabled.
	IsEnabled     *bool  `json:"is_enabled"`
	RuleType      string `json:"rule_type" binding:"required,oneof=key_size key_type ca_restriction max_lifetime naming"`
	RuleConfig    string `json:"rule_config" binding:"required"`
	DomainPattern string `json:"domain_pattern"`
	Severity      string `json:"severity" binding:"omitempty,oneof=INFO WARNING BLOCK"`
}

// policy builds the record this input describes. Everything the caller does not
// own — identity, authorship, timestamps — is left for the store to set.
func (in PolicyInput) policy() store.Policy {
	severity := in.Severity
	if severity == "" {
		severity = "WARNING"
	}
	return store.Policy{
		Name:          in.Name,
		Description:   in.Description,
		IsEnabled:     in.IsEnabled == nil || *in.IsEnabled,
		RuleType:      in.RuleType,
		RuleConfig:    in.RuleConfig,
		DomainPattern: in.DomainPattern,
		Severity:      severity,
	}
}

// Create handles POST /api/v1/policies.
func (h *PolicyHandler) Create(c *gin.Context) {
	var in PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p := in.policy()

	if err := h.store.CreatePolicy(c.Request.Context(), &p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, p)
}

// Update handles PUT /api/v1/policies/:id.
func (h *PolicyHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var in PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p := in.policy()
	p.ID = id

	if err := h.store.UpdatePolicy(c.Request.Context(), &p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

// Delete handles DELETE /api/v1/policies/:id.
func (h *PolicyHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeletePolicy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}
