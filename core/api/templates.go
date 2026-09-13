package api

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// templateSlug is the pattern migration 036 enforces on the column.
var templateSlug = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// TemplateHandler manages certificate templates.
type TemplateHandler struct {
	store     store.Store
	policyEng *policy.Engine
}

// NewTemplateHandler creates a new TemplateHandler.
func NewTemplateHandler(s store.Store, pe *policy.Engine) *TemplateHandler {
	return &TemplateHandler{store: s, policyEng: pe}
}

// TemplateInput is what a caller may set on a certificate template.
//
// Narrow, rather than binding store.CertificateTemplate. Binding the model is
// what let a caller choose a policy's identifier and assert when it was
// written, and it is the same mistake here with twenty-eight columns instead of
// eight. Identity, authorship, timestamps and the version counter are not the
// caller's to set.
//
// The binding tags carry the CHECK constraints migration 036 put on the table.
// Without them an unknown subject_mode reaches PostgreSQL and comes back as a
// raw SQLSTATE 23514, which tells an operator nothing about which value they
// should have sent.
type TemplateInput struct {
	Slug        string `json:"slug" binding:"required,max=63"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// IsEnabled is a pointer so omitting it leaves the column's default of
	// true, rather than a Go zero value quietly creating every template
	// disabled.
	IsEnabled *bool `json:"is_enabled"`

	CAAccountID string `json:"ca_account_id" binding:"required"`
	CAProfile   string `json:"ca_profile"`

	SubjectMode     string               `json:"subject_mode" binding:"omitempty,oneof=SUPPLIED CONSTRAINED"`
	SubjectDefaults map[string]string    `json:"subject_defaults"`
	CommonNameRule  store.CommonNameRule `json:"common_name_rule"`
	SANRules        store.SANRules       `json:"san_rules"`

	AllowedKeyTypes    []string `json:"allowed_key_types"`
	RSAMinBits         int      `json:"rsa_min_bits" binding:"omitempty,min=0"`
	RSAMaxBits         int      `json:"rsa_max_bits" binding:"omitempty,min=0"`
	ECDSACurves        []string `json:"ecdsa_curves"`
	CSRRequired        bool     `json:"csr_required"`
	KeyCustodyRequired string   `json:"key_custody_required" binding:"omitempty,oneof=ANY CERTPILOT AGENT EXTERNAL"`

	ValidityDays    int   `json:"validity_days" binding:"omitempty,min=0"`
	MaxValidityDays int   `json:"max_validity_days" binding:"omitempty,min=0"`
	RenewBeforeDays int   `json:"renew_before_days" binding:"omitempty,min=1"`
	AutoRenew       *bool `json:"auto_renew"`

	RequireMetadata    []string `json:"require_metadata"`
	DefaultEnvironment string   `json:"default_environment"`
	DefaultTeam        string   `json:"default_team"`
	DefaultTags        []string `json:"default_tags"`
}

// template builds the record this input describes. Everything the caller does
// not own — identity, authorship, timestamps, version — is left out.
func (in TemplateInput) template() store.CertificateTemplate {
	subjectMode := in.SubjectMode
	if subjectMode == "" {
		subjectMode = store.SubjectModeSupplied
	}
	custody := in.KeyCustodyRequired
	if custody == "" {
		custody = store.KeyCustodyAny
	}
	renewBefore := in.RenewBeforeDays
	if renewBefore == 0 {
		renewBefore = 30
	}

	// Omitting these means "this template does not restrict them", which is
	// what the column defaults in migration 036 say. Passing the caller's nil
	// straight through wrote an empty list instead, and an empty list is the
	// opposite rule: it permits nothing. The refusal message even told callers
	// to omit the field, so the advice produced the error it was meant to
	// avoid.
	keyTypes := in.AllowedKeyTypes
	if len(keyTypes) == 0 {
		keyTypes = []string{"RSA", "ECDSA", "Ed25519"}
	}
	curves := in.ECDSACurves
	if len(curves) == 0 {
		curves = []string{"P-256", "P-384", "P-521"}
	}

	return store.CertificateTemplate{
		Slug:        strings.TrimSpace(in.Slug),
		Name:        strings.TrimSpace(in.Name),
		Description: in.Description,
		IsEnabled:   in.IsEnabled == nil || *in.IsEnabled,

		CAAccountID: in.CAAccountID,
		CAProfile:   strings.TrimSpace(in.CAProfile),

		SubjectMode:     subjectMode,
		SubjectDefaults: in.SubjectDefaults,
		CommonNameRule:  in.CommonNameRule,
		SANRules:        in.SANRules,

		AllowedKeyTypes:    keyTypes,
		RSAMinBits:         in.RSAMinBits,
		RSAMaxBits:         in.RSAMaxBits,
		ECDSACurves:        curves,
		CSRRequired:        in.CSRRequired,
		KeyCustodyRequired: custody,

		ValidityDays:    in.ValidityDays,
		MaxValidityDays: in.MaxValidityDays,
		RenewBeforeDays: renewBefore,
		AutoRenew:       in.AutoRenew == nil || *in.AutoRenew,

		RequireMetadata:    in.RequireMetadata,
		DefaultEnvironment: in.DefaultEnvironment,
		DefaultTeam:        in.DefaultTeam,
		DefaultTags:        in.DefaultTags,
	}
}

// List handles GET /api/v1/certificate-templates.
func (h *TemplateHandler) List(c *gin.Context) {
	templates, err := h.store.ListCertificateTemplates(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": templates, "total": len(templates)})
}

// Get handles GET /api/v1/certificate-templates/:id.
//
// The id may be the uuid or the slug. A pipeline that names `internal-mtls`
// should not have to look up a uuid first, and the two namespaces cannot
// collide: migration 036 refuses a slug that is not lowercase-alphanumeric.
func (h *TemplateHandler) Get(c *gin.Context) {
	t, err := h.resolve(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, t)
}

func (h *TemplateHandler) resolve(ctx context.Context, ref string) (*store.CertificateTemplate, error) {
	if t, err := h.store.GetCertificateTemplate(ctx, ref); err == nil {
		return t, nil
	}
	return h.store.GetCertificateTemplateBySlug(ctx, ref)
}

// Create handles POST /api/v1/certificate-templates.
func (h *TemplateHandler) Create(c *gin.Context) {
	var in TemplateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	t := in.template()
	t.Version = 1

	if err := h.validate(c.Request.Context(), &t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.CreateCertificateTemplate(c.Request.Context(), &t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "template.created", &t, fmt.Sprintf(
		`{"slug":%q,"ca_account_id":%q,"subject_mode":%q}`,
		t.Slug, t.CAAccountID, t.SubjectMode))

	c.JSON(http.StatusCreated, t)
}

// Update handles PUT /api/v1/certificate-templates/:id.
//
// The version is bumped when a rule changed and left alone when only a label
// did. Renaming a template must not invalidate the certificates issued under
// it — a version that moved on a typo correction makes "this certificate was
// issued under version 3" mean nothing.
func (h *TemplateHandler) Update(c *gin.Context) {
	existing, err := h.resolve(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var in TemplateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	t := in.template()
	t.ID = existing.ID
	t.CreatedBy = existing.CreatedBy
	t.Version = existing.Version
	if rulesDiffer(existing, &t) {
		t.Version = existing.Version + 1
	}

	if err := h.validate(c.Request.Context(), &t); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.UpdateCertificateTemplate(c.Request.Context(), &t); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "template.updated", &t, fmt.Sprintf(
		`{"slug":%q,"version_from":%d,"version_to":%d}`,
		t.Slug, existing.Version, t.Version))

	c.JSON(http.StatusOK, t)
}

// Delete handles DELETE /api/v1/certificate-templates/:id.
func (h *TemplateHandler) Delete(c *gin.Context) {
	existing, err := h.resolve(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	// Refused here rather than at the foreign key.
	//
	// Migration 038 makes template_grants reference this table with `on delete
	// restrict`, deliberately: a rule that silently disappeared when somebody
	// removed a template would take an estate's permissions with it. But
	// letting that constraint fire reaches an operator as
	// `SQLSTATE 23503 … template_grants_template_id_fkey`, which names a
	// constraint and not a thing they can act on.
	//
	// A revoked grant still references its template, which is why this counts
	// every grant rather than only the live ones — that is exactly the case
	// that produced the raw error.
	if blocking, err := h.grantsUsing(c.Request.Context(), existing.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	} else if len(blocking) > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf(
			"template %q is still named by %d grant(s): %s. Delete those first, or disable this "+
				"template instead — a revoked grant still refers to the template it was written against, "+
				"and that record is part of why a certificate exists",
			existing.Slug, len(blocking), strings.Join(blocking, ", "))})
		return
	}

	if err := h.store.DeleteCertificateTemplate(c.Request.Context(), existing.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "template.deleted", existing, fmt.Sprintf(`{"slug":%q}`, existing.Slug))
	c.JSON(http.StatusOK, gin.H{"message": "certificate template deleted"})
}

func (h *TemplateHandler) audit(c *gin.Context, action string, t *store.CertificateTemplate, details string) {
	id := t.ID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "certificate_template",
		EntityID:   &id,
		Details:    details,
	})
}

// ── Validation ──────────────────────────────────────────────

// validate refuses a template that cannot work, before it is stored.
func (h *TemplateHandler) validate(ctx context.Context, t *store.CertificateTemplate) error {
	if err := validateTemplateShape(t); err != nil {
		return err
	}

	// The CA account has to exist. The foreign key would catch this, and would
	// report it as a constraint name.
	if _, err := h.store.GetCAAccount(ctx, t.CAAccountID); err != nil {
		return fmt.Errorf("ca_account_id: %w", err)
	}

	// Metadata keys have to exist, for the same reason an unknown metadata key
	// on a certificate is an error rather than a silent drop: a required field
	// under a misspelled key is a requirement no form will ever show and no
	// request will ever satisfy.
	if len(t.RequireMetadata) > 0 {
		fields, err := h.store.ListMetadataFields(ctx, false)
		if err != nil {
			return err
		}
		known := map[string]bool{}
		for _, f := range fields {
			known[f.Key] = true
		}
		for _, key := range t.RequireMetadata {
			if !known[key] {
				return fmt.Errorf(
					"require_metadata names %q, which is not a metadata field. "+
						"A required field nothing defines is a requirement no request can satisfy", key)
			}
		}
	}

	return h.refuseIfNothingCouldEverBeIssued(ctx, t)
}

// validateTemplateShape checks the template against itself.
func validateTemplateShape(t *store.CertificateTemplate) error {
	// The pattern migration 036 puts on the column. Without this the raw
	// SQLSTATE 23514 reaches the caller, naming a constraint rather than
	// saying what a slug may contain.
	if !templateSlug.MatchString(t.Slug) {
		return fmt.Errorf(
			"slug %q is not usable as a machine name: lowercase letters, digits and hyphens, "+
				"starting with a letter, up to 63 characters", t.Slug)
	}
	if t.ValidityDays > 0 && t.MaxValidityDays > 0 && t.ValidityDays > t.MaxValidityDays {
		return fmt.Errorf(
			"validity_days is %d and max_validity_days is %d, so the value this template supplies "+
				"exceeds the ceiling it sets", t.ValidityDays, t.MaxValidityDays)
	}
	if t.RSAMinBits > 0 && t.RSAMaxBits > 0 && t.RSAMaxBits < t.RSAMinBits {
		return fmt.Errorf(
			"rsa_max_bits is %d and rsa_min_bits is %d, so no RSA key could satisfy both",
			t.RSAMaxBits, t.RSAMinBits)
	}
	if len(t.AllowedKeyTypes) == 0 {
		return fmt.Errorf(
			"allowed_key_types is empty, which permits no key at all. " +
				"Name the types this template may issue, or omit the field to permit all three")
	}
	for _, kt := range t.AllowedKeyTypes {
		switch strings.ToUpper(strings.TrimSpace(kt)) {
		case "RSA", "ECDSA", "ED25519":
		default:
			return fmt.Errorf(
				"allowed_key_types names %q, which is not a key type this build can issue. "+
					"Supported: RSA, ECDSA, Ed25519", kt)
		}
	}
	// A template that requires a CSR and also declares CERTPILOT custody is
	// asking for a key the requester generates and CertPilot holds, and there
	// is no path that produces that.
	if t.CSRRequired && t.KeyCustodyRequired == store.KeyCustodyCertPilot {
		return fmt.Errorf(
			"csr_required is set and key_custody_required is CERTPILOT, which cannot both be true: " +
				"a requester that brings its own CSR keeps the private key, and CertPilot never sees it")
	}
	return nil
}

// refuseIfNothingCouldEverBeIssued is the save-time check against the floor.
//
// Google's own documentation admits a certificate template and a CA-pool
// issuance policy can conflict, and sends the reader to a separate page about
// resolving it — which means you find out at issuance, on the day you needed a
// certificate. Refusing to store a template that can never issue anything is
// strictly better, and the operator finds out while they are still looking at
// the form.
//
// The check is a probe rather than an analysis: build the most permissive
// request this template would allow — the strongest key of each permitted type,
// the shortest lifetime it permits — and ask the policy engine. If every
// probe comes back BLOCKed, nothing this template permits can ever be issued.
func (h *TemplateHandler) refuseIfNothingCouldEverBeIssued(ctx context.Context, t *store.CertificateTemplate) error {
	if h.policyEng == nil {
		return nil
	}

	account, err := h.store.GetCAAccount(ctx, t.CAAccountID)
	if err != nil {
		return nil // already reported by the caller
	}

	probes := templateProbes(t, account.ProviderType)
	if len(probes) == 0 {
		return nil
	}

	// A template that declares no name rules permits every name, so a naming
	// policy cannot make it unissuable — there is always some name that passes.
	// Judging the probe's placeholder name would refuse templates that are
	// perfectly usable, so naming violations are dropped in that case.
	ignoreNaming := len(t.CommonNameRule.Suffixes) == 0 && len(t.SANRules.Suffixes) == 0

	var blocked []policy.Violation
	for _, probe := range probes {
		violations, err := h.policyEng.EvaluateRequest(ctx, probe)
		if err != nil {
			return err
		}

		var blocking []policy.Violation
		for _, v := range violations {
			if v.Severity != policy.SeverityBlock {
				continue
			}
			if ignoreNaming && v.RuleType == policy.RuleNaming {
				continue
			}
			blocking = append(blocking, v)
		}

		// One probe that gets through is enough: this template can issue
		// something, and the floor will judge each real request on its merits.
		if len(blocking) == 0 {
			return nil
		}
		blocked = append(blocked, blocking...)
	}

	reasons := make([]string, 0, len(blocked))
	seen := map[string]bool{}
	for _, v := range blocked {
		if seen[v.Message] {
			continue
		}
		seen[v.Message] = true
		reasons = append(reasons, v.Message)
	}

	return fmt.Errorf(
		"this template could never issue a certificate: every key it permits is refused by a "+
			"BLOCK policy — %s. Widen the template or change the policy",
		strings.Join(reasons, "; "))
}

// templateProbes builds the strongest request this template allows, one per
// permitted key type.
//
// Strongest, not weakest: the question is whether *anything* the template
// permits can clear the floor, so the probe should be the request most likely
// to pass. A template permitting RSA from 2048 to 8192 can issue if the floor
// is 3072, and probing at 2048 would wrongly refuse it.
func templateProbes(t *store.CertificateTemplate, providerType string) []policy.Request {
	name := probeName(t)
	validity := t.ValidityDays
	if validity == 0 {
		// The shortest lifetime the template permits, because max_lifetime is
		// the only lifetime rule and a shorter request is always likelier to
		// pass it.
		validity = 1
	}

	base := policy.Request{
		CommonName:     name,
		Domains:        []string{name},
		ValidityDays:   validity,
		CAProviderType: providerType,
	}

	var probes []policy.Request
	for _, kt := range t.AllowedKeyTypes {
		probe := base
		switch strings.ToUpper(strings.TrimSpace(kt)) {
		case "RSA":
			probe.KeyType = "RSA"
			probe.KeySize = t.RSAMaxBits
			if probe.KeySize == 0 {
				probe.KeySize = 8192
			}
		case "ECDSA":
			probe.KeyType = "ECDSA"
			probe.KeySize = strongestCurve(t.ECDSACurves)
		case "ED25519":
			probe.KeyType = "Ed25519"
			probe.KeySize = 256
		default:
			continue
		}
		probes = append(probes, probe)
	}
	return probes
}

// strongestCurve returns the bit size of the strongest curve a template
// permits, so the probe is the best case rather than an arbitrary one.
func strongestCurve(curves []string) int {
	best := 0
	for _, c := range curves {
		switch strings.ToUpper(strings.TrimSpace(c)) {
		case "P-256", "P256", "PRIME256V1", "SECP256R1":
			if best < 256 {
				best = 256
			}
		case "P-384", "P384", "SECP384R1":
			if best < 384 {
				best = 384
			}
		case "P-521", "P521", "SECP521R1":
			if best < 521 {
				best = 521
			}
		}
	}
	if best == 0 {
		// No curves named means the template does not restrict them.
		return 521
	}
	return best
}

// probeName is a name this template would permit, used to ask the naming rules
// whether the template and the floor can agree about anything.
func probeName(t *store.CertificateTemplate) string {
	suffixes := t.CommonNameRule.Suffixes
	if len(suffixes) == 0 {
		suffixes = t.SANRules.Suffixes
	}
	if len(suffixes) > 0 {
		return "probe." + strings.TrimPrefix(suffixes[0], ".")
	}
	return "probe.example.com"
}

// rulesDiffer reports whether an edit changed what this template permits, as
// opposed to what it is called.
//
// Compared field by field through a copy with the non-rule fields zeroed, so a
// rule added to the model in future is compared without anybody remembering to
// add it here. The failure mode of the alternative — an explicit list — is a
// new rule that silently never bumps the version.
func rulesDiffer(a, b *store.CertificateTemplate) bool {
	return !reflect.DeepEqual(rulesOnly(a), rulesOnly(b))
}

func rulesOnly(t *store.CertificateTemplate) store.CertificateTemplate {
	c := *t
	c.ID = ""
	c.Name = ""
	c.Description = ""
	c.Version = 0
	c.CreatedBy = nil
	c.CreatedAt, c.UpdatedAt = time.Time{}, time.Time{}

	// Empty and absent are the same rule, and a round trip through the store
	// turns one into the other.
	c.SubjectDefaults = orEmptyStringMap(c.SubjectDefaults)
	c.AllowedKeyTypes = orEmptyStringSlice(c.AllowedKeyTypes)
	c.ECDSACurves = orEmptyStringSlice(c.ECDSACurves)
	c.RequireMetadata = orEmptyStringSlice(c.RequireMetadata)
	c.DefaultTags = orEmptyStringSlice(c.DefaultTags)
	c.CommonNameRule.Suffixes = orEmptyStringSlice(c.CommonNameRule.Suffixes)
	c.CommonNameRule.ForbiddenPatterns = orEmptyStringSlice(c.CommonNameRule.ForbiddenPatterns)
	c.SANRules.Types = orEmptyStringSlice(c.SANRules.Types)
	c.SANRules.Suffixes = orEmptyStringSlice(c.SANRules.Suffixes)
	return c
}

func orEmptyStringSlice(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orEmptyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// grantsUsing names the grants that refer to a template, revoked ones included.
func (h *TemplateHandler) grantsUsing(ctx context.Context, templateID string) ([]string, error) {
	grants, err := h.store.ListTemplateGrants(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, g := range grants {
		if g.TemplateID == templateID {
			names = append(names, g.Name)
		}
	}
	return names, nil
}
