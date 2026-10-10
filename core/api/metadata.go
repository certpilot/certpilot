package api

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// MetadataHandler manages the admin-defined fields every certificate answers.
type MetadataHandler struct {
	store store.Store
}

func NewMetadataHandler(s store.Store) *MetadataHandler {
	return &MetadataHandler{store: s}
}

// keyPattern matches the CHECK constraint in migration 027. Enforced here too
// so the failure is a sentence rather than a raw SQLSTATE 23514.
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

var validFieldTypes = map[string]bool{
	store.MetadataText:        true,
	store.MetadataSelect:      true,
	store.MetadataMultiSelect: true,
	store.MetadataBoolean:     true,
}

// slugify derives a stable machine key from a human label.
//
// Callers supply a label; the key is generated once and then never changes,
// because it is what every certificate stores its value under. Letting someone
// type the key by hand invites a rename later, and a renamed key orphans every
// value already recorded against the old one.
func slugify(label string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore && b.Len() > 0:
			b.WriteRune('_')
			lastUnderscore = true
		}
	}
	key := strings.Trim(b.String(), "_")
	// A key must start with a letter; a label like "2FA required" would
	// otherwise produce one the constraint refuses.
	if key != "" && (key[0] < 'a' || key[0] > 'z') {
		key = "f_" + key
	}
	if len(key) > 63 {
		key = strings.Trim(key[:63], "_")
	}
	return key
}

// MetadataFieldInput is the payload for creating or updating a field.
type MetadataFieldInput struct {
	Label     string `json:"label" binding:"required"`
	FieldType string `json:"field_type" binding:"required"`
	Options   []struct {
		Value string `json:"value"`
		Label string `json:"label"`
	} `json:"options"`
	Display    string `json:"display"`
	HelpText   string `json:"help_text"`
	IsRequired bool   `json:"is_required"`
	SortOrder  int    `json:"sort_order"`
	IsArchived bool   `json:"is_archived"`
}

// normalize turns an input into a field, or explains why it cannot.
func (in *MetadataFieldInput) normalize(existing *store.MetadataField) (*store.MetadataField, error) {
	label := strings.TrimSpace(in.Label)
	if label == "" {
		return nil, fmt.Errorf("label is required")
	}

	fieldType := strings.ToUpper(strings.TrimSpace(in.FieldType))
	if !validFieldTypes[fieldType] {
		return nil, fmt.Errorf(
			"field_type must be one of TEXT, SELECT, MULTI_SELECT, BOOLEAN; got %q", in.FieldType)
	}

	display := strings.ToUpper(strings.TrimSpace(in.Display))
	if display == "" {
		display = store.MetadataDisplayDropdown
	}
	if display != store.MetadataDisplayDropdown && display != store.MetadataDisplayRadio {
		return nil, fmt.Errorf("display must be DROPDOWN or RADIO; got %q", in.Display)
	}

	field := &store.MetadataField{
		Label:      label,
		FieldType:  fieldType,
		Display:    display,
		HelpText:   strings.TrimSpace(in.HelpText),
		IsRequired: in.IsRequired,
		SortOrder:  in.SortOrder,
		IsArchived: in.IsArchived,
		Options:    []store.MetadataOption{},
	}

	if fieldType == store.MetadataSelect || fieldType == store.MetadataMultiSelect {
		seen := map[string]bool{}
		for _, o := range in.Options {
			optLabel := strings.TrimSpace(o.Label)
			if optLabel == "" {
				optLabel = strings.TrimSpace(o.Value)
			}
			if optLabel == "" {
				continue
			}
			// An existing option keeps the value it was created with. Deriving
			// it from the label every time would silently reclassify every
			// certificate holding the old value the moment someone fixes a typo.
			value := strings.TrimSpace(o.Value)
			if value == "" {
				value = slugify(optLabel)
			}
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			field.Options = append(field.Options, store.MetadataOption{Value: value, Label: optLabel})
		}
		if len(field.Options) == 0 {
			return nil, fmt.Errorf("a %s field needs at least one option", fieldType)
		}
	}

	if existing != nil {
		field.ID = existing.ID
		field.Key = existing.Key
		field.CreatedBy = existing.CreatedBy
		field.CreatedAt = existing.CreatedAt

		// Options a certificate may already hold must survive an edit. Removing
		// one is allowed — it stops being offered — but changing the field type
		// out from under stored values is not, because the values become
		// unreadable rather than merely stale.
		if existing.FieldType != field.FieldType {
			return nil, fmt.Errorf(
				"a field's type cannot change after creation: certificates already hold %s values. Archive this field and create a new one",
				strings.ToLower(existing.FieldType))
		}
	} else {
		field.Key = slugify(label)
		if !keyPattern.MatchString(field.Key) {
			return nil, fmt.Errorf(
				"could not derive a usable key from %q; use a label with at least one letter", label)
		}
	}

	return field, nil
}

// List handles GET /api/v1/metadata-fields.
//
// Readable by any role. A viewer looking at a certificate needs the labels to
// make sense of the values on it, and the definitions are not secrets.
func (h *MetadataHandler) List(c *gin.Context) {
	includeArchived := c.Query("include_archived") == "true"
	fields, err := h.store.ListMetadataFields(c.Request.Context(), includeArchived)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": fields, "total": len(fields)})
}

// Create handles POST /api/v1/metadata-fields.
func (h *MetadataHandler) Create(c *gin.Context) {
	var input MetadataFieldInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	field, err := input.normalize(nil)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	field.CreatedBy = &actorID

	if err := h.store.CreateMetadataField(c.Request.Context(), field); err != nil {
		// The unique constraint on key is the likely failure and it has a
		// specific cause worth naming: two labels that slugify the same way.
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") ||
			strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf(
					"a field already uses the key %q — pick a label that differs by more than punctuation", field.Key),
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "metadata_field.created", field)
	c.JSON(http.StatusCreated, field)
}

// Update handles PUT /api/v1/metadata-fields/:id.
func (h *MetadataHandler) Update(c *gin.Context) {
	existing, err := h.store.GetMetadataField(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "metadata field")
		return
	}

	var input MetadataFieldInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	field, err := input.normalize(existing)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.UpdateMetadataField(c.Request.Context(), field); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.audit(c, "metadata_field.updated", field)
	c.JSON(http.StatusOK, field)
}

// Archive handles DELETE /api/v1/metadata-fields/:id.
//
// Archives rather than deletes. Certificates issued years ago may hold a value
// for a field the organisation has stopped using, and that value is part of why
// the certificate exists. Removing the definition would leave the value in
// place with nothing able to label it.
func (h *MetadataHandler) Archive(c *gin.Context) {
	field, err := h.store.GetMetadataField(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondLookup(c, err, "metadata field")
		return
	}
	if err := h.store.ArchiveMetadataField(c.Request.Context(), field.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "metadata_field.archived", field)
	c.JSON(http.StatusOK, gin.H{
		"archived": field.Key,
		"note":     "Existing certificate values are kept and still labelled by this field.",
	})
}

func (h *MetadataHandler) audit(c *gin.Context, action string, field *store.MetadataField) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "metadata_field",
		EntityID:   &field.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		Details:    fmt.Sprintf(`{"key": %q, "label": %q, "field_type": %q}`, field.Key, field.Label, field.FieldType),
	})
}

// ── Validation of values against their definitions ─────────

// validateMetadata checks submitted values against the field definitions.
//
// Two things this deliberately does not do:
//
// It does not reject values for fields it does not recognise by dropping them
// silently — an unknown key is an error, because the commonest cause is a typo
// in an integration and a value quietly discarded is one nobody notices until
// they filter by it and get nothing.
//
// It does not enforce required fields on an update. Requirements apply when a
// certificate is requested; making a field required later must not render every
// existing certificate unsaveable, which would leave an operator unable to
// correct the team on a certificate because of an unrelated new field.
func validateMetadata(
	fields []*store.MetadataField, values map[string]any, enforceRequired bool,
) (map[string]any, error) {
	byKey := make(map[string]*store.MetadataField, len(fields))
	for _, f := range fields {
		byKey[f.Key] = f
	}

	cleaned := map[string]any{}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic error for a request with several problems

	for _, key := range keys {
		raw := values[key]
		field, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("no metadata field is defined with the key %q", key)
		}
		if field.IsArchived {
			return nil, fmt.Errorf("the metadata field %q has been archived and no longer accepts values", key)
		}

		// An explicit null clears the value rather than storing a null.
		if raw == nil {
			continue
		}

		switch field.FieldType {
		case store.MetadataBoolean:
			b, ok := raw.(bool)
			if !ok {
				return nil, fmt.Errorf("%s expects true or false", field.Label)
			}
			cleaned[key] = b

		case store.MetadataText:
			str, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("%s expects text", field.Label)
			}
			str = strings.TrimSpace(str)
			if str == "" {
				continue // an empty string is an absent value, not a stored ""
			}
			if len(str) > 512 {
				return nil, fmt.Errorf("%s is limited to 512 characters", field.Label)
			}
			cleaned[key] = str

		case store.MetadataSelect:
			str, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("%s expects one of its options", field.Label)
			}
			if str = strings.TrimSpace(str); str == "" {
				continue
			}
			if !field.HasOption(str) {
				return nil, fmt.Errorf("%q is not an option for %s", str, field.Label)
			}
			cleaned[key] = str

		case store.MetadataMultiSelect:
			list, ok := raw.([]any)
			if !ok {
				return nil, fmt.Errorf("%s expects a list of its options", field.Label)
			}
			seen := map[string]bool{}
			chosen := []any{}
			for _, item := range list {
				str, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("%s expects a list of its options", field.Label)
				}
				str = strings.TrimSpace(str)
				if str == "" || seen[str] {
					continue
				}
				if !field.HasOption(str) {
					return nil, fmt.Errorf("%q is not an option for %s", str, field.Label)
				}
				seen[str] = true
				chosen = append(chosen, str)
			}
			if len(chosen) == 0 {
				continue
			}
			cleaned[key] = chosen
		}
	}

	if enforceRequired {
		for _, f := range fields {
			if !f.IsRequired || f.IsArchived {
				continue
			}
			if _, present := cleaned[f.Key]; !present {
				return nil, fmt.Errorf("%s is required", f.Label)
			}
		}
	}

	return cleaned, nil
}
