package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// certificateTemplateColumns is the one place the column list lives.
//
// Adding a column means touching four things or the value is silently lost:
// this list, scanCertificateTemplate, the INSERT, and the UPDATE. Three of the
// four look correct on their own, which is why this is written down.
const certificateTemplateColumns = `id, slug, name, description, version, is_enabled,
		ca_account_id, ca_profile,
		subject_mode, subject_defaults, common_name_rule, san_rules,
		allowed_key_types, rsa_min_bits, rsa_max_bits, ecdsa_curves,
		csr_required, key_custody_required,
		validity_days, max_validity_days, renew_before_days, auto_renew,
		key_usage, extended_key_usage, basic_constraints_ca,
		extension_passthrough, passthrough_oids, conformance,
		require_metadata, default_environment, default_team, default_tags,
		created_by, created_at, updated_at`

func scanCertificateTemplate(row pgx.Row) (*CertificateTemplate, error) {
	t := &CertificateTemplate{}
	var subjectJSON, cnJSON, sanJSON, keyTypesJSON, curvesJSON, metaJSON, tagsJSON []byte
	var keyUsageJSON, ekuJSON, passthroughOIDsJSON []byte

	err := row.Scan(
		&t.ID, &t.Slug, &t.Name, &t.Description, &t.Version, &t.IsEnabled,
		&t.CAAccountID, &t.CAProfile,
		&t.SubjectMode, &subjectJSON, &cnJSON, &sanJSON,
		&keyTypesJSON, &t.RSAMinBits, &t.RSAMaxBits, &curvesJSON,
		&t.CSRRequired, &t.KeyCustodyRequired,
		&t.ValidityDays, &t.MaxValidityDays, &t.RenewBeforeDays, &t.AutoRenew,
		&keyUsageJSON, &ekuJSON, &t.BasicConstraintsCA,
		&t.ExtensionPassthrough, &passthroughOIDsJSON, &t.Conformance,
		&metaJSON, &t.DefaultEnvironment, &t.DefaultTeam, &tagsJSON,
		&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Unmarshal errors are returned rather than swallowed. A template whose
	// rules will not parse must not come back looking like a template with no
	// rules — that is the difference between a refusal and a silent allow, and
	// this object exists to refuse things.
	if err := unmarshalTemplateJSON(subjectJSON, &t.SubjectDefaults); err != nil {
		return nil, fmt.Errorf("template %s: subject_defaults: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(cnJSON, &t.CommonNameRule); err != nil {
		return nil, fmt.Errorf("template %s: common_name_rule: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(sanJSON, &t.SANRules); err != nil {
		return nil, fmt.Errorf("template %s: san_rules: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(keyTypesJSON, &t.AllowedKeyTypes); err != nil {
		return nil, fmt.Errorf("template %s: allowed_key_types: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(curvesJSON, &t.ECDSACurves); err != nil {
		return nil, fmt.Errorf("template %s: ecdsa_curves: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(metaJSON, &t.RequireMetadata); err != nil {
		return nil, fmt.Errorf("template %s: require_metadata: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(tagsJSON, &t.DefaultTags); err != nil {
		return nil, fmt.Errorf("template %s: default_tags: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(keyUsageJSON, &t.KeyUsage); err != nil {
		return nil, fmt.Errorf("template %s: key_usage: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(ekuJSON, &t.ExtendedKeyUsage); err != nil {
		return nil, fmt.Errorf("template %s: extended_key_usage: %w", t.Slug, err)
	}
	if err := unmarshalTemplateJSON(passthroughOIDsJSON, &t.PassthroughOIDs); err != nil {
		return nil, fmt.Errorf("template %s: passthrough_oids: %w", t.Slug, err)
	}

	normaliseTemplate(t)
	return t, nil
}

func unmarshalTemplateJSON(raw []byte, into any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, into)
}

// normaliseTemplate makes the slices and maps non-nil after a read, so a
// template can be ranged over and indexed without a guard, and so a round trip
// through the API does not turn `[]` into `null`.
func normaliseTemplate(t *CertificateTemplate) {
	if t.SubjectDefaults == nil {
		t.SubjectDefaults = map[string]string{}
	}
	t.AllowedKeyTypes = orEmptyStrings(t.AllowedKeyTypes)
	t.ECDSACurves = orEmptyStrings(t.ECDSACurves)
	t.RequireMetadata = orEmptyStrings(t.RequireMetadata)
	t.DefaultTags = orEmptyStrings(t.DefaultTags)
	t.KeyUsage = orEmptyStrings(t.KeyUsage)
	t.ExtendedKeyUsage = orEmptyStrings(t.ExtendedKeyUsage)
	t.PassthroughOIDs = orEmptyStrings(t.PassthroughOIDs)

	// A zero value here is Go's, not an operator's choice, and must not reach
	// a CHECK constraint that would refuse it as a raw SQLSTATE — the API
	// layer already gives the same case a sentence.
	if t.ExtensionPassthrough == "" {
		t.ExtensionPassthrough = ExtensionPassthroughNone
	}
	if t.Conformance == "" {
		t.Conformance = ConformanceReport
	}
}

// templateJSON marshals the seven jsonb columns in one place, so a caller
// cannot marshal six and forget the seventh.
func templateJSON(t *CertificateTemplate) (subject, cn, san, keyTypes, curves, meta, tags,
	keyUsage, eku, passthroughOIDs []byte, err error) {
	if subject, err = json.Marshal(orEmptyMap(t.SubjectDefaults)); err != nil {
		return
	}
	if cn, err = json.Marshal(t.CommonNameRule); err != nil {
		return
	}
	if san, err = json.Marshal(t.SANRules); err != nil {
		return
	}
	if keyTypes, err = json.Marshal(orEmptyStrings(t.AllowedKeyTypes)); err != nil {
		return
	}
	if curves, err = json.Marshal(orEmptyStrings(t.ECDSACurves)); err != nil {
		return
	}
	if meta, err = json.Marshal(orEmptyStrings(t.RequireMetadata)); err != nil {
		return
	}
	if tags, err = json.Marshal(orEmptyStrings(t.DefaultTags)); err != nil {
		return
	}
	if keyUsage, err = json.Marshal(orEmptyStrings(t.KeyUsage)); err != nil {
		return
	}
	if eku, err = json.Marshal(orEmptyStrings(t.ExtendedKeyUsage)); err != nil {
		return
	}
	passthroughOIDs, err = json.Marshal(orEmptyStrings(t.PassthroughOIDs))
	return
}

func (s *PostgresStore) ListCertificateTemplates(ctx context.Context) ([]*CertificateTemplate, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+certificateTemplateColumns+
			" FROM public.certificate_templates ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*CertificateTemplate{}
	for rows.Next() {
		t, err := scanCertificateTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetCertificateTemplate(ctx context.Context, id string) (*CertificateTemplate, error) {
	t, err := scanCertificateTemplate(s.pool.QueryRow(ctx,
		"SELECT "+certificateTemplateColumns+
			" FROM public.certificate_templates WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("certificate template %s not found", id)
	}
	return t, err
}

func (s *PostgresStore) GetCertificateTemplateBySlug(ctx context.Context, slug string) (*CertificateTemplate, error) {
	t, err := scanCertificateTemplate(s.pool.QueryRow(ctx,
		"SELECT "+certificateTemplateColumns+
			" FROM public.certificate_templates WHERE slug = $1", slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("certificate template %q not found", slug)
	}
	return t, err
}

func (s *PostgresStore) CreateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error {
	normaliseTemplate(t)
	subject, cn, san, keyTypes, curves, meta, tags, keyUsage, eku, passthroughOIDs, err := templateJSON(t)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.certificate_templates
			(slug, name, description, version, is_enabled,
			 ca_account_id, ca_profile,
			 subject_mode, subject_defaults, common_name_rule, san_rules,
			 allowed_key_types, rsa_min_bits, rsa_max_bits, ecdsa_curves,
			 csr_required, key_custody_required,
			 validity_days, max_validity_days, renew_before_days, auto_renew,
			 key_usage, extended_key_usage, basic_constraints_ca,
			 extension_passthrough, passthrough_oids, conformance,
			 require_metadata, default_environment, default_team, default_tags,
			 created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		        $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
		        $27, $28, $29, $30, $31, $32)
		RETURNING id, version, created_at, updated_at`,
		t.Slug, t.Name, t.Description, orOne(t.Version), t.IsEnabled,
		t.CAAccountID, t.CAProfile,
		t.SubjectMode, subject, cn, san,
		keyTypes, t.RSAMinBits, t.RSAMaxBits, curves,
		t.CSRRequired, t.KeyCustodyRequired,
		t.ValidityDays, t.MaxValidityDays, t.RenewBeforeDays, t.AutoRenew,
		keyUsage, eku, t.BasicConstraintsCA,
		t.ExtensionPassthrough, passthroughOIDs, t.Conformance,
		meta, t.DefaultEnvironment, t.DefaultTeam, tags,
		t.CreatedBy,
	).Scan(&t.ID, &t.Version, &t.CreatedAt, &t.UpdatedAt)
}

// UpdateCertificateTemplate writes every field the caller owns.
//
// Version is written from the record rather than incremented here. Whether an
// edit changed a rule or only a label is a question about the two versions of
// the object, and the handler is the only place that holds both.
func (s *PostgresStore) UpdateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error {
	normaliseTemplate(t)
	subject, cn, san, keyTypes, curves, meta, tags, keyUsage, eku, passthroughOIDs, err := templateJSON(t)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.certificate_templates SET
			slug = $2, name = $3, description = $4, version = $5, is_enabled = $6,
			ca_account_id = $7, ca_profile = $8,
			subject_mode = $9, subject_defaults = $10, common_name_rule = $11, san_rules = $12,
			allowed_key_types = $13, rsa_min_bits = $14, rsa_max_bits = $15, ecdsa_curves = $16,
			csr_required = $17, key_custody_required = $18,
			validity_days = $19, max_validity_days = $20, renew_before_days = $21, auto_renew = $22,
			key_usage = $23, extended_key_usage = $24, basic_constraints_ca = $25,
			extension_passthrough = $26, passthrough_oids = $27, conformance = $28,
			require_metadata = $29, default_environment = $30, default_team = $31, default_tags = $32,
			updated_at = now()
		WHERE id = $1`,
		t.ID,
		t.Slug, t.Name, t.Description, orOne(t.Version), t.IsEnabled,
		t.CAAccountID, t.CAProfile,
		t.SubjectMode, subject, cn, san,
		keyTypes, t.RSAMinBits, t.RSAMaxBits, curves,
		t.CSRRequired, t.KeyCustodyRequired,
		t.ValidityDays, t.MaxValidityDays, t.RenewBeforeDays, t.AutoRenew,
		keyUsage, eku, t.BasicConstraintsCA,
		t.ExtensionPassthrough, passthroughOIDs, t.Conformance,
		meta, t.DefaultEnvironment, t.DefaultTeam, tags,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate template %s not found", t.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteCertificateTemplate(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM public.certificate_templates WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate template %s not found", id)
	}
	return nil
}

// orOne keeps a zero version out of the database. The column refuses it, and
// the resulting CHECK violation would reach an operator as a raw SQLSTATE
// telling them nothing about which field they left unset.
func orOne(v int) int {
	if v < 1 {
		return 1
	}
	return v
}
