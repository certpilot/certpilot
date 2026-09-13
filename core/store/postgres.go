package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store using pgxpool for PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool

	// auditChain is read on every audit write and set once at startup, but a
	// mutex rather than a bare field because the engines are already running by
	// the time the server wires it in.
	auditMu    sync.RWMutex
	auditChain *AuditChainer
}

// NewPostgresStore connects to PostgreSQL using the provided connection string.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres config: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test ping
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	// A reachable database is not the same as a usable one. Preflight refuses
	// an unmigrated schema, and refuses a connection that row-level security
	// would silently filter to nothing — which would otherwise present as a
	// perfectly healthy, perfectly empty estate.
	if err := Preflight(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	slog.Info("connected to PostgreSQL")
	return &PostgresStore{pool: pool}, nil
}

// Close terminates all pool connections.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// ── Certificates ────────────────────────────────────────

// certificateColumns is the read projection for public.certificates, in the
// order scanCertificate expects.
//
// One definition rather than the four identical copies that were here before.
// They had already drifted once: private_key_encrypted was missing from all of
// them, so key export answered "no private key is stored" for every certificate
// while the column held one.
//
// The COALESCEs are load-bearing, not decoration. Several of these columns are
// nullable in the schema but map to non-pointer Go fields — days_remaining and
// key_size to int, auto_renew to bool, environment and team to string. pgx
// cannot scan NULL into those, and it fails the whole query rather than the one
// row, so a single hand-inserted or bulk-imported row with a NULL would take
// out the entire certificate list. For an inventory product people import into,
// that is a matter of when.
const certificateColumns = `id, fingerprint_sha256, common_name,
		coalesce(sans, '[]'::jsonb), coalesce(serial_number, ''), coalesce(issuer_dn, ''),
		not_before, not_after, coalesce(days_remaining, 0),
		coalesce(key_type, ''), coalesce(key_size, 0), status,
		coalesce(auto_renew, false), coalesce(renewal_lead_days, 0),
		last_renewal_attempt, renewal_error, coalesce(renewal_count, 0),
		ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		coalesce(discovered_via, 'MANUAL'), coalesce(environment, ''), coalesce(team, ''),
		coalesce(tags, '[]'::jsonb), coalesce(metadata, '{}'::jsonb), created_by, created_at, updated_at,
		renewal_scheduled_at, ari_window_start, ari_window_end,
		coalesce(ari_explanation_url, ''), ari_checked_at, ari_next_check_at, ari_supported,
		coalesce(verification_state, ''), verify_after, last_verified_at,
		coalesce(verification_attempts, 0), coalesce(verification_detail, ''),
		coalesce(previous_fingerprint, ''),
		coalesce(key_custody, 'EXTERNAL'), key_holder_agent_id,
		coalesce(signature_algorithm, ''), coalesce(public_key_algorithm, ''),
		coalesce(posture_verdict, ''), coalesce(posture_summary, ''),
		coalesce(posture_requirements, '[]'::jsonb),
		quantum_readiness_score, quantum_assessed_at,
	revoked_at, revocation_reason, coalesce(revoked_by, ''),
		template_id, template_version, grant_id, coalesce(conformance_findings, '[]'::jsonb)`

// scanCertificate reads one row of certificateColumns.
func scanCertificate(row pgx.Row) (*Certificate, error) {
	cert := &Certificate{}
	var sansJSON, tagsJSON, metadataJSON, postureJSON, findingsJSON []byte
	err := row.Scan(
		&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, &sansJSON, &cert.SerialNumber, &cert.IssuerDN,
		&cert.NotBefore, &cert.NotAfter, &cert.DaysRemaining, &cert.KeyType, &cert.KeySize, &cert.Status,
		&cert.AutoRenew, &cert.RenewalLeadDays, &cert.LastRenewalAttempt, &cert.RenewalError, &cert.RenewalCount,
		&cert.CAAccountID, &cert.CAAuthorityID, &cert.DeploymentTargetID, &cert.CertificatePEM, &cert.ChainPEM,
		&cert.DiscoveredVia, &cert.Environment, &cert.Team, &tagsJSON, &metadataJSON,
		&cert.CreatedBy, &cert.CreatedAt, &cert.UpdatedAt,
		&cert.RenewalScheduledAt, &cert.ARIWindowStart, &cert.ARIWindowEnd,
		&cert.ARIExplanationURL, &cert.ARICheckedAt, &cert.ARINextCheckAt, &cert.ARISupported,
		&cert.VerificationState, &cert.VerifyAfter, &cert.LastVerifiedAt,
		&cert.VerificationAttempts, &cert.VerificationDetail, &cert.PreviousFingerprint,
		&cert.KeyCustody, &cert.KeyHolderAgentID,
		&cert.SignatureAlgorithm, &cert.PublicKeyAlgorithm,
		&cert.PostureVerdict, &cert.PostureSummary, &postureJSON,
		&cert.QuantumReadinessScore, &cert.QuantumAssessedAt,
		&cert.RevokedAt, &cert.RevocationReason, &cert.RevokedBy,
		&cert.TemplateID, &cert.TemplateVersion, &cert.GrantID, &findingsJSON,
	)
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &cert.SANs)
	}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &cert.Tags)
	}
	// Never nil. A template indexing metadata should not need a guard, and a
	// nil map marshals to null rather than {} — which a client then has to
	// special-case on every read.
	cert.Metadata = map[string]any{}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &cert.Metadata)
	}
	cert.PostureRequirements = postureJSON
	if len(findingsJSON) > 0 {
		_ = json.Unmarshal(findingsJSON, &cert.ConformanceFindings)
	}
	return cert, nil
}

func (s *PostgresStore) ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.Environment != "" {
		where = append(where, fmt.Sprintf("environment = $%d", argIdx))
		args = append(args, filter.Environment)
		argIdx++
	}
	if filter.CommonName != "" {
		where = append(where, fmt.Sprintf("common_name ILIKE $%d", argIdx))
		args = append(args, "%"+filter.CommonName+"%")
		argIdx++
	}
	if filter.CAAccountID != "" {
		where = append(where, fmt.Sprintf("ca_account_id = $%d", argIdx))
		args = append(args, filter.CAAccountID)
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM public.certificates WHERE %s", whereClause)
	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Fetch items
	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	query := fmt.Sprintf(`
		SELECT `+certificateColumns+`
		FROM public.certificates
		WHERE %s
		ORDER BY not_after ASC NULLS LAST
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		certs = append(certs, cert)
	}

	return certs, total, nil
}

func (s *PostgresStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	query := `
		SELECT ` + certificateColumns + `
		FROM public.certificates WHERE id = $1
	`
	cert, err := scanCertificate(s.pool.QueryRow(ctx, query, id))
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (s *PostgresStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	query := `
		SELECT ` + certificateColumns + `
		FROM public.certificates WHERE fingerprint_sha256 = $1
	`
	cert, err := scanCertificate(s.pool.QueryRow(ctx, query, fingerprint))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (s *PostgresStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	sansJSON, _ := json.Marshal(cert.SANs)
	tagsJSON, _ := json.Marshal(cert.Tags)

	// Calculate days remaining
	daysRemaining := 0
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			daysRemaining = int(d)
		}
	}
	cert.DaysRemaining = daysRemaining

	query := `
		INSERT INTO public.certificates (
			fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
			not_before, not_after, days_remaining, key_type, key_size, status,
			auto_renew, renewal_lead_days, ca_account_id, ca_authority_id,
			deployment_target_id, private_key_encrypted, certificate_pem, chain_pem,
			discovered_via, environment, team, tags, created_by,
			key_custody, key_holder_agent_id, metadata,
			revoked_at, revocation_reason, revoked_by,
			template_id, template_version, grant_id, conformance_findings
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
			$25, $26, $27, $28, $29, $30, $31, $32, $33, $34
		) RETURNING id, created_at, updated_at
	`
	// The revocation columns are written here even though revocation itself
	// goes through MarkCertificateRevoked.
	//
	// Migration 030 requires status = 'REVOKED' and revoked_at to agree, and
	// this statement did not name the columns at all — so a discovery or CT
	// import of a certificate that is already revoked set the status, dropped
	// the timestamp, and had the whole insert refused by the CHECK. Store
	// defect class B, a model field a writer silently drops, with class A's
	// symptom on top of it: the value is one the Go code produces and the
	// schema rejects. The in-memory store has no constraint, so it accepted the
	// inconsistent pair and the suite agreed with itself.
	return s.pool.QueryRow(ctx, query,
		cert.FingerprintSHA256, cert.CommonName, sansJSON, cert.SerialNumber, cert.IssuerDN,
		cert.NotBefore, cert.NotAfter, cert.DaysRemaining, cert.KeyType, cert.KeySize, cert.Status,
		cert.AutoRenew, cert.RenewalLeadDays, cert.CAAccountID, cert.CAAuthorityID,
		cert.DeploymentTargetID, cert.PrivateKeyEncrypted, cert.CertificatePEM, cert.ChainPEM,
		cert.DiscoveredVia, nullIfEmpty(cert.Environment), cert.Team, tagsJSON, cert.CreatedBy,
		custodyOrDefault(cert), cert.KeyHolderAgentID, metadataJSON(cert.Metadata),
		cert.RevokedAt, cert.RevocationReason, cert.RevokedBy,
		cert.TemplateID, cert.TemplateVersion, cert.GrantID, findingsOrEmpty(cert.ConformanceFindings),
	).Scan(&cert.ID, &cert.CreatedAt, &cert.UpdatedAt)
}

// managedOrDefault fills in a management state the caller left blank.
//
// The column carries `default 'UNMANAGED'` and a CHECK that refuses anything
// else, and passing an explicit empty string overrides the default rather than
// falling back to it — so the CHECK rejects the row and the whole write fails.
// The same shape as agents.heartbeat_interval_seconds, where an explicit zero
// overrode `DEFAULT 300` and violated a positive check; see docs/database.md.
//
// UNMANAGED is the honest fill-in on all three tables that use it. A discovered,
// logged or cloud-held certificate that nothing has matched to one CertPilot
// manages is, precisely, unmanaged.
func managedOrDefault(state string) string {
	if strings.TrimSpace(state) == "" {
		return DiscoveryUnmanaged
	}
	return state
}

// trustedOrDefault does the same for discovery's trust_state, which carries
// `default 'UNKNOWN'` under the same trap.
func trustedOrDefault(state string) string {
	if strings.TrimSpace(state) == "" {
		return TrustUnknown
	}
	return state
}

// metadataJSON encodes a metadata map for a jsonb column that is NOT NULL.
// A nil map marshals to `null`, which the column refuses.
func metadataJSON(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	encoded, err := json.Marshal(m)
	if err != nil || len(encoded) == 0 {
		return []byte("{}")
	}
	return encoded
}

func (s *PostgresStore) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	sansJSON, _ := json.Marshal(cert.SANs)
	tagsJSON, _ := json.Marshal(cert.Tags)

	daysRemaining := 0
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			daysRemaining = int(d)
		}
	}
	cert.DaysRemaining = daysRemaining

	query := `
		UPDATE public.certificates SET
			fingerprint_sha256 = $2, common_name = $3, sans = $4, serial_number = $5, issuer_dn = $6,
			not_before = $7, not_after = $8, days_remaining = $9, key_type = $10, key_size = $11, status = $12,
			auto_renew = $13, renewal_lead_days = $14, last_renewal_attempt = $15, renewal_error = $16,
			renewal_count = $17, ca_account_id = $18, ca_authority_id = $19, deployment_target_id = $20,
			certificate_pem = $21, chain_pem = $22, environment = $23, team = $24, tags = $25,
			private_key_encrypted = COALESCE($26::text, private_key_encrypted),
			key_custody = $27, key_holder_agent_id = $28,
			metadata = COALESCE($29::jsonb, metadata),
			-- COALESCE for the same reason as the two above. Provenance is set
			-- once, at issuance, and every other writer builds a partial record:
			-- renewal from a gateway response, verification from a probe, the
			-- ARI poller from a CA's advice. Any of them assigning nil here
			-- would erase which rules a certificate was issued under, and that
			-- is the one field whose whole purpose is to still be true later.
			template_id = COALESCE($30::uuid, template_id),
			template_version = COALESCE($31::integer, template_version),
			grant_id = COALESCE($32::uuid, grant_id),
			-- COALESCE for the same reason as metadata: #30's conformance check
			-- runs once, right after issuance or renewal, and every other writer
			-- of this row — UpdateCertificateMetadata, the posture assessor, the
			-- ARI poller — has nothing to say about it. Assigning unconditionally
			-- would erase a genuine finding the moment an operator relabels the
			-- certificate's team.
			conformance_findings = COALESCE($33::jsonb, conformance_findings),
			updated_at = now()
		WHERE id = $1
	`
	// COALESCE, because both directions were wrong before.
	//
	// The column was absent from this statement entirely, so renewal — which
	// rotates the key, seals it, and sets it on the record — silently discarded
	// the new key and left the old one paired with the new certificate. Anyone
	// who then exported the key and deployed the pair would have got a
	// handshake failure, from a record the dashboard showed as healthy.
	//
	// Assigning it unconditionally would be the opposite mistake: no read path
	// populates this field, so every ordinary update would erase the key.
	// COALESCE writes a key when the caller supplies one and preserves the
	// stored one when it does not.
	_, err := s.pool.Exec(ctx, query,
		cert.ID, cert.FingerprintSHA256, cert.CommonName, sansJSON, cert.SerialNumber, cert.IssuerDN,
		cert.NotBefore, cert.NotAfter, cert.DaysRemaining, cert.KeyType, cert.KeySize, cert.Status,
		cert.AutoRenew, cert.RenewalLeadDays, cert.LastRenewalAttempt, cert.RenewalError,
		cert.RenewalCount, cert.CAAccountID, cert.CAAuthorityID, cert.DeploymentTargetID,
		cert.CertificatePEM, cert.ChainPEM, nullIfEmpty(cert.Environment), cert.Team, tagsJSON,
		cert.PrivateKeyEncrypted, custodyOrDefault(cert), cert.KeyHolderAgentID,
		// COALESCE for the same reason as the key above: renewal builds a record
		// from the gateway's response and carries no metadata, so assigning
		// unconditionally would wipe an operator's cost centre every time a
		// certificate renewed itself.
		nullableMetadata(cert.Metadata),
		cert.TemplateID, cert.TemplateVersion, cert.GrantID, nullableFindings(cert.ConformanceFindings),
	)
	return err
}

// nullableMetadata returns nil when there is nothing to write, so the COALESCE
// above preserves what is stored.
func nullableMetadata(m map[string]any) []byte {
	if len(m) == 0 {
		return nil
	}
	return metadataJSON(m)
}

// findingsOrEmpty encodes conformance findings for INSERT, where the column is
// NOT NULL and there is no existing row for COALESCE to fall back to — nil
// becomes '[]', not SQL NULL.
func findingsOrEmpty(f []ConformanceFinding) []byte {
	if len(f) == 0 {
		return []byte("[]")
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return []byte("[]")
	}
	return encoded
}

// nullableFindings is findingsOrEmpty's UPDATE counterpart: nil stays NULL so
// the COALESCE above preserves whatever is already stored, the same contract
// nullableMetadata gives metadata.
func nullableFindings(f []ConformanceFinding) []byte {
	if f == nil {
		return nil
	}
	return findingsOrEmpty(f)
}

// custodyOrDefault fills in who holds the key when a caller did not say.
//
// Derived from whether a key is being stored, which is exactly what migration
// 020's backfill did to the existing rows. Without this, every path that builds
// a Certificate without setting the field — and there are several — would write
// an empty string into a checked column and fail, which is migration 012's
// lesson arriving a second time.
func custodyOrDefault(cert *Certificate) string {
	if cert.KeyCustody != "" {
		return cert.KeyCustody
	}
	if cert.PrivateKeyEncrypted != nil && *cert.PrivateKeyEncrypted != "" {
		return KeyCustodyCertPilot
	}
	return KeyCustodyExternal
}

// nullIfEmpty maps Go's zero value for a string to SQL NULL.
//
// Needed because several nullable columns carry a CHECK constraint —
// certificates.environment is `check (environment in ('production', 'staging',
// 'development'))`. A CHECK passes on NULL and fails on ”, so a field the
// caller simply did not set is rejected by the database while an absent one is
// accepted. Issuing a certificate without naming an environment is the ordinary
// case, and before this it failed outright on PostgreSQL with a constraint
// violation naming a column the request never mentioned.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GetCertificatePrivateKey reads the sealed key for exactly one certificate.
func (s *PostgresStore) GetCertificatePrivateKey(ctx context.Context, id string) (string, error) {
	var sealed *string
	err := s.pool.QueryRow(ctx,
		"SELECT private_key_encrypted FROM public.certificates WHERE id = $1", id).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("certificate %s not found", id)
	}
	if err != nil {
		return "", err
	}
	if sealed == nil {
		return "", nil
	}
	return *sealed, nil
}

func (s *PostgresStore) DeleteCertificate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.certificates WHERE id = $1", id)
	return err
}

func (s *PostgresStore) GetCertificatesDueForRenewal(ctx context.Context, defaultLeadDays int) ([]*Certificate, error) {
	// Two ways to be due, and the CA's advice takes precedence over the lead
	// time when there is any — it is better information, because the CA knows
	// things about the certificate that the certificate does not say.
	//
	// But never off a cliff. The safety floor is the second half of the CASE:
	// however far out the CA suggests renewing, a certificate inside the
	// hard-floor window renews anyway. A CA that publishes a bad window, or a
	// poller that stopped running and left a stale one, must not be able to
	// talk this system out of renewing something that is about to expire.
	query := `
		SELECT ` + certificateColumns + `
		FROM public.certificates
		WHERE auto_renew = true
		  AND status IN ('ISSUED', 'EXPIRING', 'RENEWAL_FAILED')
		  -- A certificate whose key CertPilot does not hold cannot be renewed
		  -- from here: renewing means generating a key, and for these the whole
		  -- point is that this process never has one. An agent renews its own
		  -- by sending a new request; an externally held key is renewed by
		  -- whoever holds it, submitting a new signing request.
		  --
		  -- Without this the queue would pick them up and fail on every attempt
		  -- forever, which is a loud way of being wrong about something that is
		  -- working perfectly.
		  --
		  -- NULL stays eligible. It means nobody recorded custody, which is true
		  -- of rows predating the column, and excluding them would silently stop
		  -- renewing certificates that have been renewing all along.
		  AND coalesce(key_custody, '') NOT IN ('AGENT', 'EXTERNAL')
		  AND CASE
		        WHEN renewal_scheduled_at IS NOT NULL THEN
		          renewal_scheduled_at <= now()
		          OR not_after <= (now() + make_interval(days => $2))
		        ELSE
		          not_after <= (now() + (COALESCE(renewal_lead_days, $1) || ' days')::interval)
		      END
	`
	rows, err := s.pool.Query(ctx, query, defaultLeadDays, RenewalSafetyFloorDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ── CA Authorities ──────────────────────────────────────

// caColumns builds the CA authority select list.
//
// The PEM is substituted with an empty literal rather than omitted, so the
// column count and scan order stay identical either way — a select list that
// changes shape with a flag is how a scan target ends up one column out of
// alignment and a fingerprint gets written into a status field.
func caColumns(includePEM bool) string {
	pem := `''::text`
	if includePEM {
		pem = `certificate_pem`
	}
	// COALESCE for the same reason as certificateColumns: these columns are
	// nullable in the schema but scan into non-pointer Go fields, and pgx fails
	// the whole query on a NULL rather than the single row. A CA list that
	// 500s because one row has a null CRL URL is a blank monitoring screen.
	return `id, name, ca_type, subject_dn, issuer_dn, coalesce(serial_number, ''),
		not_before, not_after, coalesce(days_remaining, 0), key_type, key_size,
		fingerprint_sha256, ` + pem + `, parent_ca_id, coalesce(crl_distribution_url, ''),
		coalesce(ocsp_responder_url, ''), coalesce(is_crl_fresh, false), crl_last_checked,
		coalesce(is_ocsp_responsive, false),
		ocsp_last_checked, coalesce(ocsp_status, ''), ocsp_revoked_at,
		coalesce(ocsp_last_error, ''), coalesce(certificates_issued_count, 0),
		coalesce(alert_thresholds, '[]'::jsonb),
		last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		owner_team, owner_email,
		coalesce(tags, '[]'::jsonb), coalesce(notes, ''),
		coalesce(source, 'MANUAL'), last_seen_at, created_at, updated_at`
}

func scanCAAuthority(row pgx.Row) (*CAAuthority, error) {
	ca := &CAAuthority{}
	var alertsJSON, tagsJSON []byte
	err := row.Scan(
		&ca.ID, &ca.Name, &ca.CAType, &ca.SubjectDN, &ca.IssuerDN, &ca.SerialNumber,
		&ca.NotBefore, &ca.NotAfter, &ca.DaysRemaining, &ca.KeyType, &ca.KeySize,
		&ca.FingerprintSHA256, &ca.CertificatePEM, &ca.ParentCAID, &ca.CRLDistributionURL,
		&ca.OCSPResponderURL, &ca.IsCRLFresh, &ca.CRLLastChecked, &ca.IsOCSPResponsive,
		&ca.OCSPLastChecked, &ca.OCSPStatus, &ca.OCSPRevokedAt, &ca.OCSPLastError,
		&ca.CertificatesIssuedCount, &alertsJSON,
		&ca.LastAlertSentAt, &ca.LastAlertThreshold, &ca.Status, &ca.CAAccountID,
		&ca.OwnerTeam, &ca.OwnerEmail,
		&tagsJSON, &ca.Notes, &ca.Source, &ca.LastSeenAt, &ca.CreatedAt, &ca.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	ca.AlertThresholds = string(alertsJSON)
	ca.Tags = string(tagsJSON)
	return ca, nil
}

func (s *PostgresStore) ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.ExpiringWithinDays > 0 {
		// Against not_after, not the cached days_remaining — see CAFilter.
		//
		// make_interval rather than ($n || ' days')::interval. In the string
		// form both sides of `||` are untyped, so PostgreSQL resolves the
		// operator as text || text and reports the parameter as text — and the
		// driver, holding an int, fails to encode it. The query is not wrong so
		// much as untypable, and it fails at bind time on every call.
		where = append(where, fmt.Sprintf("not_after <= now() + make_interval(days => $%d)", argIdx))
		args = append(args, filter.ExpiringWithinDays)
		// Nothing reads argIdx after this, and it is incremented anyway. The
		// next filter added below will use it, and a filter added without it
		// would bind its value to a parameter another clause already claimed —
		// which is not a compile error, not a runtime error, and returns the
		// wrong rows.
		//lint:ignore SA4006 deliberate: see above
		argIdx++
	}
	if filter.ExcludeExpired {
		where = append(where, "not_after > now()")
	}

	order := "name ASC"
	if filter.Sort == CASortUrgency {
		order = "not_after ASC, name ASC"
	}

	query := fmt.Sprintf("SELECT %s FROM public.ca_authorities WHERE %s ORDER BY %s",
		caColumns(filter.IncludePEM), strings.Join(where, " AND "), order)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cas := []*CAAuthority{}
	for rows.Next() {
		ca, err := scanCAAuthority(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

func (s *PostgresStore) GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error) {
	// A detail read includes the PEM: it is the one place someone is looking at
	// a single CA and may want the certificate itself.
	ca, err := scanCAAuthority(s.pool.QueryRow(ctx,
		"SELECT "+caColumns(true)+" FROM public.ca_authorities WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("CA authority %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	return ca, nil
}

// GetCAAuthorityByFingerprint finds a CA by the certificate itself.
//
// Nothing found is not an error. The importer asks this about every issuer a
// gateway offers, and returning an error for the ordinary answer would make
// "this CA is new" indistinguishable from "the database is unreachable".
func (s *PostgresStore) GetCAAuthorityByFingerprint(ctx context.Context, fingerprint string) (*CAAuthority, error) {
	ca, err := scanCAAuthority(s.pool.QueryRow(ctx,
		"SELECT "+caColumns(true)+" FROM public.ca_authorities WHERE fingerprint_sha256 = $1", fingerprint))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ca, nil
}

func (s *PostgresStore) CreateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	daysRemaining := 0
	d := time.Until(ca.NotAfter).Hours() / 24
	if d > 0 {
		daysRemaining = int(d)
	}
	ca.DaysRemaining = daysRemaining

	query := `
		INSERT INTO public.ca_authorities (
			name, ca_type, subject_dn, issuer_dn, serial_number, not_before, not_after,
			days_remaining, key_type, key_size, fingerprint_sha256, certificate_pem,
			parent_ca_id, crl_distribution_url, ocsp_responder_url, ca_account_id,
			status, notes, owner_team, owner_email, source, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
		RETURNING id, created_at, updated_at
	`
	// An empty source would violate the check constraint rather than take the
	// column default, which is the same shape of defect as the agent heartbeat
	// interval: an explicit zero value overrides a DEFAULT.
	if strings.TrimSpace(ca.Source) == "" {
		ca.Source = CASourceManual
	}
	return s.pool.QueryRow(ctx, query,
		ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber, ca.NotBefore, ca.NotAfter,
		ca.DaysRemaining, ca.KeyType, ca.KeySize, ca.FingerprintSHA256, ca.CertificatePEM,
		ca.ParentCAID, ca.CRLDistributionURL, ca.OCSPResponderURL, ca.CAAccountID,
		ca.Status, ca.Notes, ca.OwnerTeam, ca.OwnerEmail, ca.Source, ca.LastSeenAt,
	).Scan(&ca.ID, &ca.CreatedAt, &ca.UpdatedAt)
}

func (s *PostgresStore) UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	daysRemaining := 0
	d := time.Until(ca.NotAfter).Hours() / 24
	if d > 0 {
		daysRemaining = int(d)
	}
	ca.DaysRemaining = daysRemaining

	// certificate_pem is deliberately absent from this statement.
	//
	// A CA's certificate is written once, at registration, and no code path
	// replaces it. Leaving it in the update made the read path dangerous: the
	// health sweep reads a CA, mutates it, and writes it back, so any caller
	// that listed without CAFilter.IncludePEM and then updated would have
	// silently blanked the column — and the next sweep would have had nothing
	// to parse, reporting the CA as UNKNOWN rather than expiring. Dropping the
	// column here removes the trap rather than relying on every caller to
	// remember it.
	query := `
		UPDATE public.ca_authorities SET
			name = $2, ca_type = $3, subject_dn = $4, issuer_dn = $5, serial_number = $6,
			not_before = $7, not_after = $8, days_remaining = $9, key_type = $10, key_size = $11,
			fingerprint_sha256 = $12, parent_ca_id = $13,
			crl_distribution_url = $14, ocsp_responder_url = $15, is_crl_fresh = $16,
			crl_last_checked = $17, is_ocsp_responsive = $18, ocsp_last_checked = $19,
			certificates_issued_count = $20, alert_thresholds = $21,
			last_alert_sent_at = $22, last_alert_threshold = $23,
			status = $24, ca_account_id = $25, tags = $26, notes = $27,
			owner_team = $28, owner_email = $29,
			source = $30, last_seen_at = $31,
			ocsp_status = $32, ocsp_revoked_at = $33, ocsp_last_error = $34,
			updated_at = now()
		WHERE id = $1
	`
	if strings.TrimSpace(ca.Source) == "" {
		ca.Source = CASourceManual
	}
	_, err := s.pool.Exec(ctx, query,
		ca.ID, ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber,
		ca.NotBefore, ca.NotAfter, ca.DaysRemaining, ca.KeyType, ca.KeySize,
		ca.FingerprintSHA256, ca.ParentCAID,
		ca.CRLDistributionURL, ca.OCSPResponderURL, ca.IsCRLFresh,
		ca.CRLLastChecked, ca.IsOCSPResponsive, ca.OCSPLastChecked,
		ca.CertificatesIssuedCount, jsonbOrNil(ca.AlertThresholds),
		ca.LastAlertSentAt, ca.LastAlertThreshold,
		ca.Status, ca.CAAccountID, jsonbOrNil(ca.Tags), ca.Notes,
		ca.OwnerTeam, ca.OwnerEmail, ca.Source, ca.LastSeenAt,
		// nullIfEmpty because ocsp_status carries a CHECK that refuses the
		// empty string. "Never asked" is NULL, and it is a different fact from
		// UNKNOWN — which is the responder disclaiming knowledge of a
		// certificate it ought to know about.
		nullIfEmpty(ca.OCSPStatus), ca.OCSPRevokedAt, nullIfEmpty(ca.OCSPLastError),
	)
	return err
}

// jsonbOrNil renders a string field destined for a jsonb column.
//
// These are held as strings on the model and read back as "" when the column is
// NULL. Handing that empty string straight to Postgres is a syntax error on
// jsonb, which would have turned "this CA has no tags" into a failed health
// sweep.
func jsonbOrNil(s string) []byte {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []byte(s)
}

func (s *PostgresStore) DeleteCAAuthority(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.ca_authorities WHERE id = $1", id)
	return err
}

func (s *PostgresStore) GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error) {
	// The CTE selects whole rows rather than naming columns.
	//
	// It used to enumerate them, and the list drifted from the one caColumns
	// builds: migration 006 added owner_team and owner_email, the scanner
	// learned about them, this did not, and every call failed against a real
	// database with "column owner_team does not exist". The in-memory store
	// walks a map and cannot express that mistake, so nothing caught it.
	//
	// Naming the columns correctly would fix the instance. Not keeping a second
	// list fixes the class.
	//
	// The depth cap is not about deep hierarchies — nobody has sixteen tiers of
	// CA. parent_ca_id is a plain self-reference with nothing preventing a
	// cycle, and a cycle here is a recursive query that never returns while
	// holding a connection.
	query := `
		WITH RECURSIVE ca_chain AS (
			SELECT a.*, 1 AS depth
			FROM public.ca_authorities a WHERE a.id = $1
			UNION ALL
			SELECT parent.*, child.depth + 1
			FROM public.ca_authorities parent
			INNER JOIN ca_chain child ON child.parent_ca_id = parent.id
			WHERE child.depth < 16
		)
		SELECT ` + caColumns(true) + `
		FROM ca_chain ORDER BY depth ASC
	`
	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	chain := []*CAAuthority{}
	for rows.Next() {
		// Via the shared scanner, which also populates AlertThresholds and
		// Tags. The hand-written scan this replaced read both columns and then
		// dropped them on the floor, so every CA in a chain response reported
		// no configured thresholds regardless of what was stored.
		ca, err := scanCAAuthority(rows)
		if err != nil {
			return nil, err
		}
		chain = append(chain, ca)
	}
	return chain, rows.Err()
}

// ── CA Accounts ─────────────────────────────────────────

func (s *PostgresStore) ListCAAccounts(ctx context.Context) ([]*CAAccount, error) {
	query := `
		SELECT id, name, provider_type, gateway_addr, config_encrypted, is_default,
		       status, last_health_at, coalesce(renewal_rate_limit, 0),
		       coalesce(renewal_rate_window_hours, 168), created_by, created_at, updated_at
		FROM public.ca_accounts ORDER BY name ASC
	`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := []*CAAccount{}
	for rows.Next() {
		acc := &CAAccount{}
		err := rows.Scan(
			&acc.ID, &acc.Name, &acc.ProviderType, &acc.GatewayAddr, &acc.ConfigEncrypted,
			&acc.IsDefault, &acc.Status, &acc.LastHealthAt,
			&acc.RenewalRateLimit, &acc.RenewalRateWindowHours, &acc.CreatedBy,
			&acc.CreatedAt, &acc.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (s *PostgresStore) GetCAAccount(ctx context.Context, id string) (*CAAccount, error) {
	query := `
		SELECT id, name, provider_type, gateway_addr, config_encrypted, is_default,
		       status, last_health_at, coalesce(renewal_rate_limit, 0),
		       coalesce(renewal_rate_window_hours, 168), created_by, created_at, updated_at
		FROM public.ca_accounts WHERE id::text = $1 OR name = $1
	`
	acc := &CAAccount{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&acc.ID, &acc.Name, &acc.ProviderType, &acc.GatewayAddr, &acc.ConfigEncrypted,
		&acc.IsDefault, &acc.Status, &acc.LastHealthAt,
		&acc.RenewalRateLimit, &acc.RenewalRateWindowHours, &acc.CreatedBy,
		&acc.CreatedAt, &acc.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("CA account %s not found", id)
	}
	return acc, err
}

func (s *PostgresStore) CreateCAAccount(ctx context.Context, acc *CAAccount) error {
	query := `
		INSERT INTO public.ca_accounts (name, provider_type, gateway_addr, config_encrypted,
			is_default, status, renewal_rate_limit, renewal_rate_window_hours)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		acc.Name, acc.ProviderType, acc.GatewayAddr, acc.ConfigEncrypted, acc.IsDefault, acc.Status,
		acc.RenewalRateLimit, defaultWindowHours(acc.RenewalRateWindowHours),
	).Scan(&acc.ID, &acc.CreatedAt, &acc.UpdatedAt)
}

func (s *PostgresStore) UpdateCAAccount(ctx context.Context, acc *CAAccount) error {
	query := `
		UPDATE public.ca_accounts SET
			name = $2, provider_type = $3, gateway_addr = $4, config_encrypted = $5,
			is_default = $6, status = $7, last_health_at = $8,
			renewal_rate_limit = $9, renewal_rate_window_hours = $10, updated_at = now()
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		acc.ID, acc.Name, acc.ProviderType, acc.GatewayAddr, acc.ConfigEncrypted,
		acc.IsDefault, acc.Status, acc.LastHealthAt,
		acc.RenewalRateLimit, defaultWindowHours(acc.RenewalRateWindowHours),
	)
	return err
}

func (s *PostgresStore) DeleteCAAccount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.ca_accounts WHERE id = $1", id)
	return err
}

// ── Deployment targets ──────────────────────────────────

// deploymentTargetColumns is the read shape, in one place so a column added to
// the table cannot be picked up by the list query and missed by the detail one.
const deploymentTargetColumns = `id, name, coalesce(description, ''), target_type,
		coalesce(config_encrypted, ''), coalesce(is_enabled, true), coalesce(deploys_private_key, false),
		coalesce(deploy_order, 0), cloud_connection_id, agent_id,
		last_deployment_at, last_deployment_status, coalesce(last_deployment_error, ''), last_success_at,
		created_by, created_at, updated_at`

func scanDeploymentTarget(row pgx.Row) (*DeploymentTarget, error) {
	t := &DeploymentTarget{}
	err := row.Scan(&t.ID, &t.Name, &t.Description, &t.TargetType,
		&t.ConfigEncrypted, &t.IsEnabled, &t.DeploysPrivateKey, &t.DeployOrder,
		&t.CloudConnectionID, &t.AgentID,
		&t.LastDeploymentAt, &t.LastDeploymentStatus, &t.LastDeploymentError, &t.LastSuccessAt,
		&t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *PostgresStore) ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+deploymentTargetColumns+" FROM public.deployment_targets ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := []*DeploymentTarget{}
	for rows.Next() {
		t, err := scanDeploymentTarget(rows)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

func (s *PostgresStore) GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error) {
	t, err := scanDeploymentTarget(s.pool.QueryRow(ctx,
		"SELECT "+deploymentTargetColumns+" FROM public.deployment_targets WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("deployment target %s not found", id)
	}
	return t, err
}

func (s *PostgresStore) CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.deployment_targets
			(name, description, target_type, config_encrypted, is_enabled, deploys_private_key,
			 deploy_order, cloud_connection_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`,
		target.Name, nullIfEmpty(target.Description), target.TargetType,
		nullIfEmpty(target.ConfigEncrypted), target.IsEnabled, target.DeploysPrivateKey,
		target.DeployOrder, target.CloudConnectionID, target.CreatedBy,
	).Scan(&target.ID, &target.CreatedAt, &target.UpdatedAt)
}

func (s *PostgresStore) UpdateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.deployment_targets
		SET name = $2, description = $3, target_type = $4, config_encrypted = $5,
		    is_enabled = $6, deploys_private_key = $7, cloud_connection_id = $8,
		    deploy_order = $9, updated_at = now()
		WHERE id = $1`,
		target.ID, target.Name, nullIfEmpty(target.Description), target.TargetType,
		nullIfEmpty(target.ConfigEncrypted), target.IsEnabled, target.DeploysPrivateKey,
		target.CloudConnectionID, target.DeployOrder)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment target %s not found", target.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteDeploymentTarget(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.deployment_targets WHERE id = $1", id)
	return err
}

// MarkDeploymentTargetUsed records one deploy against the target.
//
// last_deployment_at always moves; last_success_at only when it worked. The
// same split ct_monitors and cloud_connections carry, for the same reason: a
// target that has been failing all week must not read as one that simply has
// had nothing to do.
func (s *PostgresStore) MarkDeploymentTargetUsed(ctx context.Context, id string,
	at time.Time, success bool, detail string) error {
	status := DeploymentFailed
	if success {
		status = DeploymentDeployed
	}

	query := `
		UPDATE public.deployment_targets
		SET last_deployment_at = $2,
		    last_deployment_status = $3,
		    last_deployment_error = $4,
		    updated_at = now()`
	if success {
		query += ", last_success_at = $2"
	}
	query += " WHERE id = $1"

	errText := ""
	if !success {
		errText = detail
	}
	_, err := s.pool.Exec(ctx, query, id, at, status, nullIfEmpty(errText))
	return err
}

// ── Certificate ↔ target bindings ───────────────────────

const certificateDeploymentColumns = `d.id, d.certificate_id, d.target_id, coalesce(d.is_enabled, true),
		coalesce(d.deploy_on_renewal, false),
		coalesce(d.options, '{}'::jsonb), coalesce(d.deployed_fingerprint, ''), d.deployed_at,
		coalesce(d.last_status, ''), coalesce(d.last_error, ''),
		d.created_by, d.created_at, d.updated_at,
		coalesce(t.name, ''), coalesce(t.target_type, '')`

func scanCertificateDeployment(row pgx.Row) (*CertificateDeployment, error) {
	d := &CertificateDeployment{}
	var optionsJSON []byte
	err := row.Scan(&d.ID, &d.CertificateID, &d.TargetID, &d.IsEnabled, &d.DeployOnRenewal,
		&optionsJSON, &d.DeployedFingerprint, &d.DeployedAt,
		&d.LastStatus, &d.LastError,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		&d.TargetName, &d.TargetType)
	if err != nil {
		return nil, err
	}
	if len(optionsJSON) > 0 {
		_ = json.Unmarshal(optionsJSON, &d.Options)
	}
	return d, nil
}

func (s *PostgresStore) ListCertificateDeployments(ctx context.Context, certificateID string) ([]*CertificateDeployment, error) {
	query := "SELECT " + certificateDeploymentColumns + `
		FROM public.certificate_deployments d
		LEFT JOIN public.deployment_targets t ON t.id = d.target_id`
	args := []any{}
	if certificateID != "" {
		query += " WHERE d.certificate_id = $1"
		args = append(args, certificateID)
	}
	query += " ORDER BY t.name ASC, d.created_at ASC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*CertificateDeployment{}
	for rows.Next() {
		d, err := scanCertificateDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetCertificateDeployment(ctx context.Context, id string) (*CertificateDeployment, error) {
	d, err := scanCertificateDeployment(s.pool.QueryRow(ctx,
		"SELECT "+certificateDeploymentColumns+`
		 FROM public.certificate_deployments d
		 LEFT JOIN public.deployment_targets t ON t.id = d.target_id
		 WHERE d.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("deployment %s not found", id)
	}
	return d, err
}

func (s *PostgresStore) CreateCertificateDeployment(ctx context.Context, d *CertificateDeployment) error {
	options := d.Options
	if options == nil {
		options = map[string]any{}
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return err
	}

	// ON CONFLICT rather than an error: binding a certificate to a target it is
	// already bound to is a request for a state that already holds, and the
	// caller wants the row either way.
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.certificate_deployments
			(certificate_id, target_id, is_enabled, deploy_on_renewal, options, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (certificate_id, target_id) DO UPDATE
		SET is_enabled = excluded.is_enabled, deploy_on_renewal = excluded.deploy_on_renewal,
		    options = excluded.options, updated_at = now()
		RETURNING id, created_at, updated_at`,
		d.CertificateID, d.TargetID, d.IsEnabled, d.DeployOnRenewal, optionsJSON, d.CreatedBy,
	).Scan(&d.ID, &d.CreatedAt, &d.UpdatedAt)
}

func (s *PostgresStore) DeleteCertificateDeployment(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.certificate_deployments WHERE id = $1", id)
	return err
}

// RecordDeploymentOutcome writes what one attempt did to one binding.
//
// deployed_fingerprint moves only on success, and only to what was actually
// installed. A failed deploy leaves the previous value alone, because the place
// is still holding whatever it was holding — overwriting it with the
// fingerprint that failed to arrive would be the record claiming a deployment
// that did not happen.
func (s *PostgresStore) RecordDeploymentOutcome(ctx context.Context, id string, outcome DeploymentOutcome) error {
	query := `
		UPDATE public.certificate_deployments
		SET last_status = $2, last_error = $3, updated_at = now()`
	args := []any{id, outcome.Status, nullIfEmpty(outcome.Error)}

	if outcome.Status == DeploymentDeployed && outcome.Fingerprint != "" {
		args = append(args, outcome.Fingerprint, outcome.At)
		query += ", deployed_fingerprint = $4, deployed_at = $5"
	}
	query += " WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment %s not found", id)
	}
	return nil
}

// ── Policies ────────────────────────────────────────────

func (s *PostgresStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, description, is_enabled, rule_type, rule_config, domain_pattern, severity, created_by, created_at, updated_at FROM public.policies ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := []*Policy{}
	for rows.Next() {
		p := &Policy{}
		var cfgJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.IsEnabled, &p.RuleType, &cfgJSON, &p.DomainPattern, &p.Severity, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.RuleConfig = string(cfgJSON)
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *PostgresStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	p := &Policy{}
	var cfgJSON []byte
	err := s.pool.QueryRow(ctx, "SELECT id, name, description, is_enabled, rule_type, rule_config, domain_pattern, severity, created_by, created_at, updated_at FROM public.policies WHERE id = $1", id).Scan(
		&p.ID, &p.Name, &p.Description, &p.IsEnabled, &p.RuleType, &cfgJSON, &p.DomainPattern, &p.Severity, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	p.RuleConfig = string(cfgJSON)
	return p, err
}

func (s *PostgresStore) CreatePolicy(ctx context.Context, p *Policy) error {
	return s.pool.QueryRow(ctx, "INSERT INTO public.policies (name, description, is_enabled, rule_type, rule_config, domain_pattern, severity) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at, updated_at",
		p.Name, p.Description, p.IsEnabled, p.RuleType, []byte(p.RuleConfig), p.DomainPattern, p.Severity,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	_, err := s.pool.Exec(ctx, "UPDATE public.policies SET name = $2, description = $3, is_enabled = $4, rule_type = $5, rule_config = $6, domain_pattern = $7, severity = $8, updated_at = now() WHERE id = $1",
		p.ID, p.Name, p.Description, p.IsEnabled, p.RuleType, []byte(p.RuleConfig), p.DomainPattern, p.Severity,
	)
	return err
}

func (s *PostgresStore) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.policies WHERE id = $1", id)
	return err
}

// ── Display Tokens ──────────────────────────────────────

const displayTokenColumns = `id, name, token_hash, expires_at, last_seen_at,
	host(last_seen_ip), revoked_at, revoked_by, created_by, created_at`

func scanDisplayToken(row pgx.Row) (*DisplayToken, error) {
	t := &DisplayToken{}
	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.ExpiresAt, &t.LastSeenAt,
		&t.LastSeenIP, &t.RevokedAt, &t.RevokedBy, &t.CreatedBy, &t.CreatedAt)
	return t, err
}

func (s *PostgresStore) ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+displayTokenColumns+" FROM public.display_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make([]*DisplayToken, 0)
	for rows.Next() {
		t, err := scanDisplayToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetDisplayTokenByHash resolves a presented token.
//
// The equality is on the hash rather than on the secret, so the query plan
// leaks nothing an attacker can steer: to influence the comparison they would
// already need a preimage of a 256-bit CSPRNG output.
func (s *PostgresStore) GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error) {
	t, err := scanDisplayToken(s.pool.QueryRow(ctx,
		"SELECT "+displayTokenColumns+" FROM public.display_tokens WHERE token_hash = $1", tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("display token not found")
	}
	return t, err
}

func (s *PostgresStore) CreateDisplayToken(ctx context.Context, t *DisplayToken) error {
	query := `
		INSERT INTO public.display_tokens (name, token_hash, expires_at, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`
	return s.pool.QueryRow(ctx, query, t.Name, t.TokenHash, t.ExpiresAt, t.CreatedBy).
		Scan(&t.ID, &t.CreatedAt)
}

func (s *PostgresStore) RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error {
	// `revoked_at is null` keeps the original revocation time and actor: who
	// first pulled the credential is the answer an incident review needs, not
	// whoever clicked the button again afterwards.
	tag, err := s.pool.Exec(ctx,
		"UPDATE public.display_tokens SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at is null",
		id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist or it was already revoked. Confirm which,
		// so a caller revoking a token that is already dead is not told it
		// failed.
		var exists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT true FROM public.display_tokens WHERE id = $1", id).Scan(&exists); err != nil {
			return fmt.Errorf("display token %s not found", id)
		}
	}
	return nil
}

func (s *PostgresStore) TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error {
	var addr *string
	if ip != "" {
		addr = &ip
	}
	_, err := s.pool.Exec(ctx,
		"UPDATE public.display_tokens SET last_seen_at = $2, last_seen_ip = coalesce($3::inet, last_seen_ip) WHERE id = $1",
		id, seenAt, addr)
	return err
}

// ── Audit Logs ──────────────────────────────────────────

// auditChainLockKey serialises audit writes across every replica.
//
// An arbitrary constant, but a fixed one: PostgreSQL advisory locks share a
// single namespace, so it is written here rather than derived from a string in
// case anything else in this codebase ever needs one and has to avoid it.
const auditChainLockKey int64 = 0x43503A61756469 // "CP:audi"

func (s *PostgresStore) UseAuditChain(chainer *AuditChainer) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.auditChain = chainer
}

func (s *PostgresStore) chainer() *AuditChainer {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	return s.auditChain
}

func (s *PostgresStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	const insert = `
		INSERT INTO public.audit_logs
			(id, action, entity_type, entity_id, actor_id, actor_email, details, ip_address,
			 created_at, seq, prev_hash, entry_hash, chain_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	// Truncated before the tag is computed, because timestamptz holds
	// microseconds and would otherwise hand back a different instant than the
	// one that was signed — making every entry read as tampered on the first
	// verification.
	log.CreatedAt = log.CreatedAt.UTC().Truncate(time.Microsecond)

	var details *string
	if log.Details != "" {
		details = &log.Details
	}

	chainer := s.chainer()
	if chainer == nil {
		// Written unchained rather than refused. Losing the record of what
		// happened is worse than losing the proof that the record is intact,
		// and VerifyAuditChain counts these and says so rather than letting
		// them pass as verified.
		_, err := s.pool.Exec(ctx, insert,
			log.ID, log.Action, log.EntityType, log.EntityID, log.ActorID, log.ActorEmail,
			details, log.IPAddress, log.CreatedAt, nil, nil, nil, nil)
		return err
	}

	// The head read and the insert have to be one atomic step. Without the
	// lock, two replicas writing at the same moment both read sequence N as the
	// head and both chain from it: the unique index then rejects one of them and
	// an audit entry is lost, or — worse, before that index existed — the chain
	// silently forks and verification fails forever at that point. The lock is
	// transaction-scoped, so it is released by commit or rollback and cannot be
	// stranded by a replica dying mid-write.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditChainLockKey); err != nil {
		return fmt.Errorf("could not take the audit chain lock: %w", err)
	}

	var headSeq int64
	prev := append([]byte(nil), AuditChainZeroPrev...)
	err = tx.QueryRow(ctx,
		`SELECT seq, entry_hash FROM public.audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1`,
	).Scan(&headSeq, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("could not read the audit chain head: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		headSeq = 0
		prev = append([]byte(nil), AuditChainZeroPrev...)
	}

	log.Seq = headSeq + 1
	log.PrevHash = prev
	keyID, tag, err := chainer.Link(log, prev)
	if err != nil {
		return fmt.Errorf("could not compute the audit chain tag: %w", err)
	}
	log.ChainKeyID = keyID
	log.EntryHash = tag

	if _, err := tx.Exec(ctx, insert,
		log.ID, log.Action, log.EntityType, log.EntityID, log.ActorID, log.ActorEmail,
		details, log.IPAddress, log.CreatedAt, log.Seq, log.PrevHash, log.EntryHash, log.ChainKeyID,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) VerifyAuditChain(ctx context.Context, from int64, limit int) (*AuditChainReport, error) {
	var unchained int64
	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM public.audit_logs WHERE seq IS NULL").Scan(&unchained); err != nil {
		return nil, err
	}

	if from < 1 {
		from = 1
	}
	// One more than asked for, so the report can say whether it stopped at the
	// end of the chain or at its own limit. "Intact" over a truncated walk is a
	// much weaker claim and must not read like the full one.
	fetch := limit
	if fetch > 0 {
		fetch++
	}

	query := `
		SELECT id, action, entity_type, entity_id, actor_id, actor_email, details,
		       host(ip_address), created_at, seq, prev_hash, entry_hash, chain_key_id
		FROM public.audit_logs
		WHERE seq IS NOT NULL AND seq >= $1
		ORDER BY seq ASC`
	args := []any{from}
	if fetch > 0 {
		query += " LIMIT $2"
		args = append(args, fetch)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]*AuditLog, 0, 256)
	for rows.Next() {
		l := &AuditLog{}
		var details *string
		if err := rows.Scan(&l.ID, &l.Action, &l.EntityType, &l.EntityID, &l.ActorID,
			&l.ActorEmail, &details, &l.IPAddress, &l.CreatedAt, &l.Seq,
			&l.PrevHash, &l.EntryHash, &l.ChainKeyID); err != nil {
			return nil, err
		}
		if details != nil {
			l.Details = *details
		}
		l.CreatedAt = l.CreatedAt.UTC()
		entries = append(entries, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	truncated := false
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
		truncated = true
	}
	return verifyAuditChainOver(entries, s.chainer(), from, unchained, truncated), nil
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if len(filter.Actions) > 0 {
		// = ANY($n) rather than an IN list built by string concatenation: the
		// actions arrive from a query parameter, and this keeps them a bound
		// parameter instead of something spliced into SQL.
		where = append(where, fmt.Sprintf("action = ANY($%d)", argIdx))
		args = append(args, filter.Actions)
		argIdx++
	}
	if filter.EntityType != "" {
		where = append(where, fmt.Sprintf("entity_type = $%d", argIdx))
		args = append(args, filter.EntityType)
		argIdx++
	}
	if filter.EntityID != "" {
		where = append(where, fmt.Sprintf("entity_id = $%d", argIdx))
		args = append(args, filter.EntityID)
		argIdx++
	}
	if !filter.Since.IsZero() {
		where = append(where, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, filter.Since)
		argIdx++
	}
	whereClause := strings.Join(where, " AND ")

	// The count is of the filtered set, not the table. A total that ignored the
	// filter would tell a caller paging through CA alerts that there are
	// forty thousand of them.
	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM public.audit_logs WHERE "+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		-- host(ip_address), not ip_address. The column is inet and AuditLog.IPAddress
		-- is a *string, which pgx cannot scan an inet into — it fails the whole
		-- query, so one entry recorded with a client IP took out the entire
		-- activity feed. Writing works either way, which is why this only showed
		-- up on reading back what the API itself had written. host() renders the
		-- address without any netmask suffix; display_tokens already does the
		-- same for last_seen_ip.
		SELECT id, action, entity_type, entity_id, actor_id, actor_email, details, host(ip_address), created_at
		FROM public.audit_logs WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]*AuditLog, 0)
	for rows.Next() {
		l := &AuditLog{}
		var detailsJSON []byte
		if err := rows.Scan(&l.ID, &l.Action, &l.EntityType, &l.EntityID, &l.ActorID, &l.ActorEmail, &detailsJSON, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		l.Details = string(detailsJSON)
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// ── Notification Channels ───────────────────────────────

const notificationChannelColumns = `id, name, channel_type, config_encrypted,
	is_enabled, severity_threshold, topics, last_sent_at, created_by, created_at, updated_at`

func scanNotificationChannel(row pgx.Row) (*NotificationChannel, error) {
	ch := &NotificationChannel{}
	var topicsJSON []byte
	err := row.Scan(&ch.ID, &ch.Name, &ch.ChannelType, &ch.ConfigEncrypted,
		&ch.IsEnabled, &ch.SeverityThreshold, &topicsJSON, &ch.LastSentAt,
		&ch.CreatedBy, &ch.CreatedAt, &ch.UpdatedAt)
	if err != nil {
		return nil, err
	}
	ch.Topics = []string{}
	if len(topicsJSON) > 0 {
		_ = json.Unmarshal(topicsJSON, &ch.Topics)
	}
	return ch, nil
}

func (s *PostgresStore) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+notificationChannelColumns+" FROM public.notification_channels ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	channels := make([]*NotificationChannel, 0)
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		channels = append(channels, ch)
	}
	return channels, rows.Err()
}

func (s *PostgresStore) GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error) {
	ch, err := scanNotificationChannel(s.pool.QueryRow(ctx,
		"SELECT "+notificationChannelColumns+" FROM public.notification_channels WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("notification channel %s not found", id)
	}
	return ch, err
}

func (s *PostgresStore) CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	topicsJSON, err := json.Marshal(normalizeTopics(ch.Topics))
	if err != nil {
		return err
	}
	query := `
		INSERT INTO public.notification_channels
			(name, channel_type, config_encrypted, is_enabled, severity_threshold, topics, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query, ch.Name, ch.ChannelType, ch.ConfigEncrypted,
		ch.IsEnabled, ch.SeverityThreshold, topicsJSON, ch.CreatedBy).
		Scan(&ch.ID, &ch.CreatedAt, &ch.UpdatedAt)
}

func (s *PostgresStore) UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	topicsJSON, err := json.Marshal(normalizeTopics(ch.Topics))
	if err != nil {
		return err
	}
	// last_sent_at is not written here — that is MarkNotificationChannelSent's
	// job, so an operator saving an edit cannot rewind the delivery record.
	query := `
		UPDATE public.notification_channels SET
			name = $2, channel_type = $3, config_encrypted = $4, is_enabled = $5,
			severity_threshold = $6, topics = $7, updated_at = now()
		WHERE id = $1
	`
	tag, err := s.pool.Exec(ctx, query, ch.ID, ch.Name, ch.ChannelType,
		ch.ConfigEncrypted, ch.IsEnabled, ch.SeverityThreshold, topicsJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("notification channel %s not found", ch.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.notification_channels WHERE id = $1", id)
	return err
}

func (s *PostgresStore) MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE public.notification_channels SET last_sent_at = $2 WHERE id = $1", id, sentAt)
	return err
}

// normalizeTopics guarantees a JSON array rather than null.
//
// A nil slice marshals to `null`, which fails the jsonb array constraint and
// would read back as "no topics" — indistinguishable from "every topic" on the
// way in and the opposite of it on the way out.
func normalizeTopics(topics []string) []string {
	if topics == nil {
		return []string{}
	}
	return topics
}

// ── Dashboard Stats ─────────────────────────────────────

func (s *PostgresStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// Cert stats
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'ISSUED' AND days_remaining > 30),
			COUNT(*) FILTER (WHERE status = 'EXPIRING' OR (status = 'ISSUED' AND days_remaining <= 30 AND days_remaining > 0)),
			COUNT(*) FILTER (WHERE status = 'EXPIRED' OR days_remaining = 0)
		FROM public.certificates
	`).Scan(&stats.TotalCertificates, &stats.HealthyCerts, &stats.ExpiringSoonCerts, &stats.ExpiredCerts)
	if err != nil {
		return nil, err
	}

	// CA stats. Each status gets its own bucket and anything unrecognised falls
	// into UnknownCAs, so the four buckets always sum to the total — see
	// DashboardStats. EXPIRED is split out from CRITICAL because they call for
	// different actions: a critical CA can still be replaced in an orderly way,
	// an expired one is already an outage.
	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'HEALTHY'),
			COUNT(*) FILTER (WHERE status = 'WARNING'),
			COUNT(*) FILTER (WHERE status = 'CRITICAL'),
			COUNT(*) FILTER (WHERE status = 'EXPIRED'),
			COUNT(*) FILTER (WHERE status NOT IN ('HEALTHY', 'WARNING', 'CRITICAL', 'EXPIRED')
			                    OR status IS NULL)
		FROM public.ca_authorities
	`).Scan(&stats.TotalCAs, &stats.HealthyCAs, &stats.WarningCAs, &stats.CriticalCAs,
		&stats.ExpiredCAs, &stats.UnknownCAs)
	if err != nil {
		return nil, err
	}

	// Scans count
	_ = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM public.discovery_scans").Scan(&stats.TotalScans)

	return stats, nil
}

// ── Alert Acknowledgements ──────────────────────────────

const acknowledgementColumns = `id, entity_type, entity_id, threshold,
	acknowledged_by, acknowledged_by_email, acknowledged_at, coalesce(note, ''),
	silence_until, revoked_at, revoked_by, created_at`

func scanAcknowledgement(row pgx.Row) (*AlertAcknowledgement, error) {
	a := &AlertAcknowledgement{}
	err := row.Scan(&a.ID, &a.EntityType, &a.EntityID, &a.Threshold,
		&a.AcknowledgedBy, &a.AcknowledgedByEmail, &a.AcknowledgedAt, &a.Note,
		&a.SilenceUntil, &a.RevokedAt, &a.RevokedBy, &a.CreatedAt)
	return a, err
}

func (s *PostgresStore) CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error {
	query := `
		INSERT INTO public.alert_acknowledgements
			(entity_type, entity_id, threshold, acknowledged_by, acknowledged_by_email,
			 note, silence_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, acknowledged_at, created_at
	`
	return s.pool.QueryRow(ctx, query,
		ack.EntityType, ack.EntityID, ack.Threshold, ack.AcknowledgedBy,
		ack.AcknowledgedByEmail, nullIfEmpty(strings.TrimSpace(ack.Note)), ack.SilenceUntil,
	).Scan(&ack.ID, &ack.AcknowledgedAt, &ack.CreatedAt)
}

func (s *PostgresStore) GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error) {
	a, err := scanAcknowledgement(s.pool.QueryRow(ctx,
		"SELECT "+acknowledgementColumns+` FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = $2 AND revoked_at IS NULL
		 ORDER BY acknowledged_at DESC LIMIT 1`, entityType, entityID))
	if errors.Is(err, pgx.ErrNoRows) {
		// Not an error. "Nobody has acknowledged this" is the normal answer,
		// and making callers distinguish it from a failure invites them to
		// treat a real failure as "not acknowledged" and alert anyway.
		return nil, nil
	}
	if err != nil {
		// nil, not the half-scanned struct. scanAcknowledgement returns a
		// non-nil pointer alongside its error, so returning it here handed a
		// caller an object *and* a failure — and a caller that checked only the
		// pointer would read a database error as somebody having acknowledged
		// the alert, which is the one direction this must never fail in.
		return nil, err
	}
	return a, nil
}

func (s *PostgresStore) ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+acknowledgementColumns+` FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = $2
		 ORDER BY acknowledged_at DESC`, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*AlertAcknowledgement, 0)
	for rows.Next() {
		a, err := scanAcknowledgement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetActiveAcknowledgements resolves many entities in one round trip.
//
// DISTINCT ON rather than a correlated subquery per row: the CA list calls this
// once for the whole estate, and the per-row form is how a dashboard ends up
// issuing one query per CA on every refresh.
func (s *PostgresStore) GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error) {
	out := make(map[string]*AlertAcknowledgement, len(entityIDs))
	if len(entityIDs) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ON (entity_id) `+acknowledgementColumns+`
		 FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = ANY($2) AND revoked_at IS NULL
		 ORDER BY entity_id, acknowledged_at DESC`, entityType, entityIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAcknowledgement(rows)
		if err != nil {
			return nil, err
		}
		out[a.EntityID] = a
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error {
	// `revoked_at IS NULL` keeps the first withdrawal's time and actor, for the
	// same reason as RevokeDisplayToken: who first pulled it is what a review
	// needs, not whoever clicked again afterwards.
	tag, err := s.pool.Exec(ctx,
		`UPDATE public.alert_acknowledgements SET revoked_at = now(), revoked_by = $2
		 WHERE id = $1 AND revoked_at IS NULL`, id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT true FROM public.alert_acknowledgements WHERE id = $1", id).Scan(&exists); err != nil {
			return fmt.Errorf("acknowledgement %s not found", id)
		}
	}
	return nil
}

// ── Discovery ───────────────────────────────────────────

const discoveryScanColumns = `id, scan_type, coalesce(targets, '[]'::jsonb), status,
		coalesce(target_count, 0), coalesce(results_count, 0),
		coalesce(unmanaged_count, 0), coalesce(managed_count, 0),
		coalesce(unreachable_count, 0), started_at, completed_at, coalesce(error, ''),
		triggered_by, actor_email, created_at`

func scanDiscoveryScan(row pgx.Row) (*DiscoveryScan, error) {
	scan := &DiscoveryScan{}
	var targetsJSON []byte
	err := row.Scan(
		&scan.ID, &scan.ScanType, &targetsJSON, &scan.Status,
		&scan.TargetCount, &scan.ResultsCount, &scan.UnmanagedCount, &scan.ManagedCount,
		&scan.UnreachableCount, &scan.StartedAt, &scan.CompletedAt, &scan.Error,
		&scan.TriggeredBy, &scan.ActorEmail, &scan.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(targetsJSON) > 0 {
		_ = json.Unmarshal(targetsJSON, &scan.Targets)
	}
	// Never nil: a nil slice serializes as `null`, and a dashboard calling
	// .map() on that crashes rather than rendering an empty run.
	if scan.Targets == nil {
		scan.Targets = []string{}
	}
	return scan, nil
}

func (s *PostgresStore) CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	targetsJSON, err := json.Marshal(scan.Targets)
	if err != nil {
		return err
	}
	if scan.Status == "" {
		scan.Status = ScanPending
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.discovery_scans
			(scan_type, targets, target_count, status, started_at, triggered_by, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		scan.ScanType, targetsJSON, scan.TargetCount, scan.Status, scan.StartedAt,
		scan.TriggeredBy, scan.ActorEmail).
		Scan(&scan.ID, &scan.CreatedAt)
}

func (s *PostgresStore) UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_scans SET
			status = $2, results_count = $3, unmanaged_count = $4, managed_count = $5,
			unreachable_count = $6, started_at = $7, completed_at = $8, error = $9
		WHERE id = $1`,
		scan.ID, scan.Status, scan.ResultsCount, scan.UnmanagedCount, scan.ManagedCount,
		scan.UnreachableCount, scan.StartedAt, scan.CompletedAt, nullIfEmpty(scan.Error))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery scan %s not found", scan.ID)
	}
	return nil
}

func (s *PostgresStore) GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error) {
	scan, err := scanDiscoveryScan(s.pool.QueryRow(ctx,
		"SELECT "+discoveryScanColumns+" FROM public.discovery_scans WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("discovery scan %s not found", id)
	}
	return scan, err
}

func (s *PostgresStore) ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error) {
	if limit <= 0 {
		limit = 50
	}

	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM public.discovery_scans").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx,
		"SELECT "+discoveryScanColumns+` FROM public.discovery_scans
		 ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	scans := make([]*DiscoveryScan, 0)
	for rows.Next() {
		scan, err := scanDiscoveryScan(rows)
		if err != nil {
			return nil, 0, err
		}
		scans = append(scans, scan)
	}
	return scans, total, rows.Err()
}

const discoveryResultColumns = `id, scan_id, host, port, coalesce(reachable, true), coalesce(error, ''),
		coalesce(management_state, 'UNMANAGED'), coalesce(trust_state, 'UNKNOWN'), matched_certificate_id,
		coalesce(common_name, ''), coalesce(subject_dn, ''), coalesce(sans, '[]'::jsonb),
		coalesce(issuer_dn, ''), coalesce(serial_number, ''), not_before, not_after,
		coalesce(key_type, ''), coalesce(key_size, 0), coalesce(is_ca, false),
		coalesce(fingerprint_sha256, ''), coalesce(certificate_pem, ''), coalesce(chain_pem, ''),
		coalesce(chain_length, 0), coalesce(tls_version, ''), coalesce(cipher_suite, ''),
		coalesce(key_exchange, ''), coalesce(alpn, ''), coalesce(findings, '[]'::jsonb),
		coalesce(is_imported, false), imported_certificate_id, coalesce(scanned_at, created_at), created_at`

// scanDiscoveryResult reads one row of discoveryResultColumns.
//
// Every nullable column is COALESCEd. A single NULL scanning into a non-pointer
// Go field fails the whole query rather than the row, so one hand-inserted
// result would otherwise blank an entire scan's findings — the defect the first
// live PostgreSQL run turned up on the certificate list.
func scanDiscoveryResult(row pgx.Row) (*DiscoveryResult, error) {
	r := &DiscoveryResult{}
	var sansJSON, findingsJSON []byte
	err := row.Scan(
		&r.ID, &r.ScanID, &r.Host, &r.Port, &r.Reachable, &r.Error,
		&r.ManagementState, &r.TrustState, &r.MatchedCertificateID,
		&r.CommonName, &r.SubjectDN, &sansJSON,
		&r.IssuerDN, &r.SerialNumber, &r.NotBefore, &r.NotAfter,
		&r.KeyType, &r.KeySize, &r.IsCA,
		&r.FingerprintSHA256, &r.CertificatePEM, &r.ChainPEM,
		&r.ChainLength, &r.TLSVersion, &r.CipherSuite,
		&r.KeyExchange, &r.ALPN, &findingsJSON,
		&r.IsImported, &r.ImportedCertificateID, &r.ScannedAt, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &r.SANs)
	}
	if len(findingsJSON) > 0 {
		_ = json.Unmarshal(findingsJSON, &r.Findings)
	}
	if r.SANs == nil {
		r.SANs = []string{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return r, nil
}

func (s *PostgresStore) CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error {
	if len(results) == 0 {
		return nil
	}

	// One transaction for the whole batch. A scan's results are a single
	// observation of the estate; half of them landing would make the counts on
	// the scan record disagree with the rows behind it.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, r := range results {
		sansJSON, err := json.Marshal(r.SANs)
		if err != nil {
			return err
		}
		findings := r.Findings
		if findings == nil {
			findings = []Finding{}
		}
		findingsJSON, err := json.Marshal(findings)
		if err != nil {
			return err
		}
		if r.ScannedAt.IsZero() {
			r.ScannedAt = time.Now()
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO public.discovery_results
				(scan_id, host, port, reachable, error, management_state, trust_state,
				 matched_certificate_id, common_name, subject_dn, sans, issuer_dn, serial_number,
				 not_before, not_after, key_type, key_size, is_ca, fingerprint_sha256,
				 certificate_pem, chain_pem, chain_length, tls_version, cipher_suite,
				 key_exchange, alpn, findings, scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
			        $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
			RETURNING id, created_at`,
			r.ScanID, r.Host, r.Port, r.Reachable, nullIfEmpty(r.Error),
			managedOrDefault(r.ManagementState), trustedOrDefault(r.TrustState),
			r.MatchedCertificateID, nullIfEmpty(r.CommonName), nullIfEmpty(r.SubjectDN), sansJSON,
			nullIfEmpty(r.IssuerDN), nullIfEmpty(r.SerialNumber), r.NotBefore, r.NotAfter,
			nullIfEmpty(r.KeyType), r.KeySize, r.IsCA, nullIfEmpty(r.FingerprintSHA256),
			nullIfEmpty(r.CertificatePEM), nullIfEmpty(r.ChainPEM), r.ChainLength,
			nullIfEmpty(r.TLSVersion), nullIfEmpty(r.CipherSuite), nullIfEmpty(r.KeyExchange),
			nullIfEmpty(r.ALPN), findingsJSON, r.ScannedAt).
			Scan(&r.ID, &r.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.ScanID != "" {
		add("scan_id = $%d", filter.ScanID)
	}
	if filter.ManagementState != "" {
		add("management_state = $%d", filter.ManagementState)
	}
	if filter.TrustState != "" {
		add("trust_state = $%d", filter.TrustState)
	}
	if filter.Host != "" {
		add("host = $%d", filter.Host)
	}
	if filter.UnimportedOnly {
		where = append(where, "coalesce(is_imported, false) = false")
	}
	clause := strings.Join(where, " AND ")

	// LatestPerEndpoint collapses an endpoint's history to its newest
	// observation *before* the filters apply, not after.
	//
	// The order matters and is easy to get backwards. Filtering first would
	// answer "the most recent time this endpoint was unmanaged", which keeps
	// reporting an endpoint that has since been adopted. Collapsing first
	// answers "endpoints that are unmanaged now", which is the question the
	// outstanding-work list is actually asking.
	source := "public.discovery_results"
	if filter.LatestPerEndpoint {
		source = `(SELECT DISTINCT ON (host, port) * FROM public.discovery_results
			   ORDER BY host, port, scanned_at DESC) latest`
	}

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM "+source+" WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + discoveryResultColumns + " FROM " + source + " WHERE " + clause +
		fmt.Sprintf(" ORDER BY created_at DESC, host ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*DiscoveryResult, 0)
	for rows.Next() {
		r, err := scanDiscoveryResult(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error) {
	r, err := scanDiscoveryResult(s.pool.QueryRow(ctx,
		"SELECT "+discoveryResultColumns+" FROM public.discovery_results WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("discovery result %s not found", id)
	}
	return r, err
}

func (s *PostgresStore) MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error {
	// management_state moves with it: adopting a result settles the question it
	// was raised about, and a list that still called it unmanaged would keep
	// asking for work already done.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_results
		SET is_imported = true, imported_certificate_id = $2,
		    matched_certificate_id = $2, management_state = 'MANAGED'
		WHERE id = $1`, id, certificateID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery result %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetLatestDiscoveryResults(ctx context.Context, endpoints []string) (map[string]*DiscoveryResult, error) {
	out := map[string]*DiscoveryResult{}

	hosts := make([]string, 0, len(endpoints))
	seen := map[string]bool{}
	for _, e := range endpoints {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			continue
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}

	// DISTINCT ON gives the newest row per endpoint in one pass, on the
	// (host, port, scanned_at desc) index from migration 009. The alternative —
	// one query per endpoint — is 254 round trips for a /24.
	query := "SELECT DISTINCT ON (host, port) " + discoveryResultColumns +
		` FROM public.discovery_results`
	args := []any{}
	if len(hosts) > 0 {
		query += " WHERE host = ANY($1)"
		args = append(args, hosts)
	}
	query += " ORDER BY host, port, scanned_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		r, err := scanDiscoveryResult(rows)
		if err != nil {
			return nil, err
		}
		out[fmt.Sprintf("%s:%d", r.Host, r.Port)] = r
	}
	return out, rows.Err()
}

// ── Discovery schedules ─────────────────────────────────

const discoveryScheduleColumns = `id, name, coalesce(targets, '[]'::jsonb), coalesce(ports, '[443]'::jsonb),
		interval_minutes, coalesce(is_enabled, true), last_run_at, next_run_at, last_scan_id,
		coalesce(last_error, ''), created_by, created_at, updated_at`

func scanDiscoverySchedule(row pgx.Row) (*DiscoverySchedule, error) {
	sched := &DiscoverySchedule{}
	var targetsJSON, portsJSON []byte
	err := row.Scan(
		&sched.ID, &sched.Name, &targetsJSON, &portsJSON,
		&sched.IntervalMinutes, &sched.IsEnabled, &sched.LastRunAt, &sched.NextRunAt, &sched.LastScanID,
		&sched.LastError, &sched.CreatedBy, &sched.CreatedAt, &sched.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(targetsJSON) > 0 {
		_ = json.Unmarshal(targetsJSON, &sched.Targets)
	}
	if len(portsJSON) > 0 {
		_ = json.Unmarshal(portsJSON, &sched.Ports)
	}
	if sched.Targets == nil {
		sched.Targets = []string{}
	}
	if sched.Ports == nil {
		sched.Ports = []int{}
	}
	return sched, nil
}

func (s *PostgresStore) ListDiscoverySchedules(ctx context.Context) ([]*DiscoverySchedule, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+discoveryScheduleColumns+" FROM public.discovery_schedules ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*DiscoverySchedule, 0)
	for rows.Next() {
		sched, err := scanDiscoverySchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sched)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetDiscoverySchedule(ctx context.Context, id string) (*DiscoverySchedule, error) {
	sched, err := scanDiscoverySchedule(s.pool.QueryRow(ctx,
		"SELECT "+discoveryScheduleColumns+" FROM public.discovery_schedules WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("discovery schedule %s not found", id)
	}
	return sched, err
}

func (s *PostgresStore) CreateDiscoverySchedule(ctx context.Context, sched *DiscoverySchedule) error {
	targetsJSON, err := json.Marshal(sched.Targets)
	if err != nil {
		return err
	}
	portsJSON, err := json.Marshal(sched.Ports)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.discovery_schedules
			(name, targets, ports, interval_minutes, is_enabled, next_run_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		sched.Name, targetsJSON, portsJSON, sched.IntervalMinutes, sched.IsEnabled,
		sched.NextRunAt, sched.CreatedBy).
		Scan(&sched.ID, &sched.CreatedAt, &sched.UpdatedAt)
}

func (s *PostgresStore) UpdateDiscoverySchedule(ctx context.Context, sched *DiscoverySchedule) error {
	targetsJSON, err := json.Marshal(sched.Targets)
	if err != nil {
		return err
	}
	portsJSON, err := json.Marshal(sched.Ports)
	if err != nil {
		return err
	}
	// Deliberately does not write last_run_at, next_run_at, or last_scan_id.
	// Editing a schedule and recording that it ran are different acts by
	// different actors, and letting an edit carry stale scheduling state would
	// let saving a name change quietly reschedule or re-run the scan.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_schedules
		SET name = $2, targets = $3, ports = $4, interval_minutes = $5,
		    is_enabled = $6, updated_at = now()
		WHERE id = $1`,
		sched.ID, sched.Name, targetsJSON, portsJSON, sched.IntervalMinutes, sched.IsEnabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery schedule %s not found", sched.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteDiscoverySchedule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM public.discovery_schedules WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetDueDiscoverySchedules(ctx context.Context, now time.Time) ([]*DiscoverySchedule, error) {
	// A schedule that has never run is due immediately: someone who has just
	// created one wants to know it works, not to find out tomorrow.
	rows, err := s.pool.Query(ctx,
		"SELECT "+discoveryScheduleColumns+` FROM public.discovery_schedules
		 WHERE is_enabled AND (next_run_at IS NULL OR next_run_at <= $1)
		 ORDER BY name ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*DiscoverySchedule, 0)
	for rows.Next() {
		sched, err := scanDiscoverySchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sched)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkDiscoveryScheduleRun(ctx context.Context, id string, ranAt, nextRunAt time.Time, scanID *string, runErr string) error {
	// coalesce keeps the previous scan id when a run failed before producing
	// one: "the last time this worked" is the more useful of the two facts.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_schedules
		SET last_run_at = $2, next_run_at = $3,
		    last_scan_id = coalesce($4, last_scan_id),
		    last_error = $5, updated_at = now()
		WHERE id = $1`, id, ranAt, nextRunAt, scanID, nullIfEmpty(runErr))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	return nil
}

// ── Certificate Transparency ────────────────────────────

const ctMonitorColumns = `id, domain, coalesce(include_subdomains, true), coalesce(is_enabled, true),
		coalesce(check_interval_minutes, 360), last_checked_at, last_success_at, next_check_at,
		coalesce(last_error, ''), last_entry_id, coalesce(certificates_seen, 0),
		coalesce(unmanaged_seen, 0), created_by, created_at, updated_at`

func scanCTMonitor(row pgx.Row) (*CTMonitor, error) {
	m := &CTMonitor{}
	err := row.Scan(
		&m.ID, &m.Domain, &m.IncludeSubdomains, &m.IsEnabled,
		&m.CheckIntervalMinutes, &m.LastCheckedAt, &m.LastSuccessAt, &m.NextCheckAt,
		&m.LastError, &m.LastEntryID, &m.CertificatesSeen,
		&m.UnmanagedSeen, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (s *PostgresStore) ListCTMonitors(ctx context.Context) ([]*CTMonitor, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+ctMonitorColumns+" FROM public.ct_monitors ORDER BY domain ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*CTMonitor, 0)
	for rows.Next() {
		m, err := scanCTMonitor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetCTMonitor(ctx context.Context, id string) (*CTMonitor, error) {
	m, err := scanCTMonitor(s.pool.QueryRow(ctx,
		"SELECT "+ctMonitorColumns+" FROM public.ct_monitors WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	return m, err
}

func (s *PostgresStore) CreateCTMonitor(ctx context.Context, m *CTMonitor) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO public.ct_monitors
			(domain, include_subdomains, is_enabled, check_interval_minutes, next_check_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`,
		m.Domain, m.IncludeSubdomains, m.IsEnabled, m.CheckIntervalMinutes, m.NextCheckAt, m.CreatedBy).
		Scan(&m.ID, &m.CreatedAt, &m.UpdatedAt)
	if err != nil && strings.Contains(err.Error(), "ct_monitors_domain_unique") {
		return fmt.Errorf("%s is already being watched", m.Domain)
	}
	return err
}

func (s *PostgresStore) UpdateCTMonitor(ctx context.Context, m *CTMonitor) error {
	// Deliberately does not write the check timestamps or the watermark:
	// editing a monitor and recording that it ran are different acts, and
	// letting an edit carry stale scheduling state would make saving a name
	// change re-read years of log history.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.ct_monitors
		SET domain = $2, include_subdomains = $3, is_enabled = $4,
		    check_interval_minutes = $5, updated_at = now()
		WHERE id = $1`,
		m.ID, m.Domain, m.IncludeSubdomains, m.IsEnabled, m.CheckIntervalMinutes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate transparency monitor %s not found", m.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteCTMonitor(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM public.ct_monitors WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetDueCTMonitors(ctx context.Context, now time.Time) ([]*CTMonitor, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+ctMonitorColumns+` FROM public.ct_monitors
		 WHERE is_enabled AND (next_check_at IS NULL OR next_check_at <= $1)
		 ORDER BY domain ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*CTMonitor, 0)
	for rows.Next() {
		m, err := scanCTMonitor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkCTMonitorChecked(ctx context.Context, id string, checkedAt, nextCheckAt time.Time,
	success bool, lastEntryID *int64, seen, unmanaged int, checkErr string) error {
	// last_success_at moves only when the check answered. Everything on screen
	// that says "we are watching this domain" is really saying "we last heard
	// from the log at this time", and a failing monitor must not read as a
	// quiet one.
	query := `
		UPDATE public.ct_monitors
		SET last_checked_at = $2, next_check_at = $3, last_error = $4`
	args := []any{id, checkedAt, nextCheckAt, nullIfEmpty(checkErr)}
	if success {
		query += `, last_success_at = $2,
		           last_entry_id = coalesce($5, last_entry_id),
		           certificates_seen = coalesce(certificates_seen, 0) + $6,
		           unmanaged_seen = coalesce(unmanaged_seen, 0) + $7`
		args = append(args, lastEntryID, seen, unmanaged)
	}
	query += ", updated_at = now() WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	return nil
}

const ctCertificateColumns = `id, monitor_id, entry_id, logged_at, coalesce(serial_number, ''),
		coalesce(issuer_dn, ''), coalesce(common_name, ''), coalesce(sans, '[]'::jsonb),
		not_before, not_after, coalesce(management_state, 'UNMANAGED'), matched_certificate_id,
		coalesce(is_precertificate, false), coalesce(first_seen_at, created_at), created_at`

func scanCTCertificate(row pgx.Row) (*CTCertificate, error) {
	c := &CTCertificate{}
	var sansJSON []byte
	err := row.Scan(
		&c.ID, &c.MonitorID, &c.EntryID, &c.LoggedAt, &c.SerialNumber,
		&c.IssuerDN, &c.CommonName, &sansJSON,
		&c.NotBefore, &c.NotAfter, &c.ManagementState, &c.MatchedCertificateID,
		&c.IsPrecertificate, &c.FirstSeenAt, &c.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &c.SANs)
	}
	if c.SANs == nil {
		c.SANs = []string{}
	}
	return c, nil
}

func (s *PostgresStore) RecordCTCertificates(ctx context.Context, certs []*CTCertificate) ([]*CTCertificate, error) {
	added := make([]*CTCertificate, 0, len(certs))
	if len(certs) == 0 {
		return added, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, c := range certs {
		sansJSON, err := json.Marshal(c.SANs)
		if err != nil {
			return nil, err
		}
		// ON CONFLICT DO NOTHING is what makes a re-check idempotent: the
		// windows overlap by design, and re-reporting the same certificate
		// every six hours is how a notification channel gets muted.
		row := tx.QueryRow(ctx, `
			INSERT INTO public.ct_certificates
				(monitor_id, entry_id, logged_at, serial_number, issuer_dn, common_name, sans,
				 not_before, not_after, management_state, matched_certificate_id, is_precertificate)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (monitor_id, entry_id) DO NOTHING
			RETURNING id, created_at, first_seen_at`,
			c.MonitorID, c.EntryID, c.LoggedAt, nullIfEmpty(c.SerialNumber), nullIfEmpty(c.IssuerDN),
			nullIfEmpty(c.CommonName), sansJSON, c.NotBefore, c.NotAfter, managedOrDefault(c.ManagementState),
			c.MatchedCertificateID, c.IsPrecertificate)

		err = row.Scan(&c.ID, &c.CreatedAt, &c.FirstSeenAt)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // already known
		}
		if err != nil {
			return nil, err
		}
		added = append(added, c)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return added, nil
}

func (s *PostgresStore) ListCTCertificates(ctx context.Context, filter CTCertificateFilter) ([]*CTCertificate, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.MonitorID != "" {
		add("monitor_id = $%d", filter.MonitorID)
	}
	if filter.ManagementState != "" {
		add("management_state = $%d", filter.ManagementState)
	}
	if filter.ExcludePrecertificates {
		// Drops the pre-issuance entry only when the real certificate is also
		// present. A precertificate whose final entry has not been logged is
		// still the only record that the certificate exists.
		where = append(where, `NOT (coalesce(is_precertificate, false) AND EXISTS (
			SELECT 1 FROM public.ct_certificates final
			WHERE final.serial_number = ct_certificates.serial_number
			  AND NOT coalesce(final.is_precertificate, false)))`)
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.ct_certificates WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + ctCertificateColumns + " FROM public.ct_certificates WHERE " + clause +
		fmt.Sprintf(" ORDER BY coalesce(logged_at, created_at) DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*CTCertificate, 0)
	for rows.Next() {
		c, err := scanCTCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ── Cloud inventory ─────────────────────────────────────────

const cloudConnectionColumns = `id, name, provider, coalesce(config_encrypted, ''),
		coalesce(is_enabled, true), coalesce(sync_interval_minutes, 360),
		last_synced_at, last_success_at, next_sync_at, coalesce(last_error, ''),
		coalesce(scopes, '[]'::jsonb), coalesce(certificates_seen, 0), coalesce(unmanaged_seen, 0),
		created_by, created_at, updated_at`

func scanCloudConnection(row pgx.Row) (*CloudConnection, error) {
	c := &CloudConnection{}
	var scopesJSON []byte
	err := row.Scan(
		&c.ID, &c.Name, &c.Provider, &c.ConfigEncrypted,
		&c.IsEnabled, &c.SyncIntervalMinutes,
		&c.LastSyncedAt, &c.LastSuccessAt, &c.NextSyncAt, &c.LastError,
		&scopesJSON, &c.CertificatesSeen, &c.UnmanagedSeen,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(scopesJSON) > 0 {
		_ = json.Unmarshal(scopesJSON, &c.Scopes)
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	return c, nil
}

func (s *PostgresStore) ListCloudConnections(ctx context.Context) ([]*CloudConnection, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+cloudConnectionColumns+" FROM public.cloud_connections ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*CloudConnection, 0)
	for rows.Next() {
		c, err := scanCloudConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetCloudConnection(ctx context.Context, id string) (*CloudConnection, error) {
	c, err := scanCloudConnection(s.pool.QueryRow(ctx,
		"SELECT "+cloudConnectionColumns+" FROM public.cloud_connections WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("cloud connection %s not found", id)
	}
	return c, err
}

func (s *PostgresStore) CreateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO public.cloud_connections
			(name, provider, config_encrypted, is_enabled, sync_interval_minutes, next_sync_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`,
		conn.Name, conn.Provider, nullIfEmpty(conn.ConfigEncrypted), conn.IsEnabled,
		conn.SyncIntervalMinutes, conn.NextSyncAt, conn.CreatedBy).
		Scan(&conn.ID, &conn.CreatedAt, &conn.UpdatedAt)
	if err != nil && strings.Contains(err.Error(), "cloud_connections_name_unique") {
		return fmt.Errorf("a cloud connection named %q already exists", conn.Name)
	}
	return err
}

func (s *PostgresStore) UpdateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	// Deliberately does not write the sync timestamps: editing a connection and
	// recording that it ran are different acts, and letting an edit carry stale
	// scheduling state would make a rename look like a successful sync.
	//
	// config_encrypted is written only when the caller supplied one, so saving
	// a name change cannot silently blank the credentials.
	query := `
		UPDATE public.cloud_connections
		SET name = $2, provider = $3, is_enabled = $4, sync_interval_minutes = $5, updated_at = now()`
	args := []any{conn.ID, conn.Name, conn.Provider, conn.IsEnabled, conn.SyncIntervalMinutes}
	if conn.ConfigEncrypted != "" {
		query += ", config_encrypted = $6"
		args = append(args, conn.ConfigEncrypted)
	}
	query += " WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		if strings.Contains(err.Error(), "cloud_connections_name_unique") {
			return fmt.Errorf("a cloud connection named %q already exists", conn.Name)
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("cloud connection %s not found", conn.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteCloudConnection(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM public.cloud_connections WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetDueCloudConnections(ctx context.Context, now time.Time) ([]*CloudConnection, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+cloudConnectionColumns+` FROM public.cloud_connections
		 WHERE is_enabled AND (next_sync_at IS NULL OR next_sync_at <= $1)
		 ORDER BY name ASC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*CloudConnection, 0)
	for rows.Next() {
		c, err := scanCloudConnection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkCloudConnectionSynced(ctx context.Context, id string, syncedAt, nextSyncAt time.Time,
	success bool, scopes []string, seen, unmanaged int, syncErr string) error {
	query := `
		UPDATE public.cloud_connections
		SET last_synced_at = $2, next_sync_at = $3, last_error = $4`
	args := []any{id, syncedAt, nextSyncAt, nullIfEmpty(syncErr)}
	if success {
		scopesJSON, err := json.Marshal(scopes)
		if err != nil {
			return err
		}
		// scopes are replaced rather than merged: they describe this sync, and
		// carrying forward a scope the current credentials can no longer reach
		// would claim coverage that no longer exists.
		query += `, last_success_at = $2, scopes = $5,
		           certificates_seen = $6, unmanaged_seen = $7`
		args = append(args, scopesJSON, seen, unmanaged)
	}
	query += ", updated_at = now() WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	return nil
}

const cloudCertificateColumns = `id, connection_id, resource_id, coalesce(name, ''), coalesce(location, ''),
		coalesce(common_name, ''), coalesce(subject_dn, ''), coalesce(issuer_dn, ''), coalesce(serial_number, ''),
		coalesce(sans, '[]'::jsonb), not_before, not_after, coalesce(key_type, ''), coalesce(key_size, 0),
		coalesce(fingerprint_sha256, ''), coalesce(certificate_pem, ''),
		coalesce(management_state, 'UNMANAGED'), matched_certificate_id,
		coalesce(renewal_mode, ''), will_renew, attached, coalesce(attached_to, '[]'::jsonb),
		coalesce(findings, '[]'::jsonb), coalesce(is_imported, false), imported_certificate_id,
		first_seen_at, last_seen_at, removed_at, created_at`

func scanCloudCertificate(row pgx.Row) (*CloudCertificate, error) {
	c := &CloudCertificate{}
	var sansJSON, attachedToJSON, findingsJSON []byte
	err := row.Scan(
		&c.ID, &c.ConnectionID, &c.ResourceID, &c.Name, &c.Location,
		&c.CommonName, &c.SubjectDN, &c.IssuerDN, &c.SerialNumber,
		&sansJSON, &c.NotBefore, &c.NotAfter, &c.KeyType, &c.KeySize,
		&c.FingerprintSHA256, &c.CertificatePEM,
		&c.ManagementState, &c.MatchedCertificateID,
		&c.RenewalMode, &c.WillRenew, &c.Attached, &attachedToJSON,
		&findingsJSON, &c.IsImported, &c.ImportedCertificateID,
		&c.FirstSeenAt, &c.LastSeenAt, &c.RemovedAt, &c.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &c.SANs)
	}
	if len(attachedToJSON) > 0 {
		_ = json.Unmarshal(attachedToJSON, &c.AttachedTo)
	}
	if len(findingsJSON) > 0 {
		_ = json.Unmarshal(findingsJSON, &c.Findings)
	}
	if c.SANs == nil {
		c.SANs = []string{}
	}
	if c.AttachedTo == nil {
		c.AttachedTo = []string{}
	}
	if c.Findings == nil {
		c.Findings = []Finding{}
	}
	return c, nil
}

func (s *PostgresStore) UpsertCloudCertificates(ctx context.Context, certs []*CloudCertificate) ([]*CloudCertificate, error) {
	added := make([]*CloudCertificate, 0, len(certs))
	if len(certs) == 0 {
		return added, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, c := range certs {
		sansJSON, err := json.Marshal(c.SANs)
		if err != nil {
			return nil, err
		}
		attachedToJSON, err := json.Marshal(c.AttachedTo)
		if err != nil {
			return nil, err
		}
		findingsJSON, err := json.Marshal(c.Findings)
		if err != nil {
			return nil, err
		}

		// The xmax test distinguishes an insert from an update. Without it an
		// upsert cannot say which certificates were new, and an alert built
		// from "everything the sync saw" fires the entire ACM inventory into a
		// channel every six hours.
		//
		// first_seen_at is never overwritten, and removed_at is cleared: a
		// certificate that came back is the same certificate returning, not a
		// new one, and its history is the interesting part.
		row := tx.QueryRow(ctx, `
			INSERT INTO public.cloud_certificates
				(connection_id, resource_id, name, location, common_name, subject_dn, issuer_dn,
				 serial_number, sans, not_before, not_after, key_type, key_size, fingerprint_sha256,
				 certificate_pem, management_state, matched_certificate_id, renewal_mode, will_renew,
				 attached, attached_to, findings, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			        $19, $20, $21, $22, $23)
			ON CONFLICT (connection_id, resource_id) DO UPDATE SET
				name = excluded.name, location = excluded.location,
				common_name = excluded.common_name, subject_dn = excluded.subject_dn,
				issuer_dn = excluded.issuer_dn, serial_number = excluded.serial_number,
				sans = excluded.sans, not_before = excluded.not_before, not_after = excluded.not_after,
				key_type = excluded.key_type, key_size = excluded.key_size,
				fingerprint_sha256 = excluded.fingerprint_sha256,
				certificate_pem = excluded.certificate_pem,
				-- An import survives the next sync.
				--
				-- The provider goes on reporting the certificate as unmanaged,
				-- because the provider has no idea it was adopted — so writing
				-- excluded.management_state straight through reverted every
				-- adopted certificate to UNMANAGED on the following sweep, six
				-- hours later, and it reappeared as an unmanaged finding for
				-- ever. The in-memory store had always preserved this, which is
				-- exactly why nothing noticed: cloud_test.go called
				-- NewMemoryStore directly and had never run against a database.
				management_state = CASE
					WHEN public.cloud_certificates.is_imported THEN 'MANAGED'
					ELSE excluded.management_state END,
				-- Likewise the link to what it was adopted as. coalesce and not
				-- excluded-wins: the provider never supplies this, so letting it
				-- win means letting NULL win.
				matched_certificate_id = coalesce(
					public.cloud_certificates.matched_certificate_id,
					excluded.matched_certificate_id),
				renewal_mode = excluded.renewal_mode, will_renew = excluded.will_renew,
				attached = excluded.attached, attached_to = excluded.attached_to,
				findings = excluded.findings, last_seen_at = excluded.last_seen_at,
				removed_at = NULL
			RETURNING id, first_seen_at, last_seen_at, created_at, (xmax = 0) AS inserted`,
			c.ConnectionID, c.ResourceID, nullIfEmpty(c.Name), nullIfEmpty(c.Location),
			nullIfEmpty(c.CommonName), nullIfEmpty(c.SubjectDN), nullIfEmpty(c.IssuerDN),
			nullIfEmpty(c.SerialNumber), sansJSON, c.NotBefore, c.NotAfter,
			nullIfEmpty(c.KeyType), c.KeySize, nullIfEmpty(c.FingerprintSHA256),
			nullIfEmpty(c.CertificatePEM), managedOrDefault(c.ManagementState), c.MatchedCertificateID,
			nullIfEmpty(c.RenewalMode), c.WillRenew, c.Attached, attachedToJSON, findingsJSON,
			c.LastSeenAt)

		var inserted bool
		if err := row.Scan(&c.ID, &c.FirstSeenAt, &c.LastSeenAt, &c.CreatedAt, &inserted); err != nil {
			return nil, err
		}
		if inserted {
			added = append(added, c)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return added, nil
}

func (s *PostgresStore) MarkCloudCertificatesRemoved(ctx context.Context, connectionID string,
	seenResourceIDs []string, at time.Time) (int, error) {
	// An empty seen list is not treated as "everything is gone". A provider
	// that answered with nothing is possible, but so is a bug, and reporting an
	// entire estate as deleted is the more expensive mistake of the two.
	if len(seenResourceIDs) == 0 {
		return 0, nil
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.cloud_certificates
		SET removed_at = $2
		WHERE connection_id = $1 AND removed_at IS NULL AND NOT (resource_id = ANY($3))`,
		connectionID, at, seenResourceIDs)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PostgresStore) ListCloudCertificates(ctx context.Context, filter CloudCertificateFilter) ([]*CloudCertificate, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.ConnectionID != "" {
		add("connection_id = $%d", filter.ConnectionID)
	}
	if filter.ManagementState != "" {
		add("management_state = $%d", filter.ManagementState)
	}
	if filter.FindingCode != "" {
		// Containment against a one-element array: matches a findings entry
		// whose code is this, whatever else that entry carries.
		add(`findings @> $%d::jsonb`, `[{"code":"`+filter.FindingCode+`"}]`)
	}
	if !filter.IncludeRemoved {
		where = append(where, "removed_at IS NULL")
	}
	if filter.UnimportedOnly {
		where = append(where, "is_imported = false")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.cloud_certificates WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + cloudCertificateColumns + " FROM public.cloud_certificates WHERE " + clause +
		fmt.Sprintf(" ORDER BY not_after ASC NULLS LAST, resource_id ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*CloudCertificate, 0)
	for rows.Next() {
		c, err := scanCloudCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) GetCloudCertificate(ctx context.Context, id string) (*CloudCertificate, error) {
	c, err := scanCloudCertificate(s.pool.QueryRow(ctx,
		"SELECT "+cloudCertificateColumns+" FROM public.cloud_certificates WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("cloud certificate %s not found", id)
	}
	return c, err
}

func (s *PostgresStore) MarkCloudCertificateImported(ctx context.Context, id, certificateID string) error {
	// Management state moves with the import. A list that still called an
	// adopted certificate unmanaged would keep asking for work already done.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.cloud_certificates
		SET is_imported = true, imported_certificate_id = $2,
		    management_state = 'MANAGED', matched_certificate_id = coalesce(matched_certificate_id, $2)
		WHERE id = $1`, id, certificateID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("cloud certificate %s not found", id)
	}
	return nil
}

// ── Renewal queue ───────────────────────────────────────────

const renewalJobColumns = `id, certificate_id, ca_account_id, reason, status, run_after, coalesce(attempts, 0),
		locked_by, locked_until, coalesce(last_error, ''), coalesce(attempt_log, '[]'::jsonb),
		not_after, coalesce(fingerprint_at_enqueue, ''), escalated_at,
		triggered_by, actor_email, started_at, completed_at, created_at, updated_at`

func scanRenewalJob(row pgx.Row) (*RenewalJob, error) {
	j := &RenewalJob{}
	var logJSON []byte
	err := row.Scan(
		&j.ID, &j.CertificateID, &j.CAAccountID, &j.Reason, &j.Status, &j.RunAfter, &j.Attempts,
		&j.LockedBy, &j.LockedUntil, &j.LastError, &logJSON,
		&j.NotAfter, &j.FingerprintAtEnqueue, &j.EscalatedAt,
		&j.TriggeredBy, &j.ActorEmail, &j.StartedAt, &j.CompletedAt, &j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(logJSON) > 0 {
		_ = json.Unmarshal(logJSON, &j.AttemptLog)
	}
	if j.AttemptLog == nil {
		j.AttemptLog = []RenewalAttempt{}
	}
	return j, nil
}

func (s *PostgresStore) EnqueueRenewal(ctx context.Context, job *RenewalJob) (bool, error) {
	// ON CONFLICT against the partial unique index. Two replicas scanning in
	// the same second both try; one wins, the other gets no row back and reads
	// the existing job. No leader, no failover gap, no duplicate issuance.
	row := s.pool.QueryRow(ctx, `
		INSERT INTO public.renewal_jobs
			(certificate_id, ca_account_id, reason, status, run_after, not_after,
			 fingerprint_at_enqueue, triggered_by, actor_email)
		VALUES ($1, $2, $3, 'PENDING', $4, $5, $6, $7, $8)
		ON CONFLICT (certificate_id) WHERE status IN ('PENDING', 'RUNNING') DO NOTHING
		RETURNING `+renewalJobColumns,
		job.CertificateID, job.CAAccountID, job.Reason, job.RunAfter, job.NotAfter,
		nullIfEmpty(job.FingerprintAtEnqueue), job.TriggeredBy, job.ActorEmail)

	created, err := scanRenewalJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		existing, findErr := s.outstandingRenewalJob(ctx, job.CertificateID)
		if findErr != nil {
			return false, findErr
		}
		if existing != nil {
			*job = *existing
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	*job = *created
	return true, nil
}

func (s *PostgresStore) outstandingRenewalJob(ctx context.Context, certificateID string) (*RenewalJob, error) {
	job, err := scanRenewalJob(s.pool.QueryRow(ctx,
		"SELECT "+renewalJobColumns+` FROM public.renewal_jobs
		 WHERE certificate_id = $1 AND status IN ('PENDING', 'RUNNING')
		 ORDER BY created_at DESC LIMIT 1`, certificateID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return job, err
}

func (s *PostgresStore) ClaimRenewalJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*RenewalJob, error) {
	// FOR UPDATE SKIP LOCKED is what lets every replica be a worker. Two
	// claiming at once do not block each other and do not take the same row;
	// the second simply picks the next one.
	//
	// The WHERE clause takes pending-and-due jobs, and running jobs whose lease
	// has expired — a worker that was killed mid-renewal releases its job by
	// the clock rather than by anything having to notice it died.
	//
	// Ordered by the deadline being raced, not by age. A certificate expiring
	// tomorrow outranks one enqueued an hour earlier with a month left.
	row := s.pool.QueryRow(ctx, `
		UPDATE public.renewal_jobs
		SET status = 'RUNNING',
		    locked_by = $1,
		    locked_until = $2,
		    attempts = attempts + 1,
		    started_at = coalesce(started_at, $3),
		    updated_at = now()
		WHERE id = (
			SELECT id FROM public.renewal_jobs
			WHERE (status = 'PENDING' AND run_after <= $3)
			   OR (status = 'RUNNING' AND locked_until IS NOT NULL AND locked_until < $3)
			ORDER BY not_after ASC NULLS LAST, run_after ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING `+renewalJobColumns,
		worker, now.Add(lease), now)

	job, err := scanRenewalJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// An empty queue is the ordinary case, not an error.
		return nil, nil
	}
	return job, err
}

func (s *PostgresStore) ExtendRenewalLease(ctx context.Context, id, worker string, until time.Time) error {
	// Scoped to the holder. A worker whose lease already expired and was taken
	// by somebody else must not be able to extend it back out from under them.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.renewal_jobs
		SET locked_until = $3, updated_at = now()
		WHERE id = $1 AND locked_by = $2 AND status = 'RUNNING'`, id, worker, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("renewal job %s is no longer held by %s", id, worker)
	}
	return nil
}

func (s *PostgresStore) CompleteRenewalJob(ctx context.Context, id, status string,
	attempt RenewalAttempt, runAfter time.Time, escalate bool) error {
	attemptJSON, err := json.Marshal([]RenewalAttempt{attempt})
	if err != nil {
		return err
	}

	// The attempt log is appended to and trimmed in one statement, so a job
	// retrying for weeks does not grow without limit. The newest entries are
	// kept: what it is doing now matters more than what it did a fortnight ago,
	// and the count of attempts survives separately.
	query := `
		UPDATE public.renewal_jobs
		SET status = $2,
		    last_error = $3,
		    attempt_log = (
		        SELECT coalesce(jsonb_agg(entry), '[]'::jsonb)
		        FROM (
		            SELECT entry FROM jsonb_array_elements(coalesce(attempt_log, '[]'::jsonb) || $4::jsonb) AS entry
		            OFFSET greatest(jsonb_array_length(coalesce(attempt_log, '[]'::jsonb)) + 1 - 50, 0)
		        ) trimmed
		    ),
		    locked_by = NULL,
		    locked_until = NULL,
		    updated_at = now()`
	args := []any{id, status, nullIfEmpty(attempt.Error), attemptJSON}

	if status == RenewalPending {
		query += ", run_after = $5"
		args = append(args, runAfter)
	} else {
		query += ", completed_at = now()"
	}
	if escalate {
		// Set once and left. When a job first became somebody's problem is more
		// useful than when it most recently was.
		query += ", escalated_at = coalesce(escalated_at, now())"
	}
	query += " WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("renewal job %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetRenewalJob(ctx context.Context, id string) (*RenewalJob, error) {
	job, err := scanRenewalJob(s.pool.QueryRow(ctx,
		"SELECT "+renewalJobColumns+" FROM public.renewal_jobs WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("renewal job %s not found", id)
	}
	return job, err
}

func (s *PostgresStore) ListRenewalJobs(ctx context.Context, filter RenewalJobFilter) ([]*RenewalJob, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.CertificateID != "" {
		add("certificate_id = $%d", filter.CertificateID)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.OutstandingOnly {
		where = append(where, "status IN ('PENDING', 'RUNNING')")
	}
	if filter.EscalatedOnly {
		where = append(where, "escalated_at IS NOT NULL")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.renewal_jobs WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, filter.Offset)
	// Urgency first, the same order the workers claim in, so the screen agrees
	// with what is actually happening next.
	query := "SELECT " + renewalJobColumns + " FROM public.renewal_jobs WHERE " + clause +
		fmt.Sprintf(" ORDER BY not_after ASC NULLS LAST, created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*RenewalJob, 0)
	for rows.Next() {
		job, err := scanRenewalJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, job)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) CancelRenewalJob(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.renewal_jobs
		SET status = 'CANCELLED', completed_at = now(), locked_by = NULL, locked_until = NULL, updated_at = now()
		WHERE id = $1 AND status IN ('PENDING', 'RUNNING')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("renewal job %s is not outstanding", id)
	}
	return nil
}

func (s *PostgresStore) DeferRenewalJob(ctx context.Context, id string, runAfter time.Time, reason string, escalate bool) error {
	entry, err := json.Marshal([]RenewalAttempt{{
		StartedAt: time.Now(),
		Deferred:  true,
		Reason:    reason,
	}})
	if err != nil {
		return err
	}

	// attempts is decremented because the claim incremented it and no renewal
	// happened. That is restoring the truth rather than fiddling the number:
	// the count means "times we tried to renew this", and a deferral is
	// precisely the case where we did not.
	//
	// last_error is left alone. A deferral is not an error, and overwriting the
	// real reason a job has been failing with "waiting on a rate limit" would
	// hide the thing somebody needs to fix.
	query := `
		UPDATE public.renewal_jobs
		SET status = 'PENDING',
		    run_after = $2,
		    attempts = greatest(attempts - 1, 0),
		    attempt_log = (
		        SELECT coalesce(jsonb_agg(entry), '[]'::jsonb)
		        FROM (
		            SELECT entry FROM jsonb_array_elements(coalesce(attempt_log, '[]'::jsonb) || $3::jsonb) AS entry
		            OFFSET greatest(jsonb_array_length(coalesce(attempt_log, '[]'::jsonb)) + 1 - 50, 0)
		        ) trimmed
		    ),
		    locked_by = NULL,
		    locked_until = NULL,
		    updated_at = now()`
	if escalate {
		// Set once and left. A quota that outlasts the certificate is announced
		// the first time it is noticed, not on every deferral for the months
		// until it expires.
		query += ", escalated_at = coalesce(escalated_at, now())"
	}
	query += " WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, id, runAfter, entry)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("renewal job %s not found", id)
	}
	return nil
}

func (s *PostgresStore) CountRecentRenewals(ctx context.Context, caAccountID string, since time.Time) (int, *time.Time, error) {
	var count int
	var oldest *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT count(*), min(completed_at)
		FROM public.renewal_jobs
		WHERE ca_account_id = $1 AND status = 'SUCCEEDED' AND completed_at >= $2`,
		caAccountID, since).Scan(&count, &oldest)
	if err != nil {
		return 0, nil, err
	}
	return count, oldest, nil
}

// defaultWindowHours keeps a zero window out of the database. The column has a
// check constraint requiring it to be positive, and a caller that simply did
// not set the field would otherwise have its whole write rejected for a value
// it never meant to supply.
func defaultWindowHours(hours int) int {
	if hours <= 0 {
		return 168
	}
	return hours
}

// UpdateCertificateRenewalInfo records what the CA last said about when to
// renew one certificate.
//
// Separate from UpdateCertificate, which writes the whole record: the ARI
// poller runs continuously and concurrently with everything else, and letting
// it write a full certificate row would let a stale copy in its hand overwrite
// a renewal that completed while it was asking.
func (s *PostgresStore) UpdateCertificateRenewalInfo(ctx context.Context, id string, info RenewalInfoUpdate) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.certificates
		SET renewal_scheduled_at = $2,
		    ari_window_start = $3,
		    ari_window_end = $4,
		    ari_explanation_url = $5,
		    ari_checked_at = $6,
		    ari_next_check_at = $7,
		    ari_supported = $8,
		    updated_at = now()
		WHERE id = $1`,
		id, info.RenewalScheduledAt, info.WindowStart, info.WindowEnd,
		nullIfEmpty(info.ExplanationURL), info.CheckedAt, info.NextCheckAt, info.Supported)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetCertificatesDueForARICheck(ctx context.Context, now time.Time, limit int) ([]*Certificate, error) {
	if limit <= 0 {
		limit = 100
	}
	// Only certificates that could act on the answer: renewed automatically,
	// issued by a CA account, and with a body to name to that CA. Asking about
	// anything else spends somebody's rate limit to learn nothing.
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateColumns+`
		FROM public.certificates
		WHERE auto_renew = true
		  AND ca_account_id IS NOT NULL
		  AND certificate_pem IS NOT NULL
		  AND status IN ('ISSUED', 'EXPIRING', 'RENEWAL_FAILED')
		  AND (ari_next_check_at IS NULL OR ari_next_check_at <= $1)
		ORDER BY not_after ASC NULLS LAST
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

func (s *PostgresStore) GetCertificatesDueForVerification(ctx context.Context, now time.Time, limit int) ([]*Certificate, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateColumns+`
		FROM public.certificates
		WHERE verify_after IS NOT NULL AND verify_after <= $1
		ORDER BY verify_after ASC
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, rows.Err()
}

// UpdateCertificateVerification records the outcome of one verification pass.
//
// Narrow rather than a full UpdateCertificate for the same reason the renewal
// information writer is: the verifier runs concurrently with everything else,
// and a whole-row write from a stale copy would undo a renewal that completed
// while it was probing.
func (s *PostgresStore) UpdateCertificateVerification(ctx context.Context, id string, update VerificationUpdate) error {
	// previous_fingerprint is coalesced rather than overwritten: it is set once
	// by the renewal that scheduled the check, and every pass afterwards has to
	// keep it in order to tell "still on the old certificate" from "something
	// else is here".
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.certificates
		SET verification_state = $2,
		    verification_detail = $3,
		    last_verified_at = $4,
		    verify_after = $5,
		    verification_attempts = $6,
		    previous_fingerprint = coalesce($7, previous_fingerprint),
		    updated_at = now()
		WHERE id = $1`,
		id, nullIfEmpty(update.State), nullIfEmpty(update.Detail),
		update.CheckedAt, update.VerifyAfter, update.Attempts,
		nullIfEmpty(update.PreviousFingerprint))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("certificate %s not found", id)
	}
	return nil
}

// GetEndpointsServingCertificate returns the endpoints discovery last observed
// serving one certificate.
//
// DISTINCT ON keeps only the newest observation of each host and port: an
// endpoint scanned nightly for a month would otherwise appear thirty times and
// be probed thirty times to answer one question.
//
// Matched on either the link discovery drew to inventory or the raw
// fingerprint, because a certificate found before it was adopted has the second
// and not the first.
func (s *PostgresStore) GetEndpointsServingCertificate(ctx context.Context, certificateID, fingerprint string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host, port FROM (
			SELECT DISTINCT ON (host, port) host, port, matched_certificate_id, fingerprint_sha256
			FROM public.discovery_results
			WHERE reachable
			ORDER BY host, port, scanned_at DESC
		) latest
		WHERE matched_certificate_id = $1
		   OR ($2 <> '' AND fingerprint_sha256 = $2)`, certificateID, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := []string{}
	for rows.Next() {
		var host string
		var port int
		if err := rows.Scan(&host, &port); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return endpoints, rows.Err()
}

// ── Deployment queue ────────────────────────────────────────

const deploymentJobColumns = `id, deployment_id, certificate_id, target_id, reason, status,
		run_after, coalesce(attempts, 0), locked_by, locked_until,
		coalesce(last_error, ''), coalesce(attempt_log, '[]'::jsonb),
		coalesce(deploy_order, 0), coalesce(fingerprint, ''), not_after, escalated_at,
		triggered_by, actor_email, started_at, completed_at, created_at, updated_at`

func scanDeploymentJob(row pgx.Row) (*DeploymentJob, error) {
	j := &DeploymentJob{}
	var logJSON []byte
	err := row.Scan(
		&j.ID, &j.DeploymentID, &j.CertificateID, &j.TargetID, &j.Reason, &j.Status,
		&j.RunAfter, &j.Attempts, &j.LockedBy, &j.LockedUntil,
		&j.LastError, &logJSON,
		&j.DeployOrder, &j.Fingerprint, &j.NotAfter, &j.EscalatedAt,
		&j.TriggeredBy, &j.ActorEmail, &j.StartedAt, &j.CompletedAt, &j.CreatedAt, &j.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(logJSON) > 0 {
		_ = json.Unmarshal(logJSON, &j.AttemptLog)
	}
	if j.AttemptLog == nil {
		j.AttemptLog = []DeploymentAttempt{}
	}
	return j, nil
}

// EnqueueDeployment creates a job unless one is outstanding for this binding.
//
// The conflict target is deployment_id — the place — not certificate_id. A
// certificate bound to six targets needs six outstanding jobs, and copying the
// renewal queue's constraint here would have deployed to the first target and
// discarded the other five without a word.
func (s *PostgresStore) EnqueueDeployment(ctx context.Context, job *DeploymentJob) (bool, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO public.deployment_jobs
			(deployment_id, certificate_id, target_id, reason, status, run_after,
			 deploy_order, fingerprint, not_after, triggered_by, actor_email)
		VALUES ($1, $2, $3, $4, 'PENDING', $5, $6, $7, $8, $9, $10)
		ON CONFLICT (deployment_id) WHERE status IN ('PENDING', 'RUNNING') DO NOTHING
		RETURNING `+deploymentJobColumns,
		job.DeploymentID, job.CertificateID, job.TargetID, job.Reason, job.RunAfter,
		job.DeployOrder, nullIfEmpty(job.Fingerprint), job.NotAfter, job.TriggeredBy, job.ActorEmail)

	created, err := scanDeploymentJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		existing, findErr := s.outstandingDeploymentJob(ctx, job.DeploymentID)
		if findErr != nil {
			return false, findErr
		}
		if existing != nil {
			*job = *existing
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	*job = *created
	return true, nil
}

func (s *PostgresStore) outstandingDeploymentJob(ctx context.Context, deploymentID string) (*DeploymentJob, error) {
	job, err := scanDeploymentJob(s.pool.QueryRow(ctx,
		"SELECT "+deploymentJobColumns+` FROM public.deployment_jobs
		 WHERE deployment_id = $1 AND status IN ('PENDING', 'RUNNING')
		 ORDER BY created_at DESC LIMIT 1`, deploymentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return job, err
}

func (s *PostgresStore) ClaimDeploymentJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*DeploymentJob, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE public.deployment_jobs
		SET status = 'RUNNING',
		    locked_by = $1,
		    locked_until = $2,
		    attempts = attempts + 1,
		    started_at = coalesce(started_at, $3),
		    updated_at = now()
		WHERE id = (
			SELECT c.id FROM public.deployment_jobs c
			JOIN public.deployment_targets t ON t.id = c.target_id
			-- Agent targets are deployed to by the host, not from here. A core
			-- worker that claimed one would fail it for as long as the attempt
			-- budget lasted, being loudly wrong about something that works —
			-- the same shape of defect as a renewal sweep claiming jobs for
			-- certificates whose keys it does not hold.
			WHERE t.agent_id IS NULL
			  AND ((c.status = 'PENDING' AND c.run_after <= $3)
			    OR (c.status = 'RUNNING' AND c.locked_until IS NOT NULL AND c.locked_until < $3))
			  -- The canary, and it needs no configuration to exist.
			  --
			  -- A job that has not itself failed waits while another job for the
			  -- same certificate has. The first target attempted therefore
			  -- becomes the canary on every certificate, automatically: one bad
			  -- renewal reaches one listener rather than forty, and the other
			  -- thirty-nine resume the moment it clears.
			  --
			  -- Keyed on last_error rather than on attempts, which is the
			  -- version that does not leak. A failing job spends part of every
			  -- retry cycle in RUNNING, and a predicate looking for a *waiting*
			  -- failure found none during those seconds — so the rollout
			  -- marched on through the estate one retry at a time. Having
			  -- failed is a property of the job; being idle is a property of
			  -- the moment.
			  --
			  -- The exemption for jobs that have themselves failed is what stops
			  -- two failures holding each other still for ever, which would
			  -- freeze the retry curve rather than pace it.
			  AND (coalesce(c.last_error, '') <> '' OR NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs f
			      WHERE f.certificate_id = c.certificate_id
			        AND f.id <> c.id
			        AND f.status IN ('PENDING', 'RUNNING')
			        AND coalesce(f.last_error, '') <> ''))
			  -- Waves. A job waits while anything for the same certificate in
			  -- an earlier wave is still outstanding.
			  --
			  -- Race-free in the safe direction: a worker that reads an earlier
			  -- job before the transaction claiming it has committed still sees
			  -- it as PENDING, and waits. The failure mode is a delay, never an
			  -- overtake.
			  AND NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs w
			      WHERE w.certificate_id = c.certificate_id
			        AND w.deploy_order < c.deploy_order
			        AND w.status IN ('PENDING', 'RUNNING'))
			  -- An earlier wave that gave up stops the ones behind it, and this
			  -- is deliberately stricter than the same-wave rule above.
			  --
			  -- Within a wave a terminally failed job stops blocking, so one
			  -- dead target does not hold up its peers. Across waves the
			  -- opposite is right: the entire point of declaring "staging, then
			  -- production" is that a certificate staging would not accept must
			  -- not reach production.
			  --
			  -- Only the *latest* job for that binding counts, and the inner
			  -- NOT EXISTS is what says so. Without it the clause matched any
			  -- failure ever recorded, so one bad afternoon in staging blocked
			  -- production for ever — including after staging had been fixed
			  -- and had deployed successfully twice since. A terminally failed
			  -- job cannot be cancelled either, so there was no way out at all.
			  -- Found by running it.
			  --
			  -- Scoped this way the question is "is that place currently
			  -- broken", which is what an operator means, and the way out is
			  -- the obvious one: fix staging and deploy again.
			  AND NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs w
			      WHERE w.certificate_id = c.certificate_id
			        AND w.deploy_order < c.deploy_order
			        AND w.status = 'FAILED'
			        AND NOT EXISTS (
			            SELECT 1 FROM public.deployment_jobs newer
			            WHERE newer.deployment_id = w.deployment_id
			              AND newer.created_at > w.created_at))
			-- Wave first, so the order the operator declared is the order the
			-- queue works in. Expiry breaks ties within a wave, as before.
			ORDER BY c.deploy_order ASC, c.not_after ASC NULLS LAST, c.run_after ASC
			FOR UPDATE OF c SKIP LOCKED
			LIMIT 1
		)
		RETURNING `+deploymentJobColumns,
		worker, now.Add(lease), now)

	job, err := scanDeploymentJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return job, err
}

func (s *PostgresStore) ExtendDeploymentLease(ctx context.Context, id, worker string, until time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.deployment_jobs
		SET locked_until = $3, updated_at = now()
		WHERE id = $1 AND locked_by = $2 AND status = 'RUNNING'`, id, worker, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment job %s is no longer held by %s", id, worker)
	}
	return nil
}

func (s *PostgresStore) CompleteDeploymentJob(ctx context.Context, id, status string,
	attempt DeploymentAttempt, runAfter time.Time, escalate bool) error {
	attemptJSON, err := json.Marshal([]DeploymentAttempt{attempt})
	if err != nil {
		return err
	}

	query := `
		UPDATE public.deployment_jobs
		SET status = $2,
		    last_error = $3,
		    attempt_log = (
		        SELECT coalesce(jsonb_agg(entry), '[]'::jsonb)
		        FROM (
		            SELECT entry FROM jsonb_array_elements(coalesce(attempt_log, '[]'::jsonb) || $4::jsonb) AS entry
		            OFFSET greatest(jsonb_array_length(coalesce(attempt_log, '[]'::jsonb)) + 1 - 50, 0)
		        ) trimmed
		    ),
		    locked_by = NULL,
		    locked_until = NULL,
		    updated_at = now()`
	args := []any{id, status, nullIfEmpty(attempt.Error), attemptJSON}

	if status == DeployPending {
		query += ", run_after = $5"
		args = append(args, runAfter)
	} else {
		query += ", completed_at = now()"
	}
	if escalate {
		query += ", escalated_at = coalesce(escalated_at, now())"
	}
	query += " WHERE id = $1"

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment job %s not found", id)
	}
	return nil
}

func (s *PostgresStore) GetDeploymentJob(ctx context.Context, id string) (*DeploymentJob, error) {
	job, err := scanDeploymentJob(s.pool.QueryRow(ctx,
		"SELECT "+deploymentJobColumns+" FROM public.deployment_jobs WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("deployment job %s not found", id)
	}
	return job, err
}

func (s *PostgresStore) ListDeploymentJobs(ctx context.Context, filter DeploymentJobFilter) ([]*DeploymentJob, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.CertificateID != "" {
		add("certificate_id = $%d", filter.CertificateID)
	}
	if filter.TargetID != "" {
		add("target_id = $%d", filter.TargetID)
	}
	if filter.DeploymentID != "" {
		add("deployment_id = $%d", filter.DeploymentID)
	}
	if filter.Status != "" {
		add("status = $%d", filter.Status)
	}
	if filter.OutstandingOnly {
		where = append(where, "status IN ('PENDING', 'RUNNING')")
	}
	if filter.EscalatedOnly {
		where = append(where, "escalated_at IS NOT NULL")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.deployment_jobs WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + deploymentJobColumns + " FROM public.deployment_jobs WHERE " + clause +
		fmt.Sprintf(" ORDER BY not_after ASC NULLS LAST, created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*DeploymentJob, 0)
	for rows.Next() {
		job, err := scanDeploymentJob(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, job)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) CancelDeploymentJob(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.deployment_jobs
		SET status = 'CANCELLED', completed_at = now(), locked_by = NULL, locked_until = NULL, updated_at = now()
		WHERE id = $1 AND status IN ('PENDING', 'RUNNING')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment job %s is not outstanding", id)
	}
	return nil
}

// ── Agents ──────────────────────────────────────────────────

const agentColumns = `id, name, coalesce(hostname, ''), coalesce(platform, ''), coalesce(version, ''),
		public_key, key_id, status, coalesce(labels, '{}'::jsonb),
		enrol_token_id, enrolled_at, coalesce(enrolled_from, ''),
		last_seen_at, coalesce(last_seen_ip, ''), coalesce(heartbeat_interval_seconds, 300),
		stale_alerted_at, last_inventory_at, coalesce(certificates_seen, 0), coalesce(unmanaged_seen, 0),
		revoked_at, revoked_by, created_at, updated_at`

func scanAgent(row pgx.Row) (*Agent, error) {
	a := &Agent{}
	var labelsJSON []byte
	err := row.Scan(&a.ID, &a.Name, &a.Hostname, &a.Platform, &a.Version,
		&a.PublicKey, &a.KeyID, &a.Status, &labelsJSON,
		&a.EnrolTokenID, &a.EnrolledAt, &a.EnrolledFrom,
		&a.LastSeenAt, &a.LastSeenIP, &a.HeartbeatIntervalSeconds,
		&a.StaleAlertedAt, &a.LastInventoryAt, &a.CertificatesSeen, &a.UnmanagedSeen,
		&a.RevokedAt, &a.RevokedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(labelsJSON) > 0 {
		_ = json.Unmarshal(labelsJSON, &a.Labels)
	}
	return a, nil
}

func (s *PostgresStore) ListAgents(ctx context.Context, filter AgentFilter) ([]*Agent, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	if filter.Status != "" {
		args = append(args, filter.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.StaleOnly {
		// The same arithmetic GetStaleAgents uses, so a list filtered to the
		// stale ones and an alert about them can never disagree.
		where = append(where, agentStalePredicate("now()"))
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.agents WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, filter.Offset)
	// Quiet agents first. The question a PKI team asks a list of agents is
	// which hosts have stopped being maintained, and sorting by name buries
	// that in the middle.
	query := "SELECT " + agentColumns + " FROM public.agents WHERE " + clause +
		fmt.Sprintf(" ORDER BY last_seen_at ASC NULLS FIRST, name ASC LIMIT $%d OFFSET $%d",
			len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*Agent, 0)
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// agentStalePredicate is the one definition of "this agent has stopped
// reporting", in SQL, parameterised only by what "now" is.
//
// Written once because it appears in two queries, and two copies of a staleness
// rule is how a dashboard ends up disagreeing with the alert that woke somebody
// up.
//
// The cast on `now` is not decoration. With a bare `$1` here, PostgreSQL has to
// infer the parameter's type from its context — and the only context is
// `$1 - <interval>`, which resolves perfectly happily as interval arithmetic.
// The parameter came out as an interval, the whole right-hand side became an
// interval, and the comparison failed at runtime with "operator does not exist:
// timestamp with time zone < interval". The identical predicate with a literal
// `now()` worked, which is why this survived until it was run.
//
// make_interval rather than multiplying an interval literal, for the same
// reason: no precedence to reason about, and no chance of the next reader
// having to.
func agentStalePredicate(now string) string {
	return fmt.Sprintf(`status = 'ACTIVE'
		AND coalesce(last_seen_at, enrolled_at)
		    < (%s)::timestamptz - make_interval(secs => heartbeat_interval_seconds * %d)`,
		now, AgentStaleAfter)
}

func (s *PostgresStore) GetAgent(ctx context.Context, id string) (*Agent, error) {
	a, err := scanAgent(s.pool.QueryRow(ctx,
		"SELECT "+agentColumns+" FROM public.agents WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("agent %s not found", id)
	}
	return a, err
}

func (s *PostgresStore) CreateAgent(ctx context.Context, a *Agent) error {
	labels := a.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return err
	}

	// The same floor the in-memory store applies. The column carries DEFAULT
	// 300 and a CHECK that it is positive, but passing an explicit zero
	// overrides the default and violates the check — so a caller that left the
	// field unset was refused here and accepted in memory. Found by the
	// conformance suite, which is the entire reason it exists.
	if a.HeartbeatIntervalSeconds <= 0 {
		a.HeartbeatIntervalSeconds = defaultAgentHeartbeatSeconds
	}

	return s.pool.QueryRow(ctx, `
		INSERT INTO public.agents
			(name, hostname, platform, version, public_key, key_id, status, labels,
			 enrol_token_id, enrolled_from, heartbeat_interval_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7, $8, $9, $10)
		RETURNING id, enrolled_at, created_at, updated_at`,
		a.Name, nullIfEmpty(a.Hostname), nullIfEmpty(a.Platform), nullIfEmpty(a.Version),
		a.PublicKey, a.KeyID, labelsJSON, a.EnrolTokenID, nullIfEmpty(a.EnrolledFrom),
		a.HeartbeatIntervalSeconds,
	).Scan(&a.ID, &a.EnrolledAt, &a.CreatedAt, &a.UpdatedAt)
}

func (s *PostgresStore) RevokeAgent(ctx context.Context, id string, revokedBy *string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.agents
		SET status = 'REVOKED', revoked_at = now(), revoked_by = $2, updated_at = now()
		WHERE id = $1 AND status <> 'REVOKED'`, id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent %s is not active", id)
	}
	return nil
}

func (s *PostgresStore) DeleteAgent(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.agents WHERE id = $1", id)
	return err
}

// RecordAgentHeartbeat writes what an agent last reported.
//
// Scoped to active agents. A revoked agent whose process has not noticed yet
// keeps calling, and letting those calls move last_seen_at would make a
// credential somebody deliberately withdrew look like a healthy host.
func (s *PostgresStore) RecordAgentHeartbeat(ctx context.Context, id string, hb AgentHeartbeat) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.agents
		SET last_seen_at = $2,
		    last_seen_ip = $3,
		    version = coalesce(nullif($4, ''), version),
		    platform = coalesce(nullif($5, ''), platform),
		    hostname = coalesce(nullif($6, ''), hostname),
		    heartbeat_interval_seconds = case when $7 > 0 then $7 else heartbeat_interval_seconds end,
		    -- Cleared on contact, so an agent that comes back is alerted on
		    -- again if it goes away a second time.
		    stale_alerted_at = NULL,
		    updated_at = now()
		WHERE id = $1 AND status = 'ACTIVE'`,
		id, hb.SeenAt, nullIfEmpty(hb.SeenIP), hb.Version, hb.Platform, hb.Hostname, hb.IntervalSeconds)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent %s is not active", id)
	}
	return nil
}

func (s *PostgresStore) GetStaleAgents(ctx context.Context, now time.Time, limit int) ([]*Agent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		"SELECT "+agentColumns+" FROM public.agents WHERE "+agentStalePredicate("$1")+`
		 AND stale_alerted_at IS NULL
		 ORDER BY coalesce(last_seen_at, enrolled_at) ASC
		 LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkAgentStaleAlerted(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE public.agents SET stale_alerted_at = $2, updated_at = now() WHERE id = $1", id, at)
	return err
}

// ── Agent enrolment tokens ──────────────────────────────────

const agentEnrolTokenColumns = `id, name, token_hash, expires_at,
		coalesce(max_uses, 1), coalesce(uses, 0), coalesce(labels, '{}'::jsonb),
		revoked_at, revoked_by, created_by, created_at, updated_at`

func scanAgentEnrolToken(row pgx.Row) (*AgentEnrolToken, error) {
	t := &AgentEnrolToken{}
	var labelsJSON []byte
	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.ExpiresAt,
		&t.MaxUses, &t.Uses, &labelsJSON,
		&t.RevokedAt, &t.RevokedBy, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(labelsJSON) > 0 {
		_ = json.Unmarshal(labelsJSON, &t.Labels)
	}
	return t, nil
}

func (s *PostgresStore) ListAgentEnrolTokens(ctx context.Context) ([]*AgentEnrolToken, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+agentEnrolTokenColumns+" FROM public.agent_enrol_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AgentEnrolToken{}
	for rows.Next() {
		t, err := scanAgentEnrolToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateAgentEnrolToken(ctx context.Context, t *AgentEnrolToken) error {
	labels := t.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.agent_enrol_tokens (name, token_hash, expires_at, max_uses, labels, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`,
		t.Name, t.TokenHash, t.ExpiresAt, t.MaxUses, labelsJSON, t.CreatedBy,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

func (s *PostgresStore) GetAgentEnrolTokenByHash(ctx context.Context, tokenHash string) (*AgentEnrolToken, error) {
	t, err := scanAgentEnrolToken(s.pool.QueryRow(ctx,
		"SELECT "+agentEnrolTokenColumns+" FROM public.agent_enrol_tokens WHERE token_hash = $1", tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ConsumeAgentEnrolToken spends one use, and only if there is one left.
//
// The check is in the WHERE clause rather than in Go. Two hosts booting from
// the same image enrol in the same second; a read-then-write would let a
// one-use token enrol both, which is precisely the property a one-use token
// exists to have.
func (s *PostgresStore) ConsumeAgentEnrolToken(ctx context.Context, id string, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.agent_enrol_tokens
		SET uses = uses + 1, updated_at = now()
		WHERE id = $1
		  AND revoked_at IS NULL
		  AND expires_at > $2
		  AND uses < max_uses`, id, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) ClaimAgentRequestSignature(ctx context.Context, agentID string, signatureHash []byte, expiresAt time.Time) (bool, error) {
	// ON CONFLICT DO NOTHING rather than a SELECT then an INSERT. Two copies of
	// one captured request can reach two replicas in the same millisecond, and
	// with a read-then-write both would find nothing and both would proceed.
	// Here the primary key decides, and exactly one insert reports a row.
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO public.agent_request_signatures (agent_id, signature_hash, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (agent_id, signature_hash) DO NOTHING`, agentID, signatureHash, expiresAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) SweepAgentRequestSignatures(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM public.agent_request_signatures WHERE expires_at <= $1", now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *PostgresStore) RevokeAgentEnrolToken(ctx context.Context, id string, revokedBy *string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.agent_enrol_tokens
		SET revoked_at = now(), revoked_by = $2, updated_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("enrolment token %s is already revoked", id)
	}
	return nil
}

// ── What is on the hosts ────────────────────────────────────

const agentCertificateColumns = `ac.id, ac.agent_id, ac.path, ac.kind, coalesce(ac.certificate_count, 1),
		coalesce(ac.common_name, ''), coalesce(ac.subject_dn, ''), coalesce(ac.issuer_dn, ''),
		coalesce(ac.serial_number, ''), coalesce(ac.sans, '[]'::jsonb),
		ac.not_before, ac.not_after, coalesce(ac.key_type, ''), coalesce(ac.key_size, 0),
		coalesce(ac.fingerprint_sha256, ''), coalesce(ac.certificate_pem, ''),
		coalesce(ac.file_mode, ''), coalesce(ac.file_owner, ''), ac.modified_at,
		coalesce(ac.private_key_path, ''), coalesce(ac.private_key_mode, ''),
		coalesce(ac.private_key_in_same_file, false), coalesce(ac.private_key_matches, false),
		coalesce(ac.referenced_by, '[]'::jsonb),
		ac.management_state, ac.matched_certificate_id, coalesce(ac.findings, '[]'::jsonb),
		ac.first_seen_at, ac.last_seen_at, ac.removed_at, ac.created_at,
		coalesce(a.name, '')`

func scanAgentCertificate(row pgx.Row) (*AgentCertificate, error) {
	c := &AgentCertificate{}
	var sansJSON, refsJSON, findingsJSON []byte
	err := row.Scan(&c.ID, &c.AgentID, &c.Path, &c.Kind, &c.CertificateCount,
		&c.CommonName, &c.SubjectDN, &c.IssuerDN,
		&c.SerialNumber, &sansJSON,
		&c.NotBefore, &c.NotAfter, &c.KeyType, &c.KeySize,
		&c.FingerprintSHA256, &c.CertificatePEM,
		&c.FileMode, &c.FileOwner, &c.ModifiedAt,
		&c.PrivateKeyPath, &c.PrivateKeyMode, &c.PrivateKeyInSameFile, &c.PrivateKeyMatches,
		&refsJSON,
		&c.ManagementState, &c.MatchedCertificateID, &findingsJSON,
		&c.FirstSeenAt, &c.LastSeenAt, &c.RemovedAt, &c.CreatedAt,
		&c.AgentName)
	if err != nil {
		return nil, err
	}
	for raw, out := range map[*[]byte]any{&sansJSON: &c.SANs, &refsJSON: &c.ReferencedBy, &findingsJSON: &c.Findings} {
		if len(*raw) > 0 {
			_ = json.Unmarshal(*raw, out)
		}
	}
	if c.Findings == nil {
		c.Findings = []Finding{}
	}
	return c, nil
}

// UpsertAgentCertificates writes one scan's results.
//
// xmax = 0 in the RETURNING clause is how an insert is told from an update in
// an upsert: PostgreSQL leaves the row's delete-transaction id at zero on a
// fresh insert. That distinction is the whole value of the return — an alert is
// built from what is new, and re-reporting the same forty files every six hours
// is how a channel gets muted.
func (s *PostgresStore) UpsertAgentCertificates(ctx context.Context, certs []*AgentCertificate) ([]*AgentCertificate, error) {
	created := []*AgentCertificate{}

	for _, c := range certs {
		sansJSON, err := json.Marshal(orEmptyStrings(c.SANs))
		if err != nil {
			return nil, err
		}
		refsJSON, err := json.Marshal(orEmptyStrings(c.ReferencedBy))
		if err != nil {
			return nil, err
		}
		findingsJSON, err := json.Marshal(orEmptyFindings(c.Findings))
		if err != nil {
			return nil, err
		}

		var isNew bool
		err = s.pool.QueryRow(ctx, `
			INSERT INTO public.agent_certificates
				(agent_id, path, kind, certificate_count, common_name, subject_dn, issuer_dn,
				 serial_number, sans, not_before, not_after, key_type, key_size,
				 fingerprint_sha256, certificate_pem, file_mode, file_owner, modified_at,
				 private_key_path, private_key_mode, private_key_in_same_file, private_key_matches,
				 referenced_by, management_state, matched_certificate_id, findings, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			        $19, $20, $21, $22, $23, $24, $25, $26, now())
			ON CONFLICT (agent_id, path) DO UPDATE SET
				kind = excluded.kind,
				certificate_count = excluded.certificate_count,
				common_name = excluded.common_name,
				subject_dn = excluded.subject_dn,
				issuer_dn = excluded.issuer_dn,
				serial_number = excluded.serial_number,
				sans = excluded.sans,
				not_before = excluded.not_before,
				not_after = excluded.not_after,
				key_type = excluded.key_type,
				key_size = excluded.key_size,
				fingerprint_sha256 = excluded.fingerprint_sha256,
				certificate_pem = excluded.certificate_pem,
				file_mode = excluded.file_mode,
				file_owner = excluded.file_owner,
				modified_at = excluded.modified_at,
				private_key_path = excluded.private_key_path,
				private_key_mode = excluded.private_key_mode,
				private_key_in_same_file = excluded.private_key_in_same_file,
				private_key_matches = excluded.private_key_matches,
				referenced_by = excluded.referenced_by,
				management_state = excluded.management_state,
				matched_certificate_id = excluded.matched_certificate_id,
				findings = excluded.findings,
				last_seen_at = now(),
				-- A file that came back is not removed any more.
				removed_at = NULL
			RETURNING id, first_seen_at, created_at, (xmax = 0)`,
			c.AgentID, c.Path, c.Kind, c.CertificateCount, nullIfEmpty(c.CommonName),
			nullIfEmpty(c.SubjectDN), nullIfEmpty(c.IssuerDN), nullIfEmpty(c.SerialNumber), sansJSON,
			c.NotBefore, c.NotAfter, nullIfEmpty(c.KeyType), c.KeySize,
			nullIfEmpty(c.FingerprintSHA256), nullIfEmpty(c.CertificatePEM),
			nullIfEmpty(c.FileMode), nullIfEmpty(c.FileOwner), c.ModifiedAt,
			nullIfEmpty(c.PrivateKeyPath), nullIfEmpty(c.PrivateKeyMode),
			c.PrivateKeyInSameFile, c.PrivateKeyMatches,
			refsJSON, c.ManagementState, c.MatchedCertificateID, findingsJSON,
		).Scan(&c.ID, &c.FirstSeenAt, &c.CreatedAt, &isNew)
		if err != nil {
			return nil, err
		}
		if isNew {
			created = append(created, c)
		}
	}
	return created, nil
}

func (s *PostgresStore) MarkAgentCertificatesRemoved(ctx context.Context, agentID string,
	seenPaths []string, at time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.agent_certificates
		SET removed_at = $3
		WHERE agent_id = $1 AND removed_at IS NULL AND NOT (path = ANY($2))`,
		agentID, seenPaths, at)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *PostgresStore) ListAgentCertificates(ctx context.Context, filter AgentCertificateFilter) ([]*AgentCertificate, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.AgentID != "" {
		add("ac.agent_id = $%d", filter.AgentID)
	}
	if filter.ManagementState != "" {
		add("ac.management_state = $%d", filter.ManagementState)
	}
	if filter.Kind != "" {
		add("ac.kind = $%d", filter.Kind)
	}
	if filter.Finding != "" {
		// jsonb containment, so the finding filter runs in the database and on
		// an estate of thousands rather than in Go over everything.
		args = append(args, fmt.Sprintf(`[{"code":%q}]`, filter.Finding))
		where = append(where, fmt.Sprintf("ac.findings @> $%d::jsonb", len(args)))
	}
	if !filter.IncludeRemoved {
		where = append(where, "ac.removed_at IS NULL")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.agent_certificates ac WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + agentCertificateColumns + `
		FROM public.agent_certificates ac
		LEFT JOIN public.agents a ON a.id = ac.agent_id
		WHERE ` + clause +
		fmt.Sprintf(" ORDER BY ac.not_after ASC NULLS LAST, ac.path ASC LIMIT $%d OFFSET $%d",
			len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*AgentCertificate, 0)
	for rows.Next() {
		c, err := scanAgentCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) MarkAgentInventoried(ctx context.Context, id string, summary AgentInventorySummary) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE public.agents
		SET last_inventory_at = $2, certificates_seen = $3, unmanaged_seen = $4, updated_at = now()
		WHERE id = $1`, id, summary.ScannedAt, summary.Seen, summary.Unmanaged)
	return err
}

func (s *PostgresStore) GetCertificateBySupersededFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	if fingerprint == "" {
		return nil, nil
	}
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM public.certificates
		 WHERE previous_fingerprint = $1
		 ORDER BY updated_at DESC LIMIT 1`, fingerprint).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.GetCertificate(ctx, id)
}

func orEmptyStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orEmptyFindings(v []Finding) []Finding {
	if v == nil {
		return []Finding{}
	}
	return v
}

// ── What a host may ask for ─────────────────────────────────

const templateGrantColumns = `id, name, template_id, subject_kind,
		agent_id, coalesce(label_selector, '{}'::jsonb), role, team, user_id,
		coalesce(names, '[]'::jsonb),
		coalesce(is_enabled, true), revoked_at, revoked_by, created_by, created_at, updated_at`

func scanTemplateGrant(row pgx.Row) (*TemplateGrant, error) {
	g := &TemplateGrant{}
	var selectorJSON, namesJSON []byte
	err := row.Scan(&g.ID, &g.Name, &g.TemplateID, &g.SubjectKind,
		&g.AgentID, &selectorJSON, &g.Role, &g.Team, &g.UserID,
		&namesJSON,
		&g.IsEnabled, &g.RevokedAt, &g.RevokedBy, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(selectorJSON) > 0 {
		_ = json.Unmarshal(selectorJSON, &g.LabelSelector)
	}
	if len(namesJSON) > 0 {
		_ = json.Unmarshal(namesJSON, &g.Names)
	}
	g.Names = orEmptyStrings(g.Names)
	return g, nil
}

func (s *PostgresStore) ListTemplateGrants(ctx context.Context) ([]*TemplateGrant, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+templateGrantColumns+" FROM public.template_grants ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*TemplateGrant{}
	for rows.Next() {
		g, err := scanTemplateGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetTemplateGrant(ctx context.Context, id string) (*TemplateGrant, error) {
	g, err := scanTemplateGrant(s.pool.QueryRow(ctx,
		"SELECT "+templateGrantColumns+" FROM public.template_grants WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("grant %s not found", id)
	}
	return g, err
}

func (s *PostgresStore) CreateTemplateGrant(ctx context.Context, g *TemplateGrant) error {
	selectorJSON, err := json.Marshal(orEmptyMap(g.LabelSelector))
	if err != nil {
		return err
	}
	namesJSON, err := json.Marshal(orEmptyStrings(g.Names))
	if err != nil {
		return err
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.template_grants
			(name, template_id, subject_kind,
			 agent_id, label_selector, role, team, user_id,
			 names, is_enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at`,
		g.Name, g.TemplateID, g.SubjectKind,
		g.AgentID, selectorJSON, g.Role, g.Team, g.UserID,
		namesJSON, g.IsEnabled, g.CreatedBy,
	).Scan(&g.ID, &g.CreatedAt, &g.UpdatedAt)
}

func (s *PostgresStore) RevokeTemplateGrant(ctx context.Context, id string, revokedBy *string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.template_grants
		SET revoked_at = now(), revoked_by = $2, is_enabled = false, updated_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("grant %s is already revoked", id)
	}
	return nil
}

// GetGrantsForAgent returns the live grants that apply to one host.
//
// The label match is done in the database with jsonb containment: the agent's
// labels must contain everything the selector asks for. Doing it here rather
// than by loading every grant and filtering in Go means an estate with a
// thousand grants costs one indexed query per request rather than a thousand
// comparisons.
func (s *PostgresStore) GetGrantsForAgent(ctx context.Context, agentID string) ([]*TemplateGrant, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+templateGrantColumns+` FROM public.template_grants g
		 WHERE g.revoked_at IS NULL AND g.is_enabled
		   AND (
		     g.agent_id = $1
		     OR (
		       g.label_selector <> '{}'::jsonb
		       AND EXISTS (
		         SELECT 1 FROM public.agents a
		         WHERE a.id = $1 AND coalesce(a.labels, '{}'::jsonb) @> g.label_selector
		       )
		     )
		   )
		 ORDER BY g.agent_id NULLS LAST, g.created_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*TemplateGrant{}
	for rows.Next() {
		g, err := scanTemplateGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func orEmptyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// ── What each host has installed where ──────────────────────

const agentInstallationColumns = `i.id, i.agent_id, i.name, i.certificate_name,
		i.certificate_id, coalesce(i.fingerprint_sha256, ''), i.not_after,
		coalesce(i.paths, '[]'::jsonb), i.status, coalesce(i.detail, ''), coalesce(i.last_error, ''),
		coalesce(i.rolled_back, false), i.installed_at, i.reloaded_at,
		coalesce(i.reload_command, ''), coalesce(i.check_command, ''),
		i.reported_at, i.created_at, i.updated_at,
		coalesce(a.name, ''), coalesce(a.hostname, '')`

func scanAgentInstallation(row pgx.Row) (*AgentInstallation, error) {
	inst := &AgentInstallation{}
	var pathsJSON []byte
	err := row.Scan(&inst.ID, &inst.AgentID, &inst.Name, &inst.CertificateName,
		&inst.CertificateID, &inst.FingerprintSHA256, &inst.NotAfter,
		&pathsJSON, &inst.Status, &inst.Detail, &inst.Error,
		&inst.RolledBack, &inst.InstalledAt, &inst.ReloadedAt,
		&inst.ReloadCommand, &inst.CheckCommand,
		&inst.ReportedAt, &inst.CreatedAt, &inst.UpdatedAt,
		&inst.AgentName, &inst.Hostname)
	if err != nil {
		return nil, err
	}
	if len(pathsJSON) > 0 {
		_ = json.Unmarshal(pathsJSON, &inst.Paths)
	}
	return inst, nil
}

// EnsureAgentDeploymentTarget returns the target that is this agent.
//
// The conflict is resolved on agent_id rather than on the name, because the
// name is the part that can change: a host renamed in the core must not become
// a second place its certificates are deployed to.
func (s *PostgresStore) EnsureAgentDeploymentTarget(ctx context.Context, agent *Agent) (*DeploymentTarget, error) {
	if agent == nil || agent.ID == "" {
		return nil, fmt.Errorf("an agent is required")
	}

	existing, err := scanDeploymentTarget(s.pool.QueryRow(ctx,
		"SELECT "+deploymentTargetColumns+" FROM public.deployment_targets WHERE agent_id = $1", agent.ID))
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	description := fmt.Sprintf(
		"The CertPilot agent on %s. Certificates are installed by the host itself, from a spec on the host.",
		firstNonEmpty(agent.Hostname, agent.Name))

	// Two names tried in order. `deployment_targets.name` is unique across every
	// target type, so a webhook target somebody already called "web-01" would
	// otherwise stop that host from ever becoming a target at all — a collision
	// between two unrelated things that a person would have no way to diagnose
	// from the error.
	candidates := []string{agent.Name, fmt.Sprintf("%s (agent %s)", agent.Name, shortID(agent.ID))}
	var lastErr error
	for _, name := range candidates {
		target, err := scanDeploymentTarget(s.pool.QueryRow(ctx, `
			INSERT INTO public.deployment_targets
				(name, description, target_type, agent_id, is_enabled, deploys_private_key, config_encrypted)
			VALUES ($1, $2, 'agent', $3, true, false, '')
			ON CONFLICT (agent_id) WHERE agent_id IS NOT NULL
			DO UPDATE SET description = excluded.description, updated_at = now()
			RETURNING `+deploymentTargetColumns, name, description, agent.ID))
		if err == nil {
			return target, nil
		}
		lastErr = err
		if !isUniqueViolation(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not create a deployment target for agent %s: %w", agent.Name, lastErr)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ReplaceAgentInstallations writes the full state of one host's destinations.
//
// In one transaction, and destinations the host no longer declares are deleted
// rather than left behind. A destination removed from the spec is a place that
// is no longer being maintained, and leaving the row would show a central team
// a certificate installed somewhere nothing is keeping up to date.
func (s *PostgresStore) ReplaceAgentInstallations(ctx context.Context, agentID string,
	installs []*AgentInstallation) error {

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	names := make([]string, 0, len(installs))
	for _, inst := range installs {
		names = append(names, inst.Name)

		pathsJSON, err := json.Marshal(nonNilStrings(inst.Paths))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO public.agent_installations
				(agent_id, name, certificate_name, certificate_id, fingerprint_sha256, not_after,
				 paths, status, detail, last_error, rolled_back, installed_at, reloaded_at,
				 reload_command, check_command, reported_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14, $15, $16, now())
			ON CONFLICT (agent_id, name) DO UPDATE SET
				certificate_name = excluded.certificate_name,
				certificate_id = excluded.certificate_id,
				fingerprint_sha256 = excluded.fingerprint_sha256,
				not_after = excluded.not_after,
				paths = excluded.paths,
				status = excluded.status,
				detail = excluded.detail,
				last_error = excluded.last_error,
				rolled_back = excluded.rolled_back,
				installed_at = excluded.installed_at,
				reloaded_at = excluded.reloaded_at,
				reload_command = excluded.reload_command,
				check_command = excluded.check_command,
				reported_at = excluded.reported_at,
				updated_at = now()`,
			agentID, inst.Name, inst.CertificateName, inst.CertificateID,
			nullIfEmpty(inst.FingerprintSHA256), inst.NotAfter,
			pathsJSON, inst.Status, nullIfEmpty(inst.Detail), nullIfEmpty(inst.Error),
			inst.RolledBack, inst.InstalledAt, inst.ReloadedAt,
			nullIfEmpty(inst.ReloadCommand), nullIfEmpty(inst.CheckCommand), inst.ReportedAt)
		if err != nil {
			return err
		}
	}

	// = ANY on an empty array removes everything, which is exactly right: a
	// host that has emptied its spec has no destinations, and the central view
	// must stop showing the ones it used to have.
	if _, err := tx.Exec(ctx,
		`DELETE FROM public.agent_installations WHERE agent_id = $1 AND NOT (name = ANY($2))`,
		agentID, names); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListAgentInstallations(ctx context.Context,
	filter AgentInstallationFilter) ([]*AgentInstallation, int64, error) {

	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if filter.AgentID != "" {
		add("i.agent_id = $%d", filter.AgentID)
	}
	if filter.CertificateID != "" {
		add("i.certificate_id = $%d", filter.CertificateID)
	}
	if filter.Status != "" {
		add("i.status = $%d", strings.ToUpper(filter.Status))
	}
	if filter.NeedsAttention {
		where = append(where, "i.status IN ('FAILED', 'UNFULFILLED')")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.agent_installations i WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit, offset := filter.Limit, filter.Offset
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, offset)
	query := "SELECT " + agentInstallationColumns + `
		FROM public.agent_installations i
		LEFT JOIN public.agents a ON a.id = i.agent_id
		WHERE ` + clause + fmt.Sprintf(`
		ORDER BY i.status <> 'FAILED', i.status <> 'UNFULFILLED', a.name ASC, i.name ASC
		LIMIT $%d OFFSET $%d`, len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*AgentInstallation{}
	for rows.Next() {
		inst, err := scanAgentInstallation(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, inst)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) EnsureCertificateDeployment(ctx context.Context,
	d *CertificateDeployment) (*CertificateDeployment, error) {

	options := d.Options
	if options == nil {
		options = map[string]any{}
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO public.certificate_deployments
			(certificate_id, target_id, is_enabled, deploy_on_renewal, options, created_by)
		-- deploy_on_renewal is true and is not the operator's choice here. An
		-- agent binding exists because the host reported installing something,
		-- and the host installs on its own cycle whether this column says so or
		-- not. False would be a switch that claims to stop something it cannot.
		VALUES ($1, $2, true, true, $3::jsonb, $4)
		ON CONFLICT (certificate_id, target_id)
		DO UPDATE SET options = excluded.options, updated_at = now()
		RETURNING id`,
		d.CertificateID, d.TargetID, optionsJSON, d.CreatedBy).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetCertificateDeployment(ctx, id)
}

// ClaimAgentDeploymentJobs leases the jobs waiting for one host.
//
// Scoped to this agent's own target by a join rather than by a column on the
// job, so a host cannot claim work for another host by asking for it: the id
// comes from the signature the middleware verified, and the join is what turns
// that into a set of rows.
func (s *PostgresStore) ClaimAgentDeploymentJobs(ctx context.Context, agentID, worker string,
	lease time.Duration, now time.Time, limit int) ([]*DeploymentJob, error) {

	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE public.deployment_jobs j
		SET status = 'RUNNING',
		    locked_by = $2,
		    locked_until = $3,
		    attempts = attempts + 1,
		    started_at = coalesce(started_at, $4),
		    updated_at = now()
		WHERE j.id IN (
			SELECT c.id FROM public.deployment_jobs c
			JOIN public.deployment_targets t ON t.id = c.target_id
			WHERE t.agent_id = $1
			  AND t.is_enabled
			  AND ((c.status = 'PENDING' AND c.run_after <= $4)
			    OR (c.status = 'RUNNING' AND c.locked_until IS NOT NULL AND c.locked_until < $4))
			  -- The canary, and it needs no configuration to exist.
			  --
			  -- A job that has not itself failed waits while another job for the
			  -- same certificate has. The first target attempted therefore
			  -- becomes the canary on every certificate, automatically: one bad
			  -- renewal reaches one listener rather than forty, and the other
			  -- thirty-nine resume the moment it clears.
			  --
			  -- Keyed on last_error rather than on attempts, which is the
			  -- version that does not leak. A failing job spends part of every
			  -- retry cycle in RUNNING, and a predicate looking for a *waiting*
			  -- failure found none during those seconds — so the rollout
			  -- marched on through the estate one retry at a time. Having
			  -- failed is a property of the job; being idle is a property of
			  -- the moment.
			  --
			  -- The exemption for jobs that have themselves failed is what stops
			  -- two failures holding each other still for ever, which would
			  -- freeze the retry curve rather than pace it.
			  AND (coalesce(c.last_error, '') <> '' OR NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs f
			      WHERE f.certificate_id = c.certificate_id
			        AND f.id <> c.id
			        AND f.status IN ('PENDING', 'RUNNING')
			        AND coalesce(f.last_error, '') <> ''))
			-- Waves, on the same terms as the core worker's claim. An agent
			-- target is still a target: without this an agent in wave 2 would
			-- poll and install while wave 1 was still being attempted from the
			-- core, and the declared order would hold for half the estate.
			AND NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs w
			      WHERE w.certificate_id = c.certificate_id
			        AND w.deploy_order < c.deploy_order
			        AND w.status IN ('PENDING', 'RUNNING'))
			  -- Latest-job-only, for the same reason as the core claim: a
			  -- historical failure must not block a place for ever.
			  AND NOT EXISTS (
			      SELECT 1 FROM public.deployment_jobs w
			      WHERE w.certificate_id = c.certificate_id
			        AND w.deploy_order < c.deploy_order
			        AND w.status = 'FAILED'
			        AND NOT EXISTS (
			            SELECT 1 FROM public.deployment_jobs newer
			            WHERE newer.deployment_id = w.deployment_id
			              AND newer.created_at > w.created_at))
			ORDER BY c.deploy_order ASC, c.not_after ASC NULLS LAST, c.run_after ASC
			-- OF c, not bare FOR UPDATE. A bare one in a joined subquery locks
			-- the deployment_targets row as well, so every agent polling for
			-- work would take a row lock on its own target and an operator
			-- renaming one would block behind the fleet.
			FOR UPDATE OF c SKIP LOCKED
			LIMIT $5
		)
		RETURNING `+deploymentJobColumns,
		agentID, worker, now.Add(lease), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*DeploymentJob{}
	for rows.Next() {
		job, err := scanDeploymentJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// PruneAgentBindings removes bindings for certificates a host no longer holds.
//
// Outstanding jobs go with them, by the foreign key's cascade. That is right: a
// job to install a certificate this host has replaced would, if it ever ran,
// push an older certificate onto a live listener.
func (s *PostgresStore) PruneAgentBindings(ctx context.Context, targetID string,
	keepCertificateIDs []string) (int, error) {

	tag, err := s.pool.Exec(ctx, `
		DELETE FROM public.certificate_deployments d
		USING public.deployment_targets t
		WHERE d.target_id = $1
		  AND t.id = d.target_id
		  -- Belt and braces. This only ever runs for an agent's own target, and
		  -- a bug that pointed it at a webhook target would silently delete
		  -- standing instructions an operator wrote.
		  AND t.agent_id IS NOT NULL
		  AND NOT (d.certificate_id = ANY($2::uuid[]))`, targetID, keepCertificateIDs)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// ── Cryptographic posture ───────────────────────────────────

const endpointTLSPostureColumns = `id, host, port, certificate_id, scan_id,
		coalesce(tls_version, ''), coalesce(cipher_suite, ''), coalesce(key_exchange_group, ''),
		coalesce(hybrid_key_exchange, false), coalesce(offered_hybrid, false),
		supports_tls13, coalesce(alpn, ''),
		coalesce(verdict, ''), coalesce(summary, ''), coalesce(requirements, '[]'::jsonb),
		observed_at`

func scanEndpointTLSPosture(row pgx.Row) (*EndpointTLSPosture, error) {
	p := &EndpointTLSPosture{}
	var requirements []byte
	err := row.Scan(&p.ID, &p.Host, &p.Port, &p.CertificateID, &p.ScanID,
		&p.TLSVersion, &p.CipherSuite, &p.KeyExchangeGroup,
		&p.HybridKeyExchange, &p.OfferedHybrid,
		&p.SupportsTLS13, &p.ALPN,
		&p.Verdict, &p.Summary, &requirements,
		&p.ObservedAt)
	if err != nil {
		return nil, err
	}
	p.Requirements = requirements
	return p, nil
}

func (s *PostgresStore) UpsertEndpointTLSPosture(ctx context.Context, p *EndpointTLSPosture) error {
	requirements := p.Requirements
	if len(requirements) == 0 {
		requirements = []byte("[]")
	}
	observed := p.ObservedAt
	if observed.IsZero() {
		observed = time.Now()
	}

	return s.pool.QueryRow(ctx, `
		INSERT INTO public.endpoint_tls_posture
			(host, port, certificate_id, scan_id, tls_version, cipher_suite, key_exchange_group,
			 hybrid_key_exchange, offered_hybrid, supports_tls13, alpn,
			 verdict, summary, requirements, observed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15)
		ON CONFLICT (host, port) DO UPDATE SET
			certificate_id = excluded.certificate_id,
			scan_id = excluded.scan_id,
			tls_version = excluded.tls_version,
			cipher_suite = excluded.cipher_suite,
			key_exchange_group = excluded.key_exchange_group,
			hybrid_key_exchange = excluded.hybrid_key_exchange,
			offered_hybrid = excluded.offered_hybrid,
			supports_tls13 = excluded.supports_tls13,
			alpn = excluded.alpn,
			verdict = excluded.verdict,
			summary = excluded.summary,
			requirements = excluded.requirements,
			observed_at = excluded.observed_at
		RETURNING id`,
		p.Host, p.Port, p.CertificateID, p.ScanID,
		nullIfEmpty(p.TLSVersion), nullIfEmpty(p.CipherSuite), nullIfEmpty(p.KeyExchangeGroup),
		p.HybridKeyExchange, p.OfferedHybrid, p.SupportsTLS13, nullIfEmpty(p.ALPN),
		nullIfEmpty(p.Verdict), nullIfEmpty(p.Summary), requirements, observed,
	).Scan(&p.ID)
}

func (s *PostgresStore) ListEndpointTLSPosture(ctx context.Context,
	filter EndpointTLSPostureFilter) ([]*EndpointTLSPosture, int64, error) {

	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if filter.Host != "" {
		add("host = $%d", filter.Host)
	}
	if filter.Verdict != "" {
		add("verdict = $%d", strings.ToUpper(filter.Verdict))
	}
	if filter.ExposedOnly {
		// The endpoints losing something today. Scoped to handshakes where a
		// hybrid group was actually offered, or the list would include
		// observations that say nothing about the server.
		where = append(where, "offered_hybrid AND NOT hybrid_key_exchange")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.endpoint_tls_posture WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit, offset := filter.Limit, filter.Offset
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, offset)
	rows, err := s.pool.Query(ctx, "SELECT "+endpointTLSPostureColumns+`
		FROM public.endpoint_tls_posture WHERE `+clause+fmt.Sprintf(`
		ORDER BY hybrid_key_exchange ASC, host ASC, port ASC
		LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*EndpointTLSPosture{}
	for rows.Next() {
		p, err := scanEndpointTLSPosture(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) CountTLSPostureByVerdict(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(verdict, 'UNKNOWN'), count(*)
		FROM public.endpoint_tls_posture
		GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var verdict string
		var count int64
		if err := rows.Scan(&verdict, &count); err != nil {
			return nil, err
		}
		out[verdict] = count
	}
	return out, rows.Err()
}

// ListCertificatesForAssessment returns what the posture sweep has left to do.
//
// "Never assessed, or assessed before the row last changed" rather than a fixed
// interval. A certificate's algorithms do not drift; they change when it is
// renewed, and re-reading the whole inventory on a timer would be work that
// finds nothing on every pass but the first.
func (s *PostgresStore) ListCertificatesForAssessment(ctx context.Context, limit int) ([]*Certificate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, "SELECT "+certificateColumns+`
		FROM public.certificates
		WHERE certificate_pem IS NOT NULL AND certificate_pem <> ''
		  AND (quantum_assessed_at IS NULL OR quantum_assessed_at < updated_at)
		ORDER BY updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateCertificatePosture(ctx context.Context, id string,
	update CertificatePostureUpdate) error {

	requirements := update.Requirements
	if len(requirements) == 0 {
		requirements = []byte("[]")
	}
	assessedAt := update.AssessedAt
	if assessedAt.IsZero() {
		assessedAt = time.Now()
	}

	// updated_at is deliberately not touched. The sweep claims work by
	// comparing quantum_assessed_at against it, and bumping updated_at here
	// would make every assessment immediately due for another one.
	_, err := s.pool.Exec(ctx, `
		UPDATE public.certificates
		SET posture_verdict = $2,
		    posture_summary = $3,
		    posture_requirements = $4::jsonb,
		    quantum_readiness_score = $5,
		    signature_algorithm = coalesce(nullif($6, ''), signature_algorithm),
		    public_key_algorithm = coalesce(nullif($7, ''), public_key_algorithm),
		    quantum_assessed_at = $8
		WHERE id = $1`,
		id, nullIfEmpty(update.Verdict), nullIfEmpty(update.Summary), requirements,
		update.Score, update.SignatureAlgorithm, update.PublicKeyAlgorithm, assessedAt)
	return err
}

// UpdateCertificateMetadata writes only the fields an operator owns.
//
// Narrow on purpose. Everything else on the row is a fact about the certificate
// itself — serial, fingerprint, expiry, renewal state — and a full-object write
// driven by a form is how a stale copy in a browser tab overwrites what a
// renewal recorded thirty seconds ago. Each field is written only when the
// caller supplied one, so a form that edits the team does not blank the
// environment.
func (s *PostgresStore) UpdateCertificateMetadata(
	ctx context.Context, id string, update CertificateMetadataUpdate,
) (*Certificate, error) {
	var tagsJSON []byte
	if update.Tags != nil {
		tagsJSON, _ = json.Marshal(*update.Tags)
	}

	query := `
		UPDATE public.certificates SET
			environment = COALESCE($2, environment),
			team        = COALESCE($3, team),
			tags        = COALESCE($4::jsonb, tags),
			metadata    = COALESCE($5::jsonb, metadata),
			updated_at  = now()
		WHERE id = $1
		RETURNING ` + certificateColumns

	var environment, team *string
	if update.Environment != nil {
		environment = update.Environment
	}
	if update.Team != nil {
		team = update.Team
	}

	row := s.pool.QueryRow(ctx, query, id, environment, team,
		nullableBytes(tagsJSON), nullableMetadata(update.Metadata))
	return scanCertificate(row)
}

// nullableBytes keeps an unsupplied jsonb parameter NULL so COALESCE preserves
// the stored value, rather than sending an empty byte slice PostgreSQL would
// reject as invalid json.
func nullableBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// ── Custom metadata fields ─────────────────────────────────

const metadataFieldColumns = `id, key, label, field_type,
		coalesce(options, '[]'::jsonb), display, coalesce(help_text, ''),
		is_required, sort_order, is_archived, created_by, created_at, updated_at`

func scanMetadataField(row pgx.Row) (*MetadataField, error) {
	f := &MetadataField{}
	var optionsJSON []byte
	err := row.Scan(&f.ID, &f.Key, &f.Label, &f.FieldType, &optionsJSON, &f.Display,
		&f.HelpText, &f.IsRequired, &f.SortOrder, &f.IsArchived,
		&f.CreatedBy, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		return nil, err
	}
	f.Options = []MetadataOption{}
	if len(optionsJSON) > 0 {
		_ = json.Unmarshal(optionsJSON, &f.Options)
	}
	return f, nil
}

func (s *PostgresStore) ListMetadataFields(ctx context.Context, includeArchived bool) ([]*MetadataField, error) {
	query := `SELECT ` + metadataFieldColumns + ` FROM public.metadata_fields`
	if !includeArchived {
		query += ` WHERE is_archived = false`
	}
	query += ` ORDER BY sort_order, label`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fields := []*MetadataField{}
	for rows.Next() {
		f, err := scanMetadataField(rows)
		if err != nil {
			return nil, err
		}
		fields = append(fields, f)
	}
	return fields, rows.Err()
}

func (s *PostgresStore) GetMetadataField(ctx context.Context, id string) (*MetadataField, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+metadataFieldColumns+` FROM public.metadata_fields WHERE id = $1`, id)
	return scanMetadataField(row)
}

func (s *PostgresStore) CreateMetadataField(ctx context.Context, field *MetadataField) error {
	optionsJSON, _ := json.Marshal(field.Options)
	if len(optionsJSON) == 0 {
		optionsJSON = []byte("[]")
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.metadata_fields (
			key, label, field_type, options, display, help_text,
			is_required, sort_order, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`,
		field.Key, field.Label, field.FieldType, optionsJSON, field.Display,
		field.HelpText, field.IsRequired, field.SortOrder, field.CreatedBy,
	).Scan(&field.ID, &field.CreatedAt, &field.UpdatedAt)
}

// UpdateMetadataField changes everything except the key.
//
// The key is what certificates store their values under, so renaming it would
// orphan every value already recorded. Labels, options, help text and ordering
// are all free to change precisely because none of them are the identity.
func (s *PostgresStore) UpdateMetadataField(ctx context.Context, field *MetadataField) error {
	optionsJSON, _ := json.Marshal(field.Options)
	if len(optionsJSON) == 0 {
		optionsJSON = []byte("[]")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE public.metadata_fields SET
			label = $2, field_type = $3, options = $4, display = $5,
			help_text = $6, is_required = $7, sort_order = $8,
			is_archived = $9, updated_at = now()
		WHERE id = $1`,
		field.ID, field.Label, field.FieldType, optionsJSON, field.Display,
		field.HelpText, field.IsRequired, field.SortOrder, field.IsArchived)
	return err
}

func (s *PostgresStore) ArchiveMetadataField(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE public.metadata_fields SET is_archived = true, updated_at = now() WHERE id = $1`, id)
	return err
}
