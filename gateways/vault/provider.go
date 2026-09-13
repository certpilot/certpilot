// Package vault implements a CertificateProviderService gateway for the
// HashiCorp Vault PKI secrets engine — the private CA most organisations
// running their own PKI already have.
//
// The gateway runs as its own process and speaks only gRPC to the CertPilot
// core. It holds no database and no long-lived state beyond the Vault tokens
// it is currently keeping alive: every request carries the CA account
// configuration it needs, which the core stores encrypted and decrypts only to
// populate the call.
//
// Two things make a Vault gateway different from an ACME one, and both shape
// this package:
//
// Vault is a CA that answers questions about itself. It will name its issuers,
// their certificates and their expiry dates — so GetCAInfo is real here, and a
// PKI team can have the CA that signs everything they own appear in the same
// inventory as the certificates it signed.
//
// Vault refuses to sign past its issuer's expiry. Not truncates: refuses. The
// day an issuing CA comes within one certificate lifetime of expiring, every
// renewal through it starts failing at once, with a message about notAfter that
// says nothing about the cause. This gateway translates that message, and says
// it at configuration time rather than waiting for the outage.
package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Version identifies this gateway in the Vault User-Agent and in capabilities.
const Version = "1.0.0"

// Provider implements providerv1.CertificateProviderServiceServer for Vault.
type Provider struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	defaultAddress   string
	defaultNamespace string
	startedAt        time.Time

	transports *transports
	tokens     *tokenCache
}

// Options configures the gateway process.
type Options struct {
	// DefaultAddress is used by CA accounts that do not name a Vault, and is
	// the only address HealthCheck can probe — the health RPC carries no
	// configuration, so without this the gateway can only report on itself.
	DefaultAddress string
	// DefaultNamespace is the Vault Enterprise namespace to assume.
	DefaultNamespace string
}

// NewProvider creates a Vault gateway provider.
func NewProvider(opts Options) *Provider {
	return &Provider{
		defaultAddress:   strings.TrimRight(strings.TrimSpace(opts.DefaultAddress), "/"),
		defaultNamespace: strings.TrimSpace(opts.DefaultNamespace),
		startedAt:        time.Now(),
		transports:       newTransports(),
		tokens:           newTokenCache(),
	}
}

// config parses and validates the per-account configuration.
//
// Validation errors are refused here rather than sent to Vault, because a
// configuration this gateway cannot understand produces a Vault error about
// something else entirely.
func (p *Provider) config(raw string) (*Config, error) {
	cfg, err := ParseConfig(raw, p.defaultAddress, p.defaultNamespace)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if errs, _ := cfg.Validate(); len(errs) > 0 {
		return nil, status.Error(codes.InvalidArgument, strings.Join(errs, "; "))
	}
	return cfg, nil
}

// ── Issue ────────────────────────────────────────────────

// IssueCertificate obtains a certificate from Vault.
//
// With a CSR it signs; without one it asks Vault to generate the key as well.
// The first is preferred everywhere it is possible, and the difference is
// visible in the response: a signed CSR comes back with no private key,
// because there was never one to return.
func (p *Provider) IssueCertificate(
	ctx context.Context, req *providerv1.IssueCertificateRequest,
) (*providerv1.IssueCertificateResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, cfg)
	defer cancel()

	result, generated, err := p.obtain(ctx, cfg, req.CsrPem, req.Domains, req.ValidityDays)
	if err != nil {
		return nil, err
	}

	info, err := describeIssued(result, generated)
	if err != nil {
		return nil, err
	}
	slog.Info("issued a certificate from Vault",
		"mount", cfg.Mount, "role", cfg.Role, "common_name", info.CommonName,
		"serial", result.SerialNumber, "expires", info.NotAfter.AsTime().Format(time.RFC3339),
		"key", keyOrigin(generated))

	return &providerv1.IssueCertificateResponse{
		Certificate:           info,
		ProviderCertificateId: result.SerialNumber,
	}, nil
}

// RenewCertificate obtains a replacement.
//
// Vault has no renewal operation — a renewal is an issuance, and treating it
// as one is what the CA itself does. The provider certificate ID changes
// because the serial changes; nothing about the old certificate is implied to
// have stopped being valid, and revoking it is a separate decision.
func (p *Provider) RenewCertificate(
	ctx context.Context, req *providerv1.RenewCertificateRequest,
) (*providerv1.RenewCertificateResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, cfg)
	defer cancel()

	domains := req.Domains
	if len(domains) == 0 && len(req.CurrentCertificatePem) > 0 {
		// A renewal that names no domains renews what is there, rather than
		// issuing for whatever the role's defaults happen to produce.
		if current, err := x509util.ParseCertificatePEM(req.CurrentCertificatePem); err == nil {
			domains = namesOf(current)
		}
	}

	result, generated, err := p.obtain(ctx, cfg, req.CsrPem, domains, 0)
	if err != nil {
		return nil, err
	}
	info, err := describeIssued(result, generated)
	if err != nil {
		return nil, err
	}
	slog.Info("renewed a certificate from Vault",
		"mount", cfg.Mount, "role", cfg.Role, "common_name", info.CommonName,
		"previous", req.ProviderCertificateId, "serial", result.SerialNumber,
		"key", keyOrigin(generated))

	return &providerv1.RenewCertificateResponse{
		Certificate:           info,
		ProviderCertificateId: result.SerialNumber,
	}, nil
}

// obtain performs the issuance, choosing sign or issue and reporting which.
func (p *Provider) obtain(
	ctx context.Context, cfg *Config, csrPEM []byte, domains []string, validityDays int32,
) (result *issuedCert, generated bool, err error) {
	domains = normalizeDomains(domains)
	ttl := cfg.TTL
	if validityDays > 0 {
		ttl = fmt.Sprintf("%dh", int(validityDays)*24)
	}

	var warnings []string
	if len(csrPEM) > 0 {
		csrNames, err := namesInCSR(csrPEM)
		if err != nil {
			return nil, false, status.Error(codes.InvalidArgument, err.Error())
		}
		if len(domains) == 0 {
			domains = csrNames
		} else if missing := notIn(domains, csrNames); len(missing) > 0 {
			// A Vault role uses the CSR's own names by default
			// (use_csr_common_name and use_csr_sans), so alt_names would be
			// ignored and the certificate would come back covering less than
			// was asked for — while CertPilot recorded it as covering the
			// names in the request. Refusing is the only outcome that does not
			// leave a wrong record behind.
			return nil, false, status.Errorf(codes.InvalidArgument,
				"the request asks for %s, and the CSR does not contain %s. A Vault role uses the names in the CSR (use_csr_common_name and use_csr_sans are on by default), so those names would be silently dropped and the certificate would cover less than was asked for",
				strings.Join(domains, ", "), strings.Join(missing, ", "))
		}
		result, warnings, err = p.sign(ctx, cfg, string(csrPEM), domains, ttl)
		if err != nil {
			return nil, false, p.explainIssuance(ctx, cfg, err)
		}
	} else {
		if len(domains) == 0 {
			return nil, false, status.Error(codes.InvalidArgument,
				"a certificate needs at least one domain, or a CSR that names one")
		}
		result, warnings, err = p.issue(ctx, cfg, domains, ttl)
		if err != nil {
			return nil, false, p.explainIssuance(ctx, cfg, err)
		}
		generated = result.PrivateKey != ""
	}

	reportWarnings(cfg, warnings)
	return result, generated, nil
}

// reportWarnings surfaces what Vault said it did differently.
//
// The one that matters is TTL capping: ask for ninety days from a role whose
// max_ttl is thirty and Vault issues thirty and mentions it here. The
// certificate is valid, the renewal schedule that was planned around ninety
// days is not, and nothing else in the system ever says so.
func reportWarnings(cfg *Config, warnings []string) {
	for _, warning := range warnings {
		if benignWarning(warning) {
			continue
		}
		slog.Warn("Vault altered this request",
			"mount", cfg.Mount, "role", cfg.Role, "warning", warning)
	}
}

// benignWarning filters the two Vault emits on every single signature.
//
// A role with use_csr_common_name and use_csr_sans set — the default — warns
// that the common_name and alt_names in the request were not needed, because
// the CSR carries them. Sending them anyway is deliberate: a role with those
// settings turned off needs them, and there is no way to know which kind of
// role this is without a read the token may not have. Logging both on every
// issuance would teach an operator to skim past the line that says the
// validity was capped.
func benignWarning(warning string) bool {
	lowered := strings.ToLower(warning)
	return strings.Contains(lowered, "use_csr_common_name") ||
		strings.Contains(lowered, "use_csr_sans")
}

// describeIssued parses what Vault returned rather than trusting it.
func describeIssued(result *issuedCert, generated bool) (*commonv1.CertificateInfo, error) {
	if strings.TrimSpace(result.Certificate) == "" {
		return nil, status.Error(codes.Internal, "Vault accepted the request and returned no certificate")
	}
	info, err := x509util.ParseCertificatePEM([]byte(result.Certificate))
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Vault returned something that is not a certificate: %v", err)
	}

	out := &commonv1.CertificateInfo{
		CommonName:        info.CommonName,
		Sans:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDn:          info.IssuerDN,
		SubjectDn:         info.SubjectDN,
		NotBefore:         timestamppb.New(info.NotBefore),
		NotAfter:          timestamppb.New(info.NotAfter),
		KeyType:           info.KeyType,
		KeySize:           int32(info.KeySize),
		FingerprintSha256: info.FingerprintSHA256,
		CertificatePem:    []byte(result.Certificate),
		ChainPem:          []byte(chainPEM(result)),
	}
	// Only when this gateway caused the key to exist. On the signing path
	// there is no key to return, and returning one would mean Vault had
	// generated a key for a CSR — which would be a different, worse bug than
	// a missing field.
	if generated {
		out.PrivateKeyPem = []byte(result.PrivateKey)
	}
	return out, nil
}

func keyOrigin(generated bool) string {
	if generated {
		return "generated by Vault"
	}
	return "held by the requester; never seen here"
}

// ── Revoke ───────────────────────────────────────────────

// RevokeCertificate revokes through Vault, which genuinely revokes: the serial
// goes on the mount's CRL and, where the mount is configured for it, is
// answered by its OCSP responder.
func (p *Provider) RevokeCertificate(
	ctx context.Context, req *providerv1.RevokeCertificateRequest,
) (*providerv1.RevokeCertificateResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, cfg)
	defer cancel()

	revokedAt, err := p.revoke(ctx, cfg, string(req.CertificatePem), req.ProviderCertificateId)
	if err != nil {
		if ve, ok := asAPIError(err); ok && strings.Contains(ve.message(), "already revoked") {
			// Revoking twice is not a failure. Reporting it as one turns a
			// retry into an incident.
			return &providerv1.RevokeCertificateResponse{
				Success: true,
				Message: "already revoked in Vault",
			}, nil
		}
		return nil, p.explainRevocation(ctx, cfg, err, len(req.CertificatePem) > 0)
	}

	slog.Info("revoked a certificate in Vault",
		"mount", cfg.Mount, "serial", req.ProviderCertificateId, "reason", req.Reason)
	message := fmt.Sprintf("revoked in Vault mount %s", cfg.Mount)
	if revokedAt > 0 {
		message = fmt.Sprintf("revoked in Vault mount %s at %s",
			cfg.Mount, time.Unix(revokedAt, 0).UTC().Format(time.RFC3339))
	}
	// Vault's revoke endpoint has no reason code. Saying so is better than
	// letting an operator believe RFC 5280 reason 1 reached the CRL.
	if req.Reason != 0 {
		message += fmt.Sprintf(" (Vault does not record a revocation reason; reason %d was not sent)", req.Reason)
	}
	return &providerv1.RevokeCertificateResponse{Success: true, Message: message}, nil
}

// ── Status ───────────────────────────────────────────────

// GetCertificateStatus asks Vault what became of a certificate it issued.
func (p *Provider) GetCertificateStatus(
	ctx context.Context, req *providerv1.GetCertificateStatusRequest,
) (*providerv1.GetCertificateStatusResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, cfg)
	defer cancel()

	serial := req.ProviderCertificateId
	if serial == "" && len(req.CertificatePem) > 0 {
		info, err := x509util.ParseCertificatePEM(req.CertificatePem)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "certificate_pem is not a certificate: %v", err)
		}
		serial = info.SerialNumber
	}
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument,
			"checking status needs the provider certificate ID or the certificate itself")
	}

	stored, err := p.readCert(ctx, cfg, serial)
	if err != nil {
		if ve, ok := asAPIError(err); ok && ve.Status == http.StatusNotFound {
			// Absence is not evidence of revocation, and must never be
			// reported as any kind of certainty. A role with no_store set
			// never had a copy; so does a certificate from another mount.
			return &providerv1.GetCertificateStatusResponse{
				Status: providerv1.CertStatus_CERT_STATUS_UNKNOWN,
				Message: fmt.Sprintf(
					"Vault mount %s has no record of serial %s. Either it was issued elsewhere, or the role has no_store set — in which case Vault keeps no copy and can neither report on it nor revoke it",
					cfg.Mount, vaultSerial(serial)),
			}, nil
		}
		return nil, p.translate(err)
	}

	certPEM := stored.Certificate
	if strings.TrimSpace(certPEM) == "" {
		certPEM = string(req.CertificatePem)
	}
	response := &providerv1.GetCertificateStatusResponse{}
	if info, err := x509util.ParseCertificatePEM([]byte(certPEM)); err == nil {
		response.ExpiresAt = timestamppb.New(info.NotAfter)
	}

	switch {
	case stored.RevocationTime > 0:
		response.Status = providerv1.CertStatus_CERT_STATUS_REVOKED
		response.Message = fmt.Sprintf("revoked in Vault at %s",
			time.Unix(stored.RevocationTime, 0).UTC().Format(time.RFC3339))
	case response.ExpiresAt != nil && response.ExpiresAt.AsTime().Before(time.Now()):
		response.Status = providerv1.CertStatus_CERT_STATUS_EXPIRED
		response.Message = "expired"
	default:
		response.Status = providerv1.CertStatus_CERT_STATUS_VALID
		response.Message = fmt.Sprintf("valid, and not revoked in Vault mount %s", cfg.Mount)
	}
	// No renewal window: Vault publishes no ACME Renewal Information, and
	// inventing one would give the core a schedule the CA never agreed to.
	return response, nil
}

// ── CA info ──────────────────────────────────────────────

// GetCAInfo reports the issuers of the configured mount.
//
// This is the RPC that earns the gateway its place for a central PKI team. The
// certificates in the inventory are the ones that get renewed automatically;
// the CA that signs them is the one that takes everything down when it
// expires, and until now nothing in CertPilot could see it.
func (p *Provider) GetCAInfo(
	ctx context.Context, req *providerv1.GetCAInfoRequest,
) (*providerv1.GetCAInfoResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := deadline(ctx, cfg)
	defer cancel()

	issuers, err := p.collectIssuers(ctx, cfg)
	if err != nil {
		return nil, p.translate(err)
	}

	urls := p.readURLs(ctx, cfg)
	chain := make([]*commonv1.CAAuthorityInfo, 0, len(issuers))
	for _, issuer := range issuers {
		if authority := describeIssuer(cfg, issuer, urls); authority != nil {
			chain = append(chain, authority)
		}
	}
	sortAuthorities(chain)
	return &providerv1.GetCAInfoResponse{CaChain: chain}, nil
}

// collectIssuers reads every issuer, or the single CA of a mount that predates
// issuers or a token that cannot list them.
func (p *Provider) collectIssuers(ctx context.Context, cfg *Config) ([]*issuerData, error) {
	refs, err := p.listIssuers(ctx, cfg)
	if err != nil {
		ve, ok := asAPIError(err)
		if !ok || (ve.Status != http.StatusForbidden && ve.Status != http.StatusNotFound) {
			return nil, err
		}
		single, fallbackErr := p.readDefaultCA(ctx, cfg)
		if fallbackErr != nil {
			return nil, err
		}
		return []*issuerData{single}, nil
	}

	issuers := make([]*issuerData, 0, len(refs))
	for _, ref := range refs {
		issuer, err := p.readIssuer(ctx, cfg, ref)
		if err != nil {
			// One unreadable issuer does not invalidate the rest. Returning
			// the ones that could be read is more useful than returning
			// nothing, and the CA that cannot be read is not the one silently
			// missing from the inventory — it was never listed.
			slog.Warn("could not read a Vault issuer",
				"mount", cfg.Mount, "issuer", ref, "error", err)
			continue
		}
		issuers = append(issuers, issuer)
	}
	if len(issuers) == 0 {
		return nil, fmt.Errorf("mount %s lists issuers, and none of them could be read", cfg.Mount)
	}
	return issuers, nil
}

// describeIssuer turns a Vault issuer into a CA authority the core can track.
func describeIssuer(cfg *Config, issuer *issuerData, urls *mountURLs) *commonv1.CAAuthorityInfo {
	info, err := x509util.ParseCertificatePEM([]byte(issuer.Certificate))
	if err != nil {
		slog.Warn("a Vault issuer is not a parseable certificate",
			"mount", cfg.Mount, "issuer", issuer.IssuerID, "error", err)
		return nil
	}

	name := strings.TrimSpace(issuer.IssuerName)
	if name == "" {
		name = info.CommonName
	}
	if name == "" {
		name = issuer.IssuerID
	}

	authority := &commonv1.CAAuthorityInfo{
		Id:                issuer.IssuerID,
		Name:              fmt.Sprintf("%s/%s", cfg.Mount, name),
		SubjectDn:         info.SubjectDN,
		IssuerDn:          info.IssuerDN,
		NotBefore:         timestamppb.New(info.NotBefore),
		NotAfter:          timestamppb.New(info.NotAfter),
		DaysRemaining:     int32(info.DaysRemaining),
		FingerprintSha256: info.FingerprintSHA256,
		CaType:            caTypeOf(info),
		CertificatePem:    []byte(issuer.Certificate),
	}
	// The certificate's own AIA extensions first, because those are what a
	// client actually follows. Then the issuer's own URLs, then the mount's.
	// The fallbacks matter more than they look: the CA created at the same
	// time as the mount was signed before any of this was configured, so its
	// certificate carries no CRL at all — and it is the one whose revocation
	// status a monitor most wants to check.
	authority.CrlUrl = firstOf(info.CRLURLs, issuer.CRLDistPoints, urls.CRLDistributionPoints)
	authority.OcspUrl = firstOf(info.OCSPURLs, issuer.OCSPServers, urls.OCSPServers)
	return authority
}

// firstOf returns the first value present, in order of how much it is to be
// trusted.
func firstOf(sources ...[]string) string {
	for _, source := range sources {
		for _, value := range source {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
	}
	return ""
}

// caTypeOf classifies an issuer, falling back to ISSUING for a certificate
// that is signing things without saying it is a CA — which is a broken mount,
// but a broken mount whose expiry still matters.
func caTypeOf(info *x509util.CertInfo) string {
	if info.IsCA {
		if info.IssuerDN == info.SubjectDN {
			return "ROOT"
		}
		return "INTERMEDIATE"
	}
	return "ISSUING"
}

// sortAuthorities puts roots first, then intermediates, then anything else,
// so a chain reads from the top down however Vault happened to list it.
func sortAuthorities(chain []*commonv1.CAAuthorityInfo) {
	rank := map[string]int{"ROOT": 0, "INTERMEDIATE": 1, "ISSUING": 2}
	sort.SliceStable(chain, func(i, j int) bool {
		left, right := rank[chain[i].CaType], rank[chain[j].CaType]
		if left != right {
			return left < right
		}
		return chain[i].Name < chain[j].Name
	})
}

// ── Metadata ─────────────────────────────────────────────

// GetCapabilities returns what this gateway supports.
func (p *Provider) GetCapabilities(
	ctx context.Context, req *providerv1.GetCapabilitiesRequest,
) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:        "vault",
			ProviderVersion:     Version,
			ProviderType:        "vault",
			SupportsWildcard:    true,
			SupportsMultiDomain: true,
			SupportedKeyTypes:   []string{"RSA", "ECDSA", "Ed25519"},
			// Empty, and not an oversight: Vault performs no domain control
			// validation. What may be issued is decided by the role's
			// allowed_domains, before the request reaches a challenge.
			SupportedChallenges: []string{},
			ValidationLevels:    []string{},
			SupportsRevocation:  true,
			SupportsCaInfo:      true,
			Description:         "HashiCorp Vault PKI secrets engine. Issues from a mount and role, revokes to the mount's CRL, and reports the mount's issuers so the CA that signs your estate is monitored alongside it",
		},
	}, nil
}

// HealthCheck reports on the gateway, and on Vault when it has an address to
// ask.
//
// The RPC carries no configuration, so per-account reachability cannot be
// checked here; that is what ValidateConfig is for. When the process was given
// a default address, this reaches sys/health, which needs no token — so an
// expired credential and an unreachable Vault stay distinguishable.
func (p *Provider) HealthCheck(
	ctx context.Context, req *providerv1.HealthCheckRequest,
) (*providerv1.HealthCheckResponse, error) {
	started := time.Now()
	if p.defaultAddress == "" {
		return &providerv1.HealthCheckResponse{
			Status: commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			Message: fmt.Sprintf(
				"vault gateway running since %s; no default address configured, so each CA account's Vault is checked when its configuration is validated",
				p.startedAt.Format(time.RFC3339)),
			CheckedAt: timestamppb.Now(),
		}, nil
	}

	cfg := &Config{Address: p.defaultAddress, Namespace: p.defaultNamespace}
	probeCtx, cancel := deadline(ctx, cfg)
	defer cancel()

	state, err := p.health(probeCtx, cfg)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return &providerv1.HealthCheckResponse{
			Status:    commonv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
			Message:   fmt.Sprintf("cannot reach Vault at %s: %v", p.defaultAddress, err),
			LatencyMs: latency,
			CheckedAt: timestamppb.Now(),
		}, nil
	}

	verdict, message := describeHealth(state, p.defaultAddress)
	return &providerv1.HealthCheckResponse{
		Status:    verdict,
		Message:   message,
		LatencyMs: latency,
		CheckedAt: timestamppb.Now(),
	}, nil
}

// describeHealth turns Vault's state into a verdict.
//
// A sealed Vault is unhealthy: it is reachable, it is answering, and it cannot
// issue anything. A standby is healthy — it forwards to the active node, which
// is what standbys are for.
func describeHealth(state *healthData, address string) (commonv1.HealthStatus, string) {
	switch {
	case !state.Initialized:
		return commonv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
			fmt.Sprintf("Vault at %s is not initialized", address)
	case state.Sealed:
		return commonv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
			fmt.Sprintf("Vault at %s is sealed; nothing can be issued or revoked until it is unsealed", address)
	case state.PerformanceStandby:
		return commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			fmt.Sprintf("Vault at %s is a performance standby and forwards writes to the active node", address)
	case state.Standby:
		return commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			fmt.Sprintf("Vault at %s is a standby and forwards to the active node", address)
	default:
		return commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			strings.TrimSpace(fmt.Sprintf("Vault %s at %s is unsealed and active", state.Version, address))
	}
}

// namesOf lists every name a certificate covers.
func namesOf(info *x509util.CertInfo) []string {
	names := []string{}
	if info.CommonName != "" {
		names = append(names, info.CommonName)
	}
	return normalizeDomains(append(names, info.SANs...))
}

// namesInCSR lists the names a CSR requests.
func namesInCSR(csrPEM []byte) ([]string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("csr_pem is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr_pem is not a certificate request: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		// An unsigned CSR proves nothing about who holds the key it names.
		// Vault checks this too; catching it here says so in words.
		return nil, fmt.Errorf("the CSR's signature does not verify against its own public key: %v", err)
	}
	names := append([]string{}, csr.DNSNames...)
	if csr.Subject.CommonName != "" {
		names = append([]string{csr.Subject.CommonName}, names...)
	}
	return normalizeDomains(names), nil
}

// normalizeDomains lowercases, trims the root label, and removes duplicates
// while keeping the first occurrence — which is the common name.
func normalizeDomains(domains []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, domain)
	}
	return out
}

// notIn reports which of wanted is absent from have.
func notIn(wanted, have []string) []string {
	present := make(map[string]bool, len(have))
	for _, name := range have {
		present[strings.ToLower(name)] = true
	}
	var missing []string
	for _, name := range wanted {
		if !present[strings.ToLower(name)] {
			missing = append(missing, name)
		}
	}
	return missing
}
