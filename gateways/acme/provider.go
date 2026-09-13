// Package acme implements a CertificateProviderService gateway for RFC 8555
// ACME certificate authorities — Let's Encrypt, ZeroSSL, BuyPass, Google Trust
// Services, Smallstep, and anything else speaking the protocol.
//
// The gateway runs as its own process and speaks only gRPC to the CertPilot
// core. It holds no database: every request carries the CA account
// configuration it needs, which the core stores encrypted and decrypts only to
// populate the call.
package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	certcrypto "github.com/certpilot/certpilot-gateway-sdk/crypto"
	commonv1 "github.com/certpilot/certpilot-gateway-sdk/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"golang.org/x/crypto/acme"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Version identifies this gateway in the ACME User-Agent and in capabilities.
const Version = "1.0.0"

// Provider implements providerv1.CertificateProviderServiceServer for ACME.
type Provider struct {
	providerv1.UnimplementedCertificateProviderServiceServer

	defaultDirectory string
	http01Addr       string
	httpClient       *http.Client
	accounts         *accountStore
	ari              *ariClient
}

// Options configures the gateway process.
type Options struct {
	// DefaultDirectory is used when a CA account does not name one.
	DefaultDirectory string
	// StateDir persists ACME account keys across restarts. Strongly
	// recommended: without it, every restart registers a new ACME account.
	StateDir string
	// HTTP01Addr is the default bind address for the http-01 challenge
	// listener.
	HTTP01Addr string
}

// NewProvider creates a new ACME gateway provider.
func NewProvider(opts Options) *Provider {
	if opts.DefaultDirectory == "" {
		opts.DefaultDirectory = LetsEncryptProduction
	}
	if alias, ok := DirectoryAliases[strings.ToLower(opts.DefaultDirectory)]; ok {
		opts.DefaultDirectory = alias
	}
	if opts.HTTP01Addr == "" {
		opts.HTTP01Addr = ":80"
	}

	httpClient := &http.Client{Timeout: 60 * time.Second}

	return &Provider{
		defaultDirectory: opts.DefaultDirectory,
		http01Addr:       opts.HTTP01Addr,
		httpClient:       httpClient,
		accounts:         newAccountStore(opts.StateDir),
		ari:              newARIClient(httpClient),
	}
}

// IssueCertificate runs a complete ACME order and returns the issued
// certificate with its chain.
func (p *Provider) IssueCertificate(ctx context.Context, req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	domains, err := normalizeDomains(req.Domains, req.CsrPem)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// A caller-supplied CSR keeps the private key wherever it was generated —
	// ideally on the host that will serve the certificate, never here. When no
	// CSR is supplied the gateway generates a key, which means the key must
	// travel back over gRPC; that channel is mTLS-protected, but supplying a
	// CSR is still the better pattern.
	csrDER, privateKeyPEM, keyType, keySize, err := p.prepareCSR(req.CsrPem, req.KeyType, int(req.KeySize), domains)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	issued, err := p.obtainCertificate(ctx, cfg, csrDER, domains)
	if err != nil {
		return nil, status.Error(issuanceErrorCode(err), err.Error())
	}

	certInfo, err := buildCertificateInfo(issued, privateKeyPEM, keyType, keySize)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &providerv1.IssueCertificateResponse{
		Certificate: certInfo,
		// The ACME certificate URL is the stable handle for this issuance.
		ProviderCertificateId: issued.CertURL,
	}, nil
}

// RenewCertificate issues a replacement certificate.
//
// ACME has no distinct renewal operation: a renewal is a fresh order for the
// same identifiers. The important part is that the key is rotated by default,
// because reusing a key across renewals means a single key compromise is never
// resolved by renewing.
func (p *Provider) RenewCertificate(ctx context.Context, req *providerv1.RenewCertificateRequest) (*providerv1.RenewCertificateResponse, error) {
	domains := req.Domains

	// Fall back to the identifiers in the certificate being replaced, so the
	// core does not have to track them separately.
	if len(domains) == 0 && len(req.CurrentCertificatePem) > 0 {
		cert, err := parseCertificatePEM(req.CurrentCertificatePem)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument,
				fmt.Sprintf("no domains supplied and the current certificate could not be parsed: %v", err))
		}
		domains = certificateDomains(cert)
	}

	issueResp, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem:         req.CsrPem,
		Domains:        domains,
		KeyType:        req.KeyType,
		KeySize:        req.KeySize,
		ProviderConfig: req.ProviderConfig,
	})
	if err != nil {
		return nil, err
	}

	return &providerv1.RenewCertificateResponse{
		Certificate:           issueResp.Certificate,
		ProviderCertificateId: issueResp.ProviderCertificateId,
	}, nil
}

// RevokeCertificate revokes a certificate with the issuing CA.
func (p *Provider) RevokeCertificate(ctx context.Context, req *providerv1.RevokeCertificateRequest) (*providerv1.RevokeCertificateResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if len(req.CertificatePem) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"certificate_pem is required to revoke: ACME revocation identifies the certificate by its bytes")
	}

	cert, err := parseCertificatePEM(req.CertificatePem)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("certificate_pem is not a valid certificate: %v", err))
	}

	client, err := p.newClient(ctx, cfg)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	reason := acme.CRLReasonCode(req.Reason)

	// Revocation may be authorized by the account that issued the certificate
	// or by the certificate's own key. Only the account route is available
	// here, since the gateway does not retain subscriber keys.
	if err := client.RevokeCert(ctx, nil, cert.Raw, reason); err != nil {
		// An already-revoked certificate is the desired end state, so report
		// it as success rather than failing a cleanup workflow.
		if isAlreadyRevoked(err) {
			slog.Info("certificate was already revoked at the CA",
				"common_name", cert.Subject.CommonName, "serial", cert.SerialNumber.Text(16))
			return &providerv1.RevokeCertificateResponse{
				Success: true,
				Message: "certificate was already revoked",
			}, nil
		}
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("CA rejected the revocation: %v", describeACMEError(err)))
	}

	slog.Info("certificate revoked",
		"common_name", cert.Subject.CommonName,
		"serial", cert.SerialNumber.Text(16),
		"reason", reason,
	)

	return &providerv1.RevokeCertificateResponse{
		Success: true,
		Message: fmt.Sprintf("certificate %s revoked (reason %d)", cert.SerialNumber.Text(16), req.Reason),
	}, nil
}

// GetCertificateStatus reports validity and, when the CA supports RFC 9773,
// the renewal window it would like this certificate replaced in.
func (p *Provider) GetCertificateStatus(ctx context.Context, req *providerv1.GetCertificateStatusRequest) (*providerv1.GetCertificateStatusResponse, error) {
	if len(req.CertificatePem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate_pem is required to determine status")
	}

	cert, err := parseCertificatePEM(req.CertificatePem)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("certificate_pem is not a valid certificate: %v", err))
	}

	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp := &providerv1.GetCertificateStatusResponse{
		ExpiresAt: timestamppb.New(cert.NotAfter),
	}

	now := time.Now()
	switch {
	case now.After(cert.NotAfter):
		resp.Status = providerv1.CertStatus_CERT_STATUS_EXPIRED
		resp.Message = fmt.Sprintf("expired %s ago", now.Sub(cert.NotAfter).Round(time.Hour))
	case now.Before(cert.NotBefore):
		resp.Status = providerv1.CertStatus_CERT_STATUS_PENDING
		resp.Message = fmt.Sprintf("not valid until %s", cert.NotBefore.Format(time.RFC3339))
	default:
		resp.Status = providerv1.CertStatus_CERT_STATUS_VALID
		resp.Message = fmt.Sprintf("%d days remaining", int(time.Until(cert.NotAfter).Hours()/24))
	}

	// Renewal advice is a bonus, never a reason to fail the status call.
	info, err := p.ari.Fetch(ctx, cfg.DirectoryURL, cert)
	switch {
	case err == nil:
		resp.RenewalWindow = &providerv1.RenewalWindow{
			Start:             timestamppb.New(info.Start),
			End:               timestamppb.New(info.End),
			ExplanationUrl:    info.ExplanationURL,
			RenewNow:          info.RenewNow(),
			RetryAfterSeconds: int64(info.RetryAfter.Seconds()),
		}
		if info.RenewNow() {
			resp.Message += " — the CA suggests renewing now (RFC 9773)"
		}
	case errors.Is(err, errARIUnsupported):
		slog.Debug("CA does not publish renewal information", "directory", cfg.DirectoryURL)
	default:
		slog.Warn("failed to fetch renewal information", "error", err, "directory", cfg.DirectoryURL)
	}

	return resp, nil
}

// GetCAInfo returns the issuing chain the CA is currently using.
func (p *Provider) GetCAInfo(ctx context.Context, req *providerv1.GetCAInfoRequest) (*providerv1.GetCAInfoResponse, error) {
	cfg, err := p.config(req.ProviderConfig)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	client := &acme.Client{DirectoryURL: cfg.DirectoryURL, HTTPClient: p.httpClient}
	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable,
			fmt.Sprintf("failed to query ACME directory %s: %v", cfg.DirectoryURL, err))
	}

	// ACME exposes no endpoint listing issuer certificates; they arrive with
	// each issuance. What the directory does tell us is who the CA claims to
	// be, which is enough to register the account meaningfully.
	name := dir.Website
	if name == "" {
		name = cfg.DirectoryURL
	}

	return &providerv1.GetCAInfoResponse{
		CaChain: []*commonv1.CAAuthorityInfo{{
			Name:      name,
			SubjectDn: cfg.DirectoryURL,
			CaType:    "ISSUING",
		}},
	}, nil
}

// GetCapabilities reports what this gateway supports.
func (p *Provider) GetCapabilities(context.Context, *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:    "acme",
			ProviderVersion: Version,
			ProviderType:    "acme",
			// Wildcards work, but only over dns-01.
			SupportsWildcard:    true,
			SupportsMultiDomain: true,
			SupportedKeyTypes:   []string{"RSA", "ECDSA"},
			SupportedChallenges: []string{"dns-01", "http-01"},
			ValidationLevels:    []string{"DV"},
			SupportsRevocation:  true,
			SupportsCaInfo:      true,
			Description: "RFC 8555 ACME gateway with dns-01 (Cloudflare, webhook) and http-01 solvers, " +
				"External Account Binding, and RFC 9773 renewal information",
		},
	}, nil
}

// HealthCheck verifies the gateway can reach its ACME directory.
func (p *Provider) HealthCheck(ctx context.Context, _ *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	start := time.Now()
	client := &acme.Client{DirectoryURL: p.defaultDirectory, HTTPClient: p.httpClient}

	_, err := client.Discover(ctx)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &providerv1.HealthCheckResponse{
			Status:    commonv1.HealthStatus_HEALTH_STATUS_UNHEALTHY,
			Message:   fmt.Sprintf("ACME directory unreachable: %v", err),
			LatencyMs: latency,
			CheckedAt: timestamppb.Now(),
		}, nil
	}

	return &providerv1.HealthCheckResponse{
		Status:    commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Message:   "connected to " + p.defaultDirectory,
		LatencyMs: latency,
		CheckedAt: timestamppb.Now(),
	}, nil
}

// ValidateConfig checks a CA account configuration before it is saved, so
// mistakes surface at configuration time rather than at 3am during a renewal.
func (p *Provider) ValidateConfig(ctx context.Context, req *providerv1.ValidateConfigRequest) (*providerv1.ValidateConfigResponse, error) {
	cfg, err := ParseConfig(req.ConfigJson, p.defaultDirectory, p.http01Addr)
	if err != nil {
		return &providerv1.ValidateConfigResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	errs, warnings := cfg.Validate()

	// Only reach for the network once the configuration is structurally sound.
	if len(errs) == 0 {
		client := &acme.Client{DirectoryURL: cfg.DirectoryURL, HTTPClient: p.httpClient}
		if _, err := client.Discover(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("ACME directory %s is unreachable: %v", cfg.DirectoryURL, err))
		} else if endpoint, err := p.ari.renewalInfoEndpoint(ctx, cfg.DirectoryURL); err == nil && endpoint == "" {
			warnings = append(warnings,
				"this CA does not publish renewal information (RFC 9773); renewals will fall back to lead-time scheduling")
		}
	}

	if cfg.AccountKeyPEM == "" && p.accounts.dir == "" {
		warnings = append(warnings,
			"no account_key_pem and no gateway state directory: a new ACME account will be registered after each restart")
	}

	return &providerv1.ValidateConfigResponse{
		Valid:    len(errs) == 0,
		Errors:   errs,
		Warnings: warnings,
	}, nil
}

// config parses and validates a provider configuration payload.
func (p *Provider) config(raw string) (*Config, error) {
	cfg, err := ParseConfig(raw, p.defaultDirectory, p.http01Addr)
	if err != nil {
		return nil, err
	}
	if errs, _ := cfg.Validate(); len(errs) > 0 {
		return nil, fmt.Errorf("invalid CA account configuration: %s", strings.Join(errs, "; "))
	}
	return cfg, nil
}

// prepareCSR returns the DER CSR to submit, plus the generated private key when
// the gateway had to create one.
func (p *Provider) prepareCSR(csrPEM []byte, keyTypeStr string, keySize int, domains []string) (csrDER []byte, privateKeyPEM []byte, keyType string, resolvedSize int, err error) {
	if len(csrPEM) > 0 {
		block, _ := pem.Decode(csrPEM)
		if block == nil {
			return nil, nil, "", 0, fmt.Errorf("csr_pem does not contain a PEM block")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, nil, "", 0, fmt.Errorf("csr_pem is not a valid certificate request: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, nil, "", 0, fmt.Errorf("CSR signature is invalid: %w", err)
		}
		kt, ks := publicKeyDetails(csr.PublicKey)
		return block.Bytes, nil, kt, ks, nil
	}

	kt := certcrypto.KeyTypeECDSA
	if keyTypeStr != "" {
		parsed, err := certcrypto.ParseKeyType(keyTypeStr)
		if err != nil {
			return nil, nil, "", 0, err
		}
		kt = parsed
	}

	// ACME CAs do not accept Ed25519 subscriber keys today; failing here with
	// an explanation beats a confusing rejection from the CA.
	if kt == certcrypto.KeyTypeEd25519 {
		return nil, nil, "", 0, fmt.Errorf("publicly trusted ACME CAs do not currently issue for Ed25519 keys; use ECDSA or RSA")
	}

	if keySize <= 0 {
		if kt == certcrypto.KeyTypeRSA {
			keySize = 2048
		} else {
			keySize = 256
		}
	}

	key, err := certcrypto.GenerateKeyPair(kt, keySize)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("failed to generate key pair: %w", err)
	}

	generatedCSR, err := certcrypto.GenerateCSR(key, domains[0], domains)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("failed to generate CSR: %w", err)
	}

	block, _ := pem.Decode(generatedCSR)
	if block == nil {
		return nil, nil, "", 0, fmt.Errorf("generated CSR could not be decoded")
	}

	keyPEM, err := certcrypto.EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, nil, "", 0, fmt.Errorf("failed to encode private key: %w", err)
	}

	return block.Bytes, keyPEM, string(kt), keySize, nil
}

// buildCertificateInfo assembles the response from the issued certificate.
func buildCertificateInfo(issued *issuedCertificate, privateKeyPEM []byte, keyType string, keySize int) (*commonv1.CertificateInfo, error) {
	info, err := x509util.ParseCertificatePEM(issued.LeafPEM)
	if err != nil {
		return nil, fmt.Errorf("the CA returned a certificate that could not be parsed: %w", err)
	}

	// Prefer what the certificate actually says over what was requested.
	if info.KeyType != "" && info.KeyType != "Unknown" {
		keyType = info.KeyType
		keySize = info.KeySize
	}

	return &commonv1.CertificateInfo{
		CommonName:        info.CommonName,
		Sans:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDn:          info.IssuerDN,
		SubjectDn:         info.SubjectDN,
		NotBefore:         timestamppb.New(info.NotBefore),
		NotAfter:          timestamppb.New(info.NotAfter),
		KeyType:           keyType,
		KeySize:           int32(keySize),
		FingerprintSha256: info.FingerprintSHA256,
		CertificatePem:    issued.LeafPEM,
		ChainPem:          issued.ChainPEM,
		PrivateKeyPem:     privateKeyPEM,
	}, nil
}

// normalizeDomains validates and de-duplicates the identifier list, falling
// back to the CSR when the caller supplied none.
func normalizeDomains(domains []string, csrPEM []byte) ([]string, error) {
	if len(domains) == 0 && len(csrPEM) > 0 {
		block, _ := pem.Decode(csrPEM)
		if block != nil {
			if csr, err := x509.ParseCertificateRequest(block.Bytes); err == nil {
				domains = append(domains, csr.DNSNames...)
				if csr.Subject.CommonName != "" && !contains(domains, csr.Subject.CommonName) {
					domains = append([]string{csr.Subject.CommonName}, domains...)
				}
			}
		}
	}

	seen := make(map[string]bool, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || seen[d] {
			continue
		}
		if strings.ContainsAny(d, " \t\n/\\:") {
			return nil, fmt.Errorf("%q is not a valid domain name", d)
		}
		seen[d] = true
		out = append(out, d)
	}

	if len(out) == 0 {
		return nil, errors.New("at least one domain is required")
	}
	return out, nil
}

func parseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certificateDomains returns every identifier a certificate covers.
func certificateDomains(cert *x509.Certificate) []string {
	domains := make([]string, 0, len(cert.DNSNames)+1)
	if cert.Subject.CommonName != "" {
		domains = append(domains, cert.Subject.CommonName)
	}
	for _, name := range cert.DNSNames {
		if !contains(domains, name) {
			domains = append(domains, name)
		}
	}
	return domains
}

func publicKeyDetails(pub crypto.PublicKey) (keyType string, keySize int) {
	// Reuse the certificate inspection logic by wrapping the key in a stub
	// certificate, which keeps the type mapping in exactly one place.
	info := x509util.CertInfoFromX509(&x509.Certificate{PublicKey: pub})
	return info.KeyType, info.KeySize
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

// isAlreadyRevoked recognises the CA's way of saying the work is already done.
func isAlreadyRevoked(err error) bool {
	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) {
		if strings.Contains(acmeErr.ProblemType, "alreadyRevoked") {
			return true
		}
		if strings.Contains(strings.ToLower(acmeErr.Detail), "already revoked") {
			return true
		}
	}
	return false
}

// issuanceErrorCode maps failures onto gRPC codes so the core can tell a
// retryable problem from a permanent one.
func issuanceErrorCode(err error) codes.Code {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "rate limit"):
		return codes.ResourceExhausted
	case strings.Contains(msg, "unreachable"), strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return codes.Unavailable
	case strings.Contains(msg, "validation failed"), strings.Contains(msg, "no usable challenge"):
		return codes.FailedPrecondition
	default:
		return codes.Internal
	}
}
