package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Vault refusals this gateway recognises by their text.
//
// Matching on message text is brittle by nature, and the alternative is worse:
// these all arrive as a bare 400, and a caller that cannot tell them apart
// retries a permanent failure forever or gives up on a transient one.
const (
	refusalBeyondCAExpiry = "beyond the expiration of the ca certificate"
	refusalUnknownRole    = "unknown role"
	refusalNotAllowed     = "not allowed by this role"
)

// translate maps a Vault failure onto the gRPC code that decides what the core
// does next.
//
// The codes are not decoration. Unavailable is retried, InvalidArgument is
// not, and ResourceExhausted backs off — so a wrong code turns a typo into an
// infinite retry loop, or a sealed Vault into a permanently failed renewal.
func (p *Provider) translate(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok && status.Code(err) != codes.Unknown {
		return err
	}

	ve, ok := asAPIError(err)
	if !ok {
		// Not an answer from Vault at all: a dial failure, a TLS failure, or a
		// timeout. All are worth retrying, and none are the operator's
		// configuration being wrong.
		return status.Error(codes.Unavailable, err.Error())
	}

	switch ve.Status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return status.Error(codes.InvalidArgument, ve.Error())
	case http.StatusForbidden:
		return status.Error(codes.PermissionDenied, ve.Error())
	case http.StatusNotFound:
		return status.Error(codes.NotFound, ve.Error())
	case http.StatusTooManyRequests:
		return status.Error(codes.ResourceExhausted, ve.Error())
	case http.StatusPreconditionFailed:
		// Vault's eventual consistency: a standby that has not yet caught up
		// with a write made against the active node. Retrying is exactly the
		// right thing, and it usually succeeds immediately.
		return status.Error(codes.Unavailable, ve.Error()+" (a Vault standby that has not caught up; retrying should succeed)")
	case http.StatusServiceUnavailable:
		return status.Error(codes.Unavailable, ve.Error()+" (Vault is sealed or in standby without an active node)")
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout:
		return status.Error(codes.Unavailable, ve.Error())
	default:
		return status.Error(codes.Internal, ve.Error())
	}
}

// explainIssuance turns Vault's issuance refusals into the sentence that names
// the cause.
func (p *Provider) explainIssuance(ctx context.Context, cfg *Config, err error) error {
	ve, ok := asAPIError(err)
	if !ok {
		return p.translate(err)
	}
	message := ve.message()

	switch {
	case strings.Contains(message, refusalBeyondCAExpiry):
		return status.Error(codes.FailedPrecondition, p.explainCAExpiry(ctx, cfg, ve))

	case strings.Contains(message, refusalUnknownRole),
		ve.Status == http.StatusNotFound && strings.Contains(ve.Path, "/"+cfg.Mount+"/"):
		return status.Errorf(codes.InvalidArgument,
			"Vault has no role %q on mount %q (%s). Both are paths rather than names, and a mount that does not exist fails the same way as a role that does not",
			cfg.Role, cfg.Mount, strings.Join(ve.Messages, "; "))

	case strings.Contains(message, refusalNotAllowed):
		return status.Error(codes.InvalidArgument, p.explainNameRefusal(ctx, cfg, ve))

	default:
		return p.translate(err)
	}
}

// explainCAExpiry is the message this gateway exists to produce.
//
// A Vault issuer does not truncate a certificate that would outlive it — it
// refuses to sign at all. So the first day an issuing CA comes within one
// certificate lifetime of its own expiry, every renewal through it fails
// together, and Vault's message talks about a notAfter date rather than about
// the CA. Teams read it as a bad request and go looking at the role.
func (p *Provider) explainCAExpiry(ctx context.Context, cfg *Config, ve *apiError) string {
	base := fmt.Sprintf(
		"Vault refused to sign because the certificate would outlive the CA signing it (%s). This is not a problem with the request: the issuing CA is inside one certificate lifetime of its own expiry, so every renewal through mount %s is now failing, and will keep failing until that CA is rotated or the requested validity is shortened below what it has left",
		strings.Join(ve.Messages, "; "), cfg.Mount)

	// Naming the CA and the date makes the difference between a message that
	// explains and a message that has to be investigated. It needs a read the
	// token may not have, so its absence costs the detail and not the answer.
	issuers, err := p.collectIssuers(ctx, cfg)
	if err != nil || len(issuers) == 0 {
		return base
	}
	culprit := signingIssuer(cfg, issuers)
	if culprit == nil {
		return base
	}
	return fmt.Sprintf("%s. The issuer is %q, which expires on %s — %d days from now",
		base, culprit.CommonName, culprit.NotAfter.UTC().Format("2006-01-02"), culprit.DaysRemaining)
}

// signingIssuer picks the issuer the refusal is about: the pinned one when the
// account names it, and otherwise the one that expires first — which is the
// one whose expiry a refusal is most likely to be about, and the one worth
// naming either way.
func signingIssuer(cfg *Config, issuers []*issuerData) *x509util.CertInfo {
	var soonest *x509util.CertInfo
	for _, issuer := range issuers {
		info, err := x509util.ParseCertificatePEM([]byte(issuer.Certificate))
		if err != nil {
			continue
		}
		if cfg.IssuerRef != "" && (issuer.IssuerID == cfg.IssuerRef || issuer.IssuerName == cfg.IssuerRef) {
			return info
		}
		if soonest == nil || info.NotAfter.Before(soonest.NotAfter) {
			soonest = info
		}
	}
	return soonest
}

// explainNameRefusal names the constraint that refused a domain.
func (p *Provider) explainNameRefusal(ctx context.Context, cfg *Config, ve *apiError) string {
	base := fmt.Sprintf("Vault's role %q refused this name (%s)",
		cfg.Role, strings.Join(ve.Messages, "; "))

	role, err := p.readRole(ctx, cfg)
	if err != nil {
		return base + ". The role's allowed_domains could not be read to say which names it does allow"
	}
	if role.AllowAnyName {
		return base + ", although the role has allow_any_name set — so the refusal is one of the other constraints, such as allowed_uri_sans or a wildcard rule"
	}
	if len(role.AllowedDomains) == 0 {
		return base + ", and the role has no allowed_domains, so it can issue no names at all"
	}
	return fmt.Sprintf("%s. The role allows %s (subdomains %s, bare domains %s)",
		base, strings.Join(role.AllowedDomains, ", "),
		onOff(role.AllowSubdomains), onOff(role.AllowBareDomains))
}

// explainRevocation says which of the two ways this can fail happened.
//
// Vault will revoke a certificate it never stored, as long as it is given the
// certificate: it verifies the signature against the issuer and adds the
// serial to the CRL. What it cannot do is find a certificate by serial that it
// never kept — which is what a no_store role produces, and which is the only
// case where "Vault has no record" and "there is nothing to revoke" are the
// same sentence.
func (p *Provider) explainRevocation(ctx context.Context, cfg *Config, err error, hadCertificate bool) error {
	ve, ok := asAPIError(err)
	if !ok {
		return p.translate(err)
	}
	if ve.Status != http.StatusBadRequest && ve.Status != http.StatusNotFound {
		return p.translate(err)
	}

	if !hadCertificate && strings.Contains(ve.message(), "not found") {
		message := fmt.Sprintf(
			"Vault mount %s has no certificate with that serial, so it cannot be revoked by serial alone (%s). Vault will revoke a certificate it never stored if it is given the certificate itself",
			cfg.Mount, strings.Join(ve.Messages, "; "))
		if role, roleErr := p.readRole(ctx, cfg); roleErr == nil && role.NoStore {
			message += fmt.Sprintf(
				". Role %q has no_store set, which is why there is no copy to look up", cfg.Role)
		}
		return status.Error(codes.FailedPrecondition, message)
	}
	return p.translate(err)
}

func onOff(value bool) string {
	if value {
		return "allowed"
	}
	return "not allowed"
}
