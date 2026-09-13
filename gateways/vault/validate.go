package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
)

// issuerHorizon is how close an issuing CA has to be to its own expiry before
// this gateway says so unprompted.
//
// Ninety days is not arbitrary: it is roughly the longest certificate a private
// PKI issues, so an issuer inside ninety days is an issuer that may already be
// refusing to sign some of what is asked of it.
const issuerHorizon = 90 * 24 * time.Hour

// staticTokenHorizon is how much life a supplied token needs before its expiry
// stops being somebody's problem for later.
const staticTokenHorizon = 30 * 24 * time.Hour

// ValidateConfig checks a CA account against the Vault it names.
//
// This is the cheapest moment in the whole system to find out that a role does
// not exist, that a credential is wrong, or that the CA behind it expires
// before the certificates it is about to start signing. Everything checked here
// is otherwise discovered during an unattended renewal.
func (p *Provider) ValidateConfig(
	ctx context.Context, req *providerv1.ValidateConfigRequest,
) (*providerv1.ValidateConfigResponse, error) {
	cfg, err := ParseConfig(req.ConfigJson, p.defaultAddress, p.defaultNamespace)
	if err != nil {
		return &providerv1.ValidateConfigResponse{Valid: false, Errors: []string{err.Error()}}, nil
	}

	errs, warnings := cfg.Validate()
	if len(errs) > 0 {
		// No point asking Vault anything: the configuration does not yet
		// describe a Vault to ask.
		return &providerv1.ValidateConfigResponse{Valid: false, Errors: errs, Warnings: warnings}, nil
	}

	checkCtx, cancel := deadline(ctx, cfg)
	defer cancel()

	errs, warnings = p.checkReachable(checkCtx, cfg, errs, warnings)
	if len(errs) > 0 {
		return &providerv1.ValidateConfigResponse{Valid: false, Errors: errs, Warnings: warnings}, nil
	}

	errs, warnings = p.checkCredential(checkCtx, cfg, errs, warnings)
	if len(errs) > 0 {
		return &providerv1.ValidateConfigResponse{Valid: false, Errors: errs, Warnings: warnings}, nil
	}

	errs, warnings = p.checkRole(checkCtx, cfg, errs, warnings)
	errs, warnings = p.checkIssuers(checkCtx, cfg, errs, warnings)

	return &providerv1.ValidateConfigResponse{
		Valid:    len(errs) == 0,
		Errors:   errs,
		Warnings: warnings,
	}, nil
}

// checkReachable confirms there is a Vault at the address, without a token.
func (p *Provider) checkReachable(ctx context.Context, cfg *Config, errs, warnings []string) ([]string, []string) {
	state, err := p.health(ctx, cfg)
	if err != nil {
		return append(errs, fmt.Sprintf("cannot reach Vault at %s: %v", cfg.Address, err)), warnings
	}
	switch {
	case !state.Initialized:
		return append(errs, fmt.Sprintf("Vault at %s is not initialized", cfg.Address)), warnings
	case state.Sealed:
		// Not an error. A sealed Vault is a correct configuration pointed at a
		// Vault that is temporarily unavailable, and refusing to save the
		// account would be refusing to prepare during an outage.
		warnings = append(warnings, fmt.Sprintf(
			"Vault at %s is sealed: this configuration is fine, and nothing can be issued or revoked until it is unsealed", cfg.Address))
	}
	return errs, warnings
}

// checkCredential proves the credential works, and reports when it will stop.
func (p *Provider) checkCredential(ctx context.Context, cfg *Config, errs, warnings []string) ([]string, []string) {
	token, _, err := p.token(ctx, cfg)
	if err != nil {
		return append(errs, err.Error()), warnings
	}

	info, err := p.lookupSelf(ctx, cfg, token)
	if err != nil {
		// A token that cannot look itself up is unusual but not broken; the
		// default policy allows it, and a policy that removes it is a choice.
		return errs, append(warnings,
			"the credential works, and could not look itself up, so this gateway cannot say when it expires")
	}

	switch {
	case info.Period > 0:
		// A periodic token renews indefinitely. This is the configuration that
		// survives unattended operation, and it is worth confirming out loud.
		warnings = append(warnings, fmt.Sprintf(
			"the Vault token is periodic (%s) and renews indefinitely", humanDuration(info.Period)))
	case info.TTL == 0:
		if cfg.AuthMethod == AuthToken {
			warnings = append(warnings,
				"the supplied Vault token has no expiry, which usually means it is a root token. A root token in a CA account is a credential with every permission in Vault, stored to sign certificates")
		}
	case time.Duration(info.TTL)*time.Second < staticTokenHorizon && !info.Renewable:
		errs = append(errs, fmt.Sprintf(
			"the Vault token expires in %s and cannot be renewed. Every renewal through this account will fail from that moment, unattended. Use approle or kubernetes, or a periodic token",
			humanDuration(info.TTL)))
	case time.Duration(info.TTL)*time.Second < staticTokenHorizon:
		warnings = append(warnings, fmt.Sprintf(
			"the Vault token expires in %s; it is renewable, and this gateway renews it while it is running", humanDuration(info.TTL)))
	}
	return errs, warnings
}

// checkRole reads the role and reports what it will override.
//
// Everything here is something the operator asked for and will not get. None
// of it stops issuance, and all of it produces a certificate that is not what
// the request said.
func (p *Provider) checkRole(ctx context.Context, cfg *Config, errs, warnings []string) ([]string, []string) {
	role, err := p.readRole(ctx, cfg)
	if err != nil {
		ve, ok := asAPIError(err)
		switch {
		case ok && ve.Status == http.StatusNotFound:
			return append(errs, fmt.Sprintf(
				"Vault has no role %q on mount %q. Nothing can be issued through this account until it exists",
				cfg.Role, cfg.Mount)), warnings
		case ok && ve.Status == http.StatusForbidden:
			// A token allowed to issue and not to read roles is a
			// well-scoped token, not a broken one.
			return errs, append(warnings, fmt.Sprintf(
				"the credential cannot read %s/roles/%s, so this gateway cannot warn you in advance about what the role overrides. Issuance is unaffected", cfg.Mount, cfg.Role))
		default:
			return errs, append(warnings, fmt.Sprintf("could not read the role: %v", err))
		}
	}

	if role.NoStore {
		// Worth saying, and worth saying accurately. Vault will still revoke
		// one of these if it is handed the certificate — which CertPilot has —
		// so what is actually lost is the ability to ask Vault anything about
		// a certificate before it is revoked.
		warnings = append(warnings, fmt.Sprintf(
			"role %q has no_store set: Vault keeps no copy of what it signs, so CertPilot cannot ask Vault the status of a certificate from this account and will report it as unknown. Revocation still works, because it sends the certificate rather than its serial", cfg.Role))
	}
	if role.AllowAnyName {
		warnings = append(warnings, fmt.Sprintf(
			"role %q has allow_any_name set, so it will sign any name asked of it. The role is the only thing standing between a request and a certificate here — Vault performs no domain control validation", cfg.Role))
	}
	if role.KeyType != "" && role.KeyType != "any" {
		warnings = append(warnings, fmt.Sprintf(
			"role %q issues %s keys%s regardless of what a request asks for",
			cfg.Role, strings.ToUpper(role.KeyType), keyBitsSuffix(int(role.KeyBits))))
	}
	if role.MaxTTL > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"role %q caps validity at %s; a longer request is shortened to it, and Vault reports that as a warning rather than an error",
			cfg.Role, humanDuration(int(role.MaxTTL))))
	}
	return errs, warnings
}

// checkIssuers confirms the pinned issuer exists and reports one that is
// running out.
func (p *Provider) checkIssuers(ctx context.Context, cfg *Config, errs, warnings []string) ([]string, []string) {
	issuers, err := p.collectIssuers(ctx, cfg)
	if err != nil {
		return errs, append(warnings, fmt.Sprintf(
			"could not read the issuers of mount %s, so this gateway cannot tell you when the CA behind this account expires: %v", cfg.Mount, err))
	}

	if cfg.IssuerRef != "" {
		found := false
		for _, issuer := range issuers {
			if issuer.IssuerID == cfg.IssuerRef || issuer.IssuerName == cfg.IssuerRef {
				found = true
				break
			}
		}
		if !found {
			return append(errs, fmt.Sprintf(
				"mount %s has no issuer named %q. Every issuance through this account would fail", cfg.Mount, cfg.IssuerRef)), warnings
		}
	}

	culprit := signingIssuer(cfg, issuers)
	if culprit == nil {
		return errs, warnings
	}
	remaining := time.Until(culprit.NotAfter)
	switch {
	case remaining <= 0:
		errs = append(errs, fmt.Sprintf(
			"the issuing CA %q expired on %s. Vault will refuse to sign anything through it",
			culprit.CommonName, culprit.NotAfter.UTC().Format("2006-01-02")))
	case remaining < issuerHorizon:
		// The sentence this gateway was written to be able to say.
		warnings = append(warnings, fmt.Sprintf(
			"the issuing CA %q expires on %s, in %d days. Vault refuses to sign a certificate that would outlive its issuer, so issuance through this account starts failing before that date — as soon as a requested validity reaches past it — and every certificate it has already signed expires with it",
			culprit.CommonName, culprit.NotAfter.UTC().Format("2006-01-02"), culprit.DaysRemaining))
	}
	return errs, warnings
}

// humanDuration renders a count of seconds the way an operator would say it.
func humanDuration(seconds int) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d >= 48*time.Hour:
		return plural(int(d.Hours()/24), "day")
	case d >= time.Hour:
		return plural(int(d.Hours()), "hour")
	case d >= time.Minute:
		return plural(int(d.Minutes()), "minute")
	default:
		return plural(int(d.Seconds()), "second")
	}
}

func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", count, noun)
}

func keyBitsSuffix(bits int) string {
	if bits <= 0 {
		return ""
	}
	return fmt.Sprintf(" of %d bits", bits)
}
