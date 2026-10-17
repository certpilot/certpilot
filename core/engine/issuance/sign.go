package issuance

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Signer has a CA sign a request whose key is held somewhere else, and checks
// what comes back before anyone records it.
//
// Every path that signs a CSR goes through here: the agent's, and the ACME
// server's. They used to be written out in each, and a check added to one is a
// check the other does not have.
type Signer struct {
	plugins *pluginmgr.Manager
	keyring *secrets.Keyring
}

// NewSigner creates a signer.
func NewSigner(pm *pluginmgr.Manager, kr *secrets.Keyring) *Signer {
	return &Signer{plugins: pm, keyring: kr}
}

// Signed is a certificate the CA issued for a CSR, already parsed and checked.
type Signed struct {
	CertificatePEM []byte
	ChainPEM       []byte
	Info           *x509util.CertInfo
	// Findings are the non-blocking conformance findings, to be recorded with
	// the certificate. Blocking ones never get this far.
	Findings []store.ConformanceFinding
	// Gateway names the gateway that asked the CA.
	Gateway string
}

// SignCSR asks the decision's CA to sign csrPEM.
//
// The names, key and lifetime sent are the decision's, which is to say the ones
// CertPilot validated rather than the ones the request asked for. The two are
// the same by this point, but a gateway that trusts its caller is then trusting
// a decision that was actually made.
func (s *Signer) SignCSR(ctx context.Context, d *Decision, csrPEM string) (*Signed, error) {
	account := d.Account
	gw, err := s.plugins.GatewayFor(ctx, pluginmgr.Endpoint{
		Name: account.Name, Addr: account.GatewayAddr, Type: account.ProviderType, ServerName: account.ServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("the gateway for CA account %s is not connected: %w", account.Name, err)
	}
	config, err := DecryptCAConfig(s.keyring, account)
	if err != nil {
		return nil, err
	}

	resp, err := gw.Client.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem:           []byte(csrPEM),
		Domains:          d.Domains,
		KeyType:          d.KeyType,
		KeySize:          int32(d.KeySize),
		ValidityDays:     int32(d.ValidityDays),
		ProviderConfig:   config,
		CaProfile:        d.CAProfile,
		KeyUsage:         d.KeyUsage,
		ExtendedKeyUsage: d.ExtendedKeyUsage,
	})
	if err != nil {
		return nil, fmt.Errorf("the CA refused this request: %w", err)
	}
	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		return nil, fmt.Errorf("the gateway reported success and returned no certificate")
	}

	// Parsed before it is stored, so a gateway that returns something that is
	// not a certificate cannot put it in the inventory.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		return nil, fmt.Errorf("the CA returned data that is not a valid X.509 certificate: %w", err)
	}

	// A gateway that returns a private key for a CSR-based request has
	// generated its own keypair and ignored the request. Storing that would be
	// worse than failing: the certificate the requester holds would not match
	// any key it has, and both would look fine.
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		return nil, fmt.Errorf(
			"the %s gateway returned a private key for a request that carried its own public key, which means it ignored the request. Refusing to store a certificate whose key CertPilot was not supposed to have",
			account.ProviderType)
	}

	// Issue, then check — #30. A gateway that cannot enforce a declared key
	// usage or a validity ceiling must not have its answer trusted uninspected.
	findings, err := VerifyConformance(d, resp.Certificate.CertificatePem)
	if err != nil {
		return nil, fmt.Errorf("issued certificate could not be checked for conformance: %w", err)
	}
	if blocking := Enforced(d.Template, findings); len(blocking) > 0 {
		messages := make([]string, 0, len(blocking))
		for _, f := range blocking {
			messages = append(messages, f.Message)
		}
		// Best effort. A gateway that cannot revoke must not turn "this
		// certificate was wrong" into "and nobody can be told about it".
		if _, revokeErr := gw.Client.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
			CertificatePem:        resp.Certificate.CertificatePem,
			ProviderCertificateId: resp.ProviderCertificateId,
			ProviderConfig:        config,
		}); revokeErr != nil {
			slog.Warn("could not revoke a certificate that failed conformance under an ENFORCE template",
				"template", d.Template.Slug, "error", revokeErr)
		}
		return nil, fmt.Errorf(
			"template %q requires ENFORCE conformance and the CA did not honour the request: %s",
			d.Template.Slug, strings.Join(messages, "; "))
	}

	return &Signed{
		CertificatePEM: resp.Certificate.CertificatePem,
		ChainPEM:       resp.Certificate.ChainPem,
		Info:           info,
		Findings:       findings,
		Gateway:        gw.Name,
	}, nil
}

// DecryptCAConfig opens a CA account's sealed configuration for one call.
//
// Records written before encryption existed are stored as plaintext JSON;
// those are passed through so an upgrade does not break every existing account.
func DecryptCAConfig(keyring *secrets.Keyring, acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := keyring.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}
