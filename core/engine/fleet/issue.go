package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// maxRequestedNames bounds one request.
//
// A certificate for four hundred hostnames is not a certificate somebody meant
// to ask for, and refusing it early is cheaper than discovering the CA's own
// limit at the far end of an issuance.
const maxRequestedNames = 100

// Issuer signs certificate requests that came from a host.
//
// This is the point of the whole agent. The key was generated on the machine
// that will use it and has never left; what arrives here is a request, and
// CertPilot never holds a secret it could lose, copy, or be compelled to
// produce.
//
// Which makes authorisation the entire security surface. A credential that can
// request any name is a way to obtain a certificate for the payroll system from
// a compromised web server, signed by the organisation's own CA, indexed in the
// audit log next to every legitimate issuance. So nothing is signed that an
// operator did not grant in advance.
type Issuer struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
	broker    *events.Broker
	// resolver decides what may be issued. The grant decides who may ask and
	// for which names; everything about the certificate itself comes from here,
	// through the same six rungs a person's request goes through.
	//
	// Before this, the two paths had separate rulebooks and the agent's was the
	// narrower one — which is how a host could obtain a certificate the policy
	// engine would have refused a person.
	resolver *issuance.Resolver
	now      func() time.Time
}

// NewIssuer creates the issuer.
func NewIssuer(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, broker *events.Broker, pe *policy.Engine) *Issuer {
	return &Issuer{
		store: s, pluginMgr: pm, keyring: kr, broker: broker,
		resolver: issuance.NewResolver(s, pe),
		now:      time.Now,
	}
}

// Request is what an agent submits.
type Request struct {
	// CSRPem carries the names, the public key, and a signature proving the
	// requester holds the private half. Nothing else in it is honoured.
	CSRPem string `json:"csr_pem"`
	// InstallPath is where the agent intends to keep it, recorded so the
	// inventory can be matched against issuance without guessing.
	InstallPath string `json:"install_path,omitempty"`
	// Renews is the certificate this replaces, when the agent is rotating a key
	// it already holds.
	Renews string `json:"renews,omitempty"`
}

// Issued is what goes back to the host.
type Issued struct {
	CertificateID  string    `json:"certificate_id"`
	CommonName     string    `json:"common_name"`
	SANs           []string  `json:"sans"`
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem,omitempty"`
	NotAfter       time.Time `json:"not_after"`
	// RenewAfter is when this host may ask for a replacement. Decided by the
	// grant, not by the agent, so a fleet cannot decide to renew itself hourly.
	RenewAfter time.Time `json:"renew_after"`
}

// Issue validates a request against what its host has been granted, and signs
// it if it holds up.
func (i *Issuer) Issue(ctx context.Context, agent *store.Agent, req Request) (*Issued, error) {
	csr, err := parseCSR(req.CSRPem)
	if err != nil {
		return nil, err
	}

	names, err := requestedNames(csr)
	if err != nil {
		return nil, err
	}

	grant, err := i.authorise(ctx, agent, names)
	if err != nil {
		// Refusals are published, not only returned. A host asking for a name
		// it has not been granted is either a misconfiguration somebody needs
		// to fix or the first sign of a compromised credential, and both look
		// identical from here — which is exactly why a person should see it.
		i.announceRefusal(agent, names, err)
		return nil, err
	}

	// Everything about the certificate — the issuer, the key rules, the
	// lifetime, the naming rules and the estate-wide floor above all of them —
	// comes from here. The grant said who may ask and for which names, and that
	// is the whole of its job now.
	decision, err := i.resolver.Resolve(ctx, issuance.Request{
		TemplateRef: grant.TemplateID,
		CSR:         csr,
		// The host generated this key and CertPilot has never seen it. Stated
		// rather than left to be inferred, so a template that requires custody
		// elsewhere refuses instead of silently accepting.
		KeyCustody: store.KeyCustodyAgent,
	})
	if err != nil {
		i.announceRefusal(agent, names, err)
		return nil, err
	}

	account := decision.Account
	gateway, err := i.gateway(account)
	if err != nil {
		return nil, err
	}
	config, err := decryptCAConfig(i.keyring, account)
	if err != nil {
		return nil, err
	}

	slog.Info("signing a request from a host",
		"agent", agent.Name, "names", decision.Domains, "grant", grant.Name,
		"template", decision.Template.Slug,
		"ca_account", account.Name,
		"key", fmt.Sprintf("%s/%d", decision.KeyType, decision.KeySize),
		"private_key", "never sent, never held")

	resp, err := gateway.Client.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem: []byte(req.CSRPem),
		// The names CertPilot validated, not the ones the request asked for.
		// The two are the same here — that is what the grant and the template
		// between them checked — but passing the validated set means a gateway
		// that trusts its caller is trusting a decision that was actually made.
		Domains:        decision.Domains,
		KeyType:        decision.KeyType,
		KeySize:        int32(decision.KeySize),
		ValidityDays:   int32(decision.ValidityDays),
		ProviderConfig: config,
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
	// worse than failing: the certificate on the host would not match the key
	// in the database, and both would look fine.
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		return nil, fmt.Errorf(
			"the %s gateway returned a private key for a request that carried its own public key, which means it ignored the request. Refusing to store a certificate whose key CertPilot was not supposed to have",
			account.ProviderType)
	}

	cert, err := i.record(ctx, agent, grant, decision, req, info, resp)
	if err != nil {
		return nil, err
	}

	issued := &Issued{
		CertificateID:  cert.ID,
		CommonName:     cert.CommonName,
		SANs:           cert.SANs,
		CertificatePEM: string(resp.Certificate.CertificatePem),
		ChainPEM:       string(resp.Certificate.ChainPem),
		NotAfter:       info.NotAfter,
		RenewAfter:     info.NotAfter.AddDate(0, 0, -decision.RenewBeforeDays),
	}
	return issued, nil
}

// record writes the issued certificate to the inventory.
//
// With no private key, and said so explicitly rather than left as an absence:
// KeyCustodyAgent is the difference between "we do not have this key" and "this
// key is on a host and we could not produce it if we were ordered to".
func (i *Issuer) record(ctx context.Context, agent *store.Agent, grant *store.TemplateGrant,
	decision *issuance.Decision, req Request, info *x509util.CertInfo,
	resp *providerv1.IssueCertificateResponse) (*store.Certificate, error) {

	notBefore, notAfter := info.NotBefore, info.NotAfter
	certPEM := string(resp.Certificate.CertificatePem)
	holder := agent.ID
	accountID := decision.Account.ID
	templateID := decision.Template.ID
	templateVersion := decision.Template.Version
	grantID := grant.ID

	cert := &store.Certificate{
		FingerprintSHA256: info.FingerprintSHA256,
		CommonName:        info.CommonName,
		SANs:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDN:          info.IssuerDN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		Status:            "ISSUED",
		// The core does not renew this one. The host holds the key, so only the
		// host can rotate it, and a sweep that tried would fail on every
		// attempt forever.
		AutoRenew:       false,
		RenewalLeadDays: decision.RenewBeforeDays,
		CAAccountID:     &accountID,
		TemplateID:      &templateID,
		TemplateVersion: &templateVersion,
		// Which binding permitted it, which the human path has no equivalent of yet.
		GrantID:          &grantID,
		CertificatePEM:   &certPEM,
		DiscoveredVia:    "AGENT",
		KeyCustody:       store.KeyCustodyAgent,
		KeyHolderAgentID: &holder,
	}
	if len(resp.Certificate.ChainPem) > 0 {
		chain := string(resp.Certificate.ChainPem)
		cert.ChainPEM = &chain
	}

	if err := i.store.CreateCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("the certificate was issued and could not be recorded: %w", err)
	}

	_ = i.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.issued_to_agent",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn":%q,"agent":%q,"grant":%q,"install_path":%q,"key_custody":"AGENT"}`,
			cert.CommonName, agent.Name, grant.Name, req.InstallPath),
	})

	if i.broker != nil {
		i.broker.Publish(events.Event{
			Topic:    events.TopicCertIssued,
			Severity: events.SeverityInfo,
			EntityID: cert.ID,
			Payload: map[string]any{
				"common_name": cert.CommonName,
				"not_after":   notAfter.Format(time.RFC3339),
				"gateway":     agent.Name + " (key generated on the host)",
			},
		})
	}
	return cert, nil
}

// authorise decides whether this host may have this certificate.
func (i *Issuer) authorise(ctx context.Context, agent *store.Agent,
	names []string) (*store.TemplateGrant, error) {

	grants, err := i.store.GetGrantsForAgent(ctx, agent.ID)
	if err != nil {
		return nil, fmt.Errorf("could not read what this host is allowed to ask for: %w", err)
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf(
			"%s has no grant, so it may not request certificates. Create one with POST /api/v1/agent-grants naming this agent or a label it carries",
			agent.Name)
	}

	// One grant has to cover the whole request. Assembling permission from
	// several would let a host combine a grant for one tier's names with
	// another tier's CA account, and the resulting certificate would be
	// something nobody authorised as a whole.
	var reasons []string
	for _, grant := range grants {
		if missing := uncovered(grant, names); len(missing) > 0 {
			reasons = append(reasons, fmt.Sprintf("%s does not cover %s",
				grant.Name, strings.Join(missing, ", ")))
			continue
		}
		// No key check here. The grant used to carry one, and it was a
		// second, narrower rulebook that drifted from the policy engine the
		// moment either changed. The template the grant names decides the key
		// now, and the estate-wide floor sits above that.
		return grant, nil
	}

	return nil, fmt.Errorf("no grant permits this request from %s — %s",
		agent.Name, strings.Join(reasons, "; "))
}

func uncovered(grant *store.TemplateGrant, names []string) []string {
	missing := []string{}
	for _, name := range names {
		if !grant.Covers(name) {
			missing = append(missing, name)
		}
	}
	return missing
}

// parseCSR reads a request and checks it is what it claims to be.
//
// The shared parser checks the signature — proof of possession, and the reason
// a CSR is worth more than a list of names. Without it anybody who can reach
// this endpoint could obtain a certificate for a public key belonging to
// somebody else, from an authority this organisation runs.
//
// It also reports whether the request asks to become a CA. The refusal for that
// used to live here and applied to agents only, so the same CSR submitted by a
// person through the API reached the gateway unchecked. It is in the resolver
// now, which every path goes through.
func parseCSR(csrPEM string) (*x509util.CSRInfo, error) {
	return x509util.ParseCSRPEM([]byte(csrPEM))
}

// requestedNames is what this request asks to certify.
//
// The restriction to DNS names used to live here — "a grant has no way to
// express them" — and a template does, through san_rules.types. Migration 038
// sets it on every template generated from an existing grant, so the rule is
// unchanged for every agent that has one and can now be relaxed deliberately
// for a host that genuinely needs an IP or SPIFFE name.
//
// What stays is the count ceiling, which is not policy: it is a bound on one
// request.
func requestedNames(csr *x509util.CSRInfo) ([]string, error) {
	names := csr.Names()
	if len(names) == 0 {
		return nil, fmt.Errorf("this request names nothing: it has no common name and no DNS names")
	}
	if len(names) > maxRequestedNames {
		return nil, fmt.Errorf("this request carries %d names, which is more than the %d allowed",
			len(names), maxRequestedNames)
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")))
	}
	return out, nil
}

func (i *Issuer) gateway(account *store.CAAccount) (*pluginmgr.GatewayClient, error) {
	gw, err := i.pluginMgr.GetGateway(account.Name)
	if err == nil {
		return gw, nil
	}
	gw, err = i.pluginMgr.GetGateway(account.ProviderType)
	if err != nil {
		return nil, fmt.Errorf("the gateway for CA account %s is not connected: %w", account.Name, err)
	}
	return gw, nil
}

// decryptCAConfig opens a CA account's sealed configuration.
func decryptCAConfig(keyring *secrets.Keyring, acc *store.CAAccount) (string, error) {
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

// announceRefusal publishes a request that was not permitted.
//
// A host asking for a name it has not been granted is either a
// misconfiguration somebody needs to fix or the first sign of a stolen
// credential being used, and the two are indistinguishable from here. That is
// precisely why it goes to a person rather than only into a log.
func (i *Issuer) announceRefusal(agent *store.Agent, names []string, cause error) {
	if i.broker == nil {
		return
	}
	i.broker.Publish(events.Event{
		Topic:    events.TopicAgentRequestRefused,
		Severity: events.SeverityWarning,
		EntityID: agent.ID,
		Payload: map[string]any{
			"agent":    agent.Name,
			"hostname": agent.Hostname,
			"names":    names,
			"reason":   cause.Error(),
		},
	})
}
