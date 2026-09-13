package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
)

// bypassFixture builds the smallest estate that can issue to a host: a CA
// account, a template, an agent, and a grant binding the two.
//
// No gateway. Every assertion below is about a request being refused, and a
// refusal that reached a gateway would already be a failure — so a nil plugin
// manager is not a shortcut, it is part of the assertion.
func bypassFixture(t *testing.T) (*Issuer, store.Store, *store.Agent, *store.CertificateTemplate) {
	t.Helper()
	ctx := context.Background()
	s := store.NewMemoryStore()

	for _, p := range mustPolicies(t, s) {
		if err := s.DeletePolicy(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}

	acc := &store.CAAccount{
		Name: "Test CA", ProviderType: "selfsigned",
		GatewayAddr: "127.0.0.1:9443", ConfigEncrypted: "sealed", Status: "CONNECTED",
	}
	if err := s.CreateCAAccount(ctx, acc); err != nil {
		t.Fatal(err)
	}

	tpl := &store.CertificateTemplate{
		Slug: "hosts", Name: "Hosts", Version: 1, IsEnabled: true,
		CAAccountID:        acc.ID,
		SubjectMode:        store.SubjectModeSupplied,
		AllowedKeyTypes:    []string{"RSA", "ECDSA", "Ed25519"},
		ECDSACurves:        []string{"P-256", "P-384", "P-521"},
		KeyCustodyRequired: store.KeyCustodyAny,
		RenewBeforeDays:    30,
	}
	if err := s.CreateCertificateTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}

	agent := &store.Agent{Name: "web-01", KeyID: "agt_web01", PublicKey: "AAAA", Status: "ACTIVE"}
	if err := s.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}

	grant := &store.TemplateGrant{
		Name: "web tier", TemplateID: tpl.ID, SubjectKind: store.GrantSubjectAgent,
		AgentID: &agent.ID, Names: []string{"*.example.com"}, IsEnabled: true,
	}
	if err := s.CreateTemplateGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}

	return NewIssuer(s, nil, nil, nil, policy.NewEngine(s)), s, agent, tpl
}

func mustPolicies(t *testing.T, s store.Store) []*store.Policy {
	t.Helper()
	ps, err := s.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func addPolicy(t *testing.T, s store.Store, name, ruleType, config, severity string) {
	t.Helper()
	err := s.CreatePolicy(context.Background(), &store.Policy{
		Name: name, IsEnabled: true, RuleType: ruleType,
		RuleConfig: config, Severity: severity,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAPolicyNowStopsAnAgentToo is the whole point of this change.
//
// `policyEng` had exactly one consumer in the tree — the handler for a person's
// request. `grep -rn "engine/policy" core/engine/fleet/` returned nothing, so a
// BLOCK policy an operator wrote stopped somebody in the console and did not
// stop a host. Agents are the numerous, automated, unattended half of an
// estate: a control that holds for the handful of certificates a person asks
// for by hand and not for the thousands a fleet asks for on its own is close to
// no control.
func TestAPolicyNowStopsAnAgentToo(t *testing.T) {
	issuer, s, agent, _ := bypassFixture(t)
	addPolicy(t, s, "P-384 or better", policy.RuleKeySize,
		`{"ecdsa_min_bits": 384}`, policy.SeverityBlock)

	// A P-256 request, which the old grant would have permitted: its key check
	// judged every elliptic key against one global constant of 256.
	csr := csrFor(t, "web-01.example.com", []string{"web-01.example.com"}, nil)

	_, err := issuer.Issue(context.Background(), agent, Request{CSRPem: csr})
	if err == nil {
		t.Fatal("an agent obtained a certificate a BLOCK policy forbids")
	}
	if !strings.Contains(err.Error(), "P-384 or better") {
		t.Errorf("the refusal does not name the policy that refused it: %v", err)
	}
}

// TestTheTemplateStopsAnAgentToo. The other half: rules an operator writes on
// the template, not the floor.
func TestTheTemplateStopsAnAgentToo(t *testing.T) {
	issuer, s, agent, tpl := bypassFixture(t)
	tpl.AllowedKeyTypes = []string{"RSA"}
	if err := s.UpdateCertificateTemplate(context.Background(), tpl); err != nil {
		t.Fatal(err)
	}

	csr := csrFor(t, "web-01.example.com", []string{"web-01.example.com"}, nil)

	_, err := issuer.Issue(context.Background(), agent, Request{CSRPem: csr})
	if err == nil {
		t.Fatal("an agent obtained a key type its template does not issue")
	}
	if !strings.Contains(err.Error(), "not one template") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// TestTheGrantStillBoundsTheNames. The grant kept one job and has to still do
// it: a host asking for a name nobody granted is refused before anything else
// is considered.
func TestTheGrantStillBoundsTheNames(t *testing.T) {
	issuer, _, agent, _ := bypassFixture(t)

	csr := csrFor(t, "payroll.elsewhere.net", []string{"payroll.elsewhere.net"}, nil)

	_, err := issuer.Issue(context.Background(), agent, Request{CSRPem: csr})
	if err == nil {
		t.Fatal("an agent obtained a certificate for a name no grant covers")
	}
	if !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("the refusal does not say the name was not granted: %v", err)
	}
}

// TestAHostWithNoGrantIsRefusedBeforeAnythingElse.
func TestAHostWithNoGrantIsRefusedBeforeAnythingElse(t *testing.T) {
	issuer, s, _, _ := bypassFixture(t)

	stranger := &store.Agent{Name: "unknown-01", KeyID: "agt_unknown", PublicKey: "BBBB", Status: "ACTIVE"}
	if err := s.CreateAgent(context.Background(), stranger); err != nil {
		t.Fatal(err)
	}

	csr := csrFor(t, "web-01.example.com", []string{"web-01.example.com"}, nil)

	_, err := issuer.Issue(context.Background(), stranger, Request{CSRPem: csr})
	if err == nil {
		t.Fatal("a host with no grant obtained a certificate")
	}
	if !strings.Contains(err.Error(), "no grant") {
		t.Errorf("the refusal should say there is no grant: %v", err)
	}
}
