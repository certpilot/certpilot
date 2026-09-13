// Package issuance decides what may be issued, once, for every path that
// issues.
//
// Before this existed there were three paths and they enforced three different
// things: a person's request was judged by the policy engine, a host's request
// by its grant, and a renewal by nothing at all. Each of those was written
// separately and each forgot something the others remembered, which is the
// failure this package exists to make structurally impossible — a new path that
// forgets to ask is a path that cannot issue.
package issuance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// The precedence order, stated once and obeyed everywhere.
//
//  1. Global policy (BLOCK)     the estate floor — nothing below may exceed it
//  2. Template supplied values  win over everything under them
//  3. Template constraints      the request must satisfy these
//  4. Grant narrowing           may only narrow, never widen
//  5. The request               fills whatever is left
//  6. The CSR                   names and public key only
//
// Borrowed from AWS Private CA, which is the only major implementation that
// writes its rule down plainly: "the template definition has highest priority,
// followed by API passthrough values, followed by CSR passthrough extensions".
// Google's documentation acknowledges that its two layers can conflict and
// sends the reader to a separate page rather than stating which wins.
//
// Rung 4 is not implemented here. Grants still carry certificate shape of their
// own and are still agent-only; moving them onto templates is #27, and the seam
// is Decision.Template, which is what a grant will narrow.
const (
	// RungRequest is the caller's own mistake: a name they did not send, a
	// template that does not exist. Their problem to fix, and a different HTTP
	// status from the two below.
	RungRequest  = "request"
	RungTemplate = "template"
	RungPolicy   = "policy"
)

// Refusal is a request that was well-formed and not permitted.
//
// Distinct from an error, because the two need different answers: a malformed
// request is the caller's to fix, and a refused one is an operator's. A handler
// that reported both as 400 would tell somebody to correct a request that was
// already correct.
type Refusal struct {
	Rung    string
	Message string
	// Violations carries the policy engine's own findings when Rung is
	// RungPolicy, so a caller can show the severity and the rule alongside.
	Violations []policy.Violation
}

func (r *Refusal) Error() string { return r.Message }

func refuse(rung, format string, a ...any) *Refusal {
	return &Refusal{Rung: rung, Message: fmt.Sprintf(format, a...)}
}

// AsRefusal reports whether an error is a refusal, and returns it.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}

// Request is what a caller asks for, before any rule has been applied.
type Request struct {
	// TemplateRef is a slug or a uuid. Empty resolves to the default template
	// for CAAccountID, which reproduces the behaviour that existed before
	// templates did.
	TemplateRef string
	// CAAccountID is only consulted when TemplateRef is empty. A template pins
	// its own issuer, because a requester who could pick one could pick the
	// cheapest, the least logged, or the one with the widest trust.
	CAAccountID string

	CommonName string
	SANs       []string

	// CSR is the parsed signing request, when one was supplied. It is the
	// authority on the names and the key, and it carries a subject the
	// requester chose — which is the thing subject_mode decides about.
	CSR *x509util.CSRInfo

	KeyType      string
	KeySize      int
	ValidityDays int

	Environment string
	Team        string
	Tags        []string
	// MetadataKeys is which metadata fields the request answered, used for the
	// template's own required-field list. The values are validated elsewhere.
	MetadataKeys []string

	// KeyCustody is where the private key will live if this is issued.
	KeyCustody string
}

// Decision is what may actually be issued.
type Decision struct {
	Template *store.CertificateTemplate
	Account  *store.CAAccount

	CommonName   string
	Domains      []string
	KeyType      string
	KeySize      int
	ValidityDays int

	RenewBeforeDays int
	AutoRenew       bool

	Environment string
	Team        string
	Tags        []string

	// Violations is everything the floor found, including the advisory ones. A
	// BLOCK among them is a refusal and never reaches here.
	Violations []policy.Violation

	// Overrides records where the template supplied a value the request had
	// also asked for. AWS resolves this by ignoring the request silently; a
	// requester who asked for 365 days and received 90 should be told which
	// rule shortened it rather than left to notice.
	Overrides []string
}

// Resolver applies the precedence order.
type Resolver struct {
	store  store.Store
	policy *policy.Engine
}

// NewResolver creates a Resolver.
func NewResolver(s store.Store, pe *policy.Engine) *Resolver {
	return &Resolver{store: s, policy: pe}
}

// Resolve decides what may be issued, or refuses and says which rung refused.
func (r *Resolver) Resolve(ctx context.Context, req Request) (*Decision, error) {
	tpl, err := r.template(ctx, req)
	if err != nil {
		return nil, err
	}

	account, err := r.store.GetCAAccount(ctx, tpl.CAAccountID)
	if err != nil {
		return nil, fmt.Errorf(
			"template %q issues from a CA account that no longer exists: %w", tpl.Slug, err)
	}

	d := &Decision{
		Template:        tpl,
		Account:         account,
		RenewBeforeDays: tpl.RenewBeforeDays,
		AutoRenew:       tpl.AutoRenew,
	}

	// ── Rung 6, then 5: the CSR decides the names and the key, the request
	// fills what it left ──────────────────────────────────────────────────
	if err := applyNamesAndKey(d, tpl, req); err != nil {
		return nil, err
	}

	// ── Rung 2: what the template supplies ────────────────────────────────
	applySuppliedValues(d, tpl, req)

	// ── Rung 3: what the template constrains ──────────────────────────────
	if err := checkTemplate(d, tpl, req); err != nil {
		return nil, err
	}

	// ── Rung 1: the floor, judged on the values that survived ─────────────
	violations, err := r.policy.EvaluateRequest(ctx, policy.Request{
		CommonName:     d.CommonName,
		Domains:        d.Domains,
		KeyType:        d.KeyType,
		KeySize:        d.KeySize,
		ValidityDays:   d.ValidityDays,
		CAProviderType: account.ProviderType,
	})
	if err != nil {
		// A floor that cannot be consulted blocks. Treating an evaluation
		// failure as "no violations" means a database blip silently disables
		// every policy at once.
		return nil, fmt.Errorf("could not evaluate security policy, refusing to issue: %w", err)
	}
	d.Violations = violations

	var blocking []policy.Violation
	for _, v := range violations {
		if v.Severity == policy.SeverityBlock {
			blocking = append(blocking, v)
		}
	}
	if len(blocking) > 0 {
		messages := make([]string, 0, len(blocking))
		for _, v := range blocking {
			messages = append(messages, v.Message)
		}
		return nil, &Refusal{
			Rung:       RungPolicy,
			Message:    strings.Join(messages, "; "),
			Violations: violations,
		}
	}

	return d, nil
}

// template resolves which template governs this request.
func (r *Resolver) template(ctx context.Context, req Request) (*store.CertificateTemplate, error) {
	ref := strings.TrimSpace(req.TemplateRef)

	if ref == "" {
		// The compatibility path. Every CA account has a default template that
		// constrains nothing, generated by migration 037, so a caller written
		// before templates existed behaves exactly as it did.
		if req.CAAccountID == "" {
			return nil, refuse(RungRequest,
				"neither template_id nor ca_account_id was given, so there is nothing to issue under")
		}
		tpl, err := r.store.GetCertificateTemplateBySlug(ctx, defaultSlug(req.CAAccountID))
		if err != nil {
			return nil, fmt.Errorf(
				"no template was named and CA account %s has no default template: %w",
				req.CAAccountID, err)
		}
		return live(tpl)
	}

	if tpl, err := r.store.GetCertificateTemplateBySlug(ctx, ref); err == nil {
		return live(tpl)
	}
	tpl, err := r.store.GetCertificateTemplate(ctx, ref)
	if err != nil {
		return nil, refuse(RungRequest, "no certificate template named %q", ref)
	}
	return live(tpl)
}

func live(tpl *store.CertificateTemplate) (*store.CertificateTemplate, error) {
	if !tpl.Live() {
		return nil, refuse(RungTemplate,
			"template %q is disabled, so nothing may be issued under it", tpl.Slug)
	}
	return tpl, nil
}

// DefaultSlug is the slug of the template generated for a CA account.
func DefaultSlug(caAccountID string) string { return defaultSlug(caAccountID) }

func defaultSlug(caAccountID string) string {
	id := strings.ToLower(strings.ReplaceAll(caAccountID, "-", ""))
	if len(id) > 8 {
		id = id[:8]
	}
	return "default-" + id
}
