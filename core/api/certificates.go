package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// CertificateHandler handles certificate management endpoints.
type CertificateHandler struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	executor  *renewal.Executor
	renewals  *renewal.Scheduler
	policyEng *policy.Engine
	// resolver decides what may be issued. policyEng stays because other
	// handlers on this type report policy findings against certificates that
	// already exist, which is a different question from what may be issued.
	resolver *issuance.Resolver
	keyring  *secrets.Keyring
	broker   *events.Broker
}

// NewCertificateHandler creates a new handler.
func NewCertificateHandler(s store.Store, pm *pluginmgr.Manager, exec *renewal.Executor, sched *renewal.Scheduler, pe *policy.Engine, kr *secrets.Keyring, broker *events.Broker) *CertificateHandler {
	return &CertificateHandler{
		store:     s,
		pluginMgr: pm,
		executor:  exec,
		renewals:  sched,
		policyEng: pe,
		resolver:  issuance.NewResolver(s, pe),
		keyring:   kr,
		broker:    broker,
	}
}

// List handles GET /api/v1/certificates.
func (h *CertificateHandler) List(c *gin.Context) {
	// Refused rather than ignored, and this one was paid for. A cleanup script
	// asked for `?search=rollout.step3.example.com`, which this handler has
	// never read; the filter was dropped, the list came back as the whole
	// estate, and the loop deleting what it matched deleted everything.
	//
	// A narrowing parameter that silently does not narrow turns a specific
	// request into "all rows" — harmless on a GET a person reads, destructive
	// the moment anything acts on the result. So an unrecognised filter is a
	// 400 that names it.
	if unknown := unexpectedQuery(c, "status", "environment", "common_name",
		"ca_account_id", "limit", "offset"); unknown != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"%q is not a filter this endpoint understands, and returning every certificate instead of the ones you asked for would be worse than refusing. Supported: status, environment, common_name, ca_account_id, limit, offset",
				unknown),
		})
		return
	}

	var filter store.CertificateFilter
	filter.Status = c.Query("status")
	filter.Environment = c.Query("environment")
	filter.CommonName = c.Query("common_name")
	filter.CAAccountID = c.Query("ca_account_id")

	certs, total, err := h.store.ListCertificates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  certs,
		"total": total,
	})
}

// Get handles GET /api/v1/certificates/:id.
func (h *CertificateHandler) Get(c *gin.Context) {
	id := c.Param("id")
	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cert)
}

// RequestCertificateInput defines the payload to request a new certificate.
type RequestCertificateInput struct {
	// CommonName is required unless CSRPEM is supplied, in which case the names
	// come from the request itself. Checked by the resolver rather than by a
	// binding tag, which cannot express "one of these two".
	CommonName string   `json:"common_name"`
	SANs       []string `json:"sans"`

	// TemplateID names the certificate template to issue under, by slug or by
	// uuid. A slug is what a pipeline should carry: it survives a rename.
	//
	// Optional, for now. A request without one resolves to the default
	// template for CAAccountID, which constrains nothing — so every caller
	// written before templates existed behaves exactly as it did. Requiring it
	// is the third stage of #25 and is a decision for an operator, not a
	// migration.
	TemplateID string `json:"template_id"`

	// CAAccountID is only consulted when TemplateID is absent. A template pins
	// its own issuer, so naming both is naming the same thing twice — and when
	// they disagree the template wins, because a requester who could choose an
	// issuer could choose the cheapest, the least logged, or the one with the
	// widest trust.
	//
	// No longer `binding:"required"`: one of the two has to be present, which
	// a binding tag cannot express. The resolver says which is missing.
	CAAccountID string `json:"ca_account_id"`

	// CSRPEM is a certificate signing request whose private key was generated
	// somewhere else and never sent here.
	//
	// This is the path for the keys CertPilot must not hold: an HSM, a load
	// balancer that generates its own, a team whose policy forbids a key
	// leaving their host. The names, key type and key size are taken from the
	// request and the corresponding fields above are ignored, because the only
	// key that can serve the certificate is the one the requester already has —
	// honouring a conflicting key_type here would issue a certificate nobody
	// can use.
	CSRPEM string `json:"csr_pem"`

	KeyType         string `json:"key_type"`
	KeySize         int    `json:"key_size"`
	ValidityDays    int    `json:"validity_days"`
	Environment     string `json:"environment"`
	Team            string `json:"team"`
	AutoRenew       bool   `json:"auto_renew"`
	RenewalLeadDays int    `json:"renewal_lead_days"`
	// Metadata holds values for the admin-defined fields. Required ones are
	// enforced at request time.
	Metadata map[string]any `json:"metadata"`
}

// Create handles POST /api/v1/certificates (Requests and issues a new certificate).
func (h *CertificateHandler) Create(c *gin.Context) {
	var input RequestCertificateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	environment, err := normalizeEnvironment(input.Environment)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Environment = environment

	// A signing request, when there is one, is the authority on what is being
	// asked for. Parsed first so the policy engine and the gateway both see the
	// real names and the real key rather than whatever the form also sent.
	var csrInfo *x509util.CSRInfo
	if strings.TrimSpace(input.CSRPEM) != "" {
		csrInfo, err = x509util.ParseCSRPEM([]byte(input.CSRPEM))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		names := csrInfo.Names()
		input.CommonName = names[0]
		input.SANs = names[1:]
		input.KeyType = csrInfo.KeyType
		input.KeySize = csrInfo.KeySize
	}

	// Required fields are enforced here and only here: at the moment somebody
	// asks for a certificate, which is when the organisation gets to insist on
	// a cost centre or a change ticket.
	metadataFields, err := h.store.ListMetadataFields(c.Request.Context(), false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cleanedMetadata, err := validateMetadata(metadataFields, input.Metadata, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Decide what may be issued.
	//
	// One call, six rungs, and the same call every other issuance path will
	// make. What used to be here — a common name check, four hardcoded
	// defaults, a dedupe, a CA lookup and a policy evaluation — was written
	// once for this path and never repeated on the other two, which is how an
	// agent came to be able to ask for anything the policy engine forbids.
	decision, err := h.resolver.Resolve(c.Request.Context(), issuance.Request{
		TemplateRef:  input.TemplateID,
		CAAccountID:  input.CAAccountID,
		CommonName:   input.CommonName,
		SANs:         input.SANs,
		CSR:          csrInfo,
		KeyType:      input.KeyType,
		KeySize:      input.KeySize,
		ValidityDays: input.ValidityDays,
		Environment:  input.Environment,
		Team:         input.Team,
		MetadataKeys: keysOf(cleanedMetadata),
		KeyCustody:   custodyFor(csrInfo),
	})
	if err != nil {
		writeResolveFailure(c, err)
		return
	}

	caAccount := decision.Account
	allDomains := decision.Domains
	input.CommonName = decision.CommonName
	input.KeyType = decision.KeyType
	input.KeySize = decision.KeySize
	input.ValidityDays = decision.ValidityDays
	input.Environment = decision.Environment
	input.Team = decision.Team
	violations := decision.Violations

	if input.RenewalLeadDays <= 0 {
		input.RenewalLeadDays = decision.RenewBeforeDays
	}

	// 3. Find Gateway
	gw, err := h.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		gw, err = h.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("gateway for CA %s is not connected", caAccount.Name)})
			return
		}
	}

	// 4. Request Issuance from Gateway.
	// The CA account configuration is stored sealed and is decrypted only here,
	// to populate a single mutually-authenticated gRPC call.
	providerConfig, err := h.decryptCAConfig(caAccount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	issueReq := &providerv1.IssueCertificateRequest{
		Domains:          allDomains,
		KeyType:          input.KeyType,
		KeySize:          int32(input.KeySize),
		ValidityDays:     int32(input.ValidityDays),
		ProviderConfig:   providerConfig,
		CaProfile:        decision.CAProfile,
		KeyUsage:         decision.KeyUsage,
		ExtendedKeyUsage: decision.ExtendedKeyUsage,
	}
	if csrInfo != nil {
		// With a CSR present the gateway signs the key it was given instead of
		// generating one, so no private key comes back and none is stored.
		issueReq.CsrPem = []byte(input.CSRPEM)
	}

	resp, err := gw.Client.IssueCertificate(c.Request.Context(), issueReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("gateway issuance failed: %v", err)})
		return
	}
	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "gateway reported success but returned no certificate"})
		return
	}

	// 5. Parse what the gateway returned rather than trusting its metadata.
	// A gateway that returns something other than a certificate must fail here,
	// not be recorded as ISSUED — that failure mode is exactly how a CSR ended
	// up stored as a certificate before.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("gateway returned data that is not a valid X.509 certificate: %v", err),
		})
		return
	}

	// 5b. Issue, then check — #30. CertPilot cannot enforce key usage or
	// extended key usage on a CA whose own profile decides them, and cannot
	// enforce anything on a public CA's validity cap. The only honest check
	// left is comparing what came back against what was asked.
	findings, err := issuance.VerifyConformance(decision, resp.Certificate.CertificatePem)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("issued certificate could not be checked for conformance: %v", err),
		})
		return
	}
	if blocking := issuance.Enforced(decision.Template, findings); len(blocking) > 0 {
		messages := make([]string, 0, len(blocking))
		for _, f := range blocking {
			messages = append(messages, f.Message)
		}
		// Best-effort. A gateway that cannot revoke, or a CA account without
		// revocation support, must not turn "this certificate was wrong" into
		// "and now nobody can be told about it" — the refusal below still
		// happens, and the certificate that should not exist is at least kept
		// out of the inventory even if it lives on at the CA a little longer.
		if _, revokeErr := gw.Client.RevokeCertificate(c.Request.Context(), &providerv1.RevokeCertificateRequest{
			CertificatePem:        resp.Certificate.CertificatePem,
			ProviderCertificateId: resp.ProviderCertificateId,
			ProviderConfig:        providerConfig,
		}); revokeErr != nil {
			slog.Warn("could not revoke a certificate that failed conformance under an ENFORCE template",
				"template", decision.Template.Slug, "error", revokeErr)
		}
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf(
				"template %q requires ENFORCE conformance and the CA did not honour the request: %s",
				decision.Template.Slug, strings.Join(messages, "; ")),
			"conformance_findings": blocking,
		})
		return
	}

	var chainPEM *string
	if len(resp.Certificate.ChainPem) > 0 {
		ch := string(resp.Certificate.ChainPem)
		chainPEM = &ch
	}

	// The private key is sealed before it touches the database. Without this
	// the certificate is unusable, since a certificate is only useful to
	// whoever holds the matching key.
	var privateKey *string
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		sealed, err := h.keyring.Encrypt(resp.Certificate.PrivateKeyPem, secrets.ContextCertificatePrivKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("failed to encrypt the private key; refusing to store it in the clear: %v", err),
			})
			return
		}
		privateKey = &sealed
	}

	userID := c.GetString(middleware.ContextUserID)
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	certPEM := string(resp.Certificate.CertificatePem)
	// The account the template pinned, not the one the request named — which
	// may be a different account, or none at all when a template was named
	// instead. Read from the decision rather than from the request, because
	// the request's copy is empty in exactly the case templates were added
	// for, and an empty string reaches a uuid column as `invalid input syntax
	// for type uuid` — after the CA has already signed.
	caAccountID := caAccount.ID

	// The rules this was issued under, recorded so renewal can ask whether they
	// still hold. The version and not only the id, because a template's rules
	// change and the record of which version governed this issuance must not.
	templateID := decision.Template.ID
	templateVersion := decision.Template.Version

	notBefore, notAfter := info.NotBefore, info.NotAfter

	keyCustody := store.KeyCustodyExternal
	if privateKey != nil {
		keyCustody = store.KeyCustodyCertPilot
	}

	certRecord := &store.Certificate{
		FingerprintSHA256:   info.FingerprintSHA256,
		CommonName:          info.CommonName,
		SANs:                info.SANs,
		SerialNumber:        info.SerialNumber,
		IssuerDN:            info.IssuerDN,
		NotBefore:           &notBefore,
		NotAfter:            &notAfter,
		DaysRemaining:       info.DaysRemaining,
		KeyType:             info.KeyType,
		KeySize:             info.KeySize,
		Status:              "ISSUED",
		AutoRenew:           input.AutoRenew,
		RenewalLeadDays:     input.RenewalLeadDays,
		CAAccountID:         &caAccountID,
		TemplateID:          &templateID,
		TemplateVersion:     &templateVersion,
		PrivateKeyEncrypted: privateKey,
		CertificatePEM:      &certPEM,
		ChainPEM:            chainPEM,
		DiscoveredVia:       "REQUESTED",
		Environment:         input.Environment,
		Team:                input.Team,
		CreatedBy:           createdBy,
		Metadata:            cleanedMetadata,
		// Stated rather than inferred. A CSR-signed certificate is REQUESTED
		// like any other, so provenance cannot answer "do we hold the key" —
		// and that is the question deciding whether an export is even offered.
		KeyCustody: keyCustody,
		// Non-blocking findings from #30 — validity shorter than asked, or a
		// subject field the CA added — reach here even under ENFORCE, because
		// neither was ever the class that setting refuses.
		ConformanceFindings: findings,
	}

	if err := h.store.CreateCertificate(c.Request.Context(), certRecord); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save certificate to store: %v", err)})
		return
	}

	// 6. Audit Log
	userEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.issued",
		EntityType: "certificate",
		EntityID:   &certRecord.ID,
		ActorID:    createdBy,
		ActorEmail: &userEmail,
		Details: fmt.Sprintf(`{"cn": %q, "gateway": %q, "serial": %q, "not_after": %q, "key_custody": %q}`,
			certRecord.CommonName, gw.Name, certRecord.SerialNumber,
			notAfter.Format(time.RFC3339), keyCustody),
	})

	h.broker.Publish(events.Event{
		Topic:    events.TopicCertIssued,
		Severity: events.SeverityInfo,
		EntityID: certRecord.ID,
		Payload: map[string]any{
			"common_name":    certRecord.CommonName,
			"serial_number":  certRecord.SerialNumber,
			"days_remaining": certRecord.DaysRemaining,
			"not_after":      notAfter.Format(time.RFC3339),
			"gateway":        gw.Name,
		},
	})

	var warnings []string
	if csrInfo != nil {
		if dropped := csrInfo.DroppedNames(); len(dropped) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"the signing request asked for %s, which this issuance path does not carry; the certificate covers DNS names only",
				strings.Join(dropped, ", ")))
		}
	}

	if len(violations) > 0 || len(warnings) > 0 {
		// Non-blocking violations were allowed through, so the response has to
		// say so — silently discarding them makes a policy that reports
		// nothing indistinguishable from a policy that found nothing.
		body := gin.H{"certificate": certRecord}
		if len(violations) > 0 {
			body["policy_violations"] = violations
		}
		if len(warnings) > 0 {
			body["warnings"] = warnings
		}
		c.JSON(http.StatusCreated, body)
		return
	}
	c.JSON(http.StatusCreated, certRecord)
}

// UpdateMetadataInput is what an operator may change on a certificate.
//
// Pointers, so an omitted field is left alone rather than cleared. A form that
// edits only the team must not blank the environment, and a client that knows
// about three of these fields must not erase the fourth.
type UpdateMetadataInput struct {
	Environment *string        `json:"environment"`
	Team        *string        `json:"team"`
	Tags        *[]string      `json:"tags"`
	Metadata    map[string]any `json:"metadata"`
}

// UpdateMetadata handles PATCH /api/v1/certificates/:id.
//
// The only mutable part of a certificate record. Everything else on it —
// serial, fingerprint, expiry, renewal state — is a fact about the certificate
// rather than a decision about it, and none of those are a person's to edit.
func (h *CertificateHandler) UpdateMetadata(c *gin.Context) {
	id := c.Param("id")

	existing, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var input UpdateMetadataInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	update := store.CertificateMetadataUpdate{Tags: input.Tags}

	if input.Environment != nil {
		environment, err := normalizeEnvironment(*input.Environment)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		update.Environment = &environment
	}
	if input.Team != nil {
		team := strings.TrimSpace(*input.Team)
		update.Team = &team
	}

	if input.Metadata != nil {
		fields, err := h.store.ListMetadataFields(c.Request.Context(), true)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Required is not enforced here. Marking a field required later must
		// not make every existing certificate unsaveable — an operator would
		// be unable to correct the team on a certificate because of an
		// unrelated new field somebody added this morning.
		cleaned, err := validateMetadata(fields, input.Metadata, false)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		update.Metadata = cleaned
	}

	updated, err := h.store.UpdateCertificateMetadata(c.Request.Context(), id, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.metadata_updated",
		EntityType: "certificate",
		EntityID:   &existing.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		Details:    fmt.Sprintf(`{"cn": %q}`, existing.CommonName),
	})

	c.JSON(http.StatusOK, updated)
}

// Renew handles POST /api/v1/certificates/:id/renew.
//
// Enqueues rather than renews. It used to call the gateway inline and return
// the renewed certificate, which read well and was wrong in three ways: an ACME
// order with a DNS challenge outlives the server's write timeout, so the caller
// got a truncated response for a renewal that was still running; a failure
// meant one attempt and no record of it; and a core that restarted mid-request
// left nothing behind at all.
//
// 202 with the job, so the caller has something to watch. A renewal already in
// flight returns the same job rather than starting a second one — two
// certificates issued because somebody clicked twice is a real way to spend a
// weekly rate limit.
func (h *CertificateHandler) Renew(c *gin.Context) {
	id := c.Param("id")

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if cert.CAAccountID == nil || *cert.CAAccountID == "" {
		// Caught here rather than three minutes later in a worker: a
		// certificate imported from a scan or a cloud store has no CA account
		// and no private key, so nothing can renew it, and saying so now is the
		// difference between an answer and a job that fails forever.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this certificate has no CA account, so nothing can renew it. " +
				"Certificates that were discovered rather than issued have to be replaced by issuing a new one",
		})
		return
	}
	// Refused here rather than in a worker, for the same reason: a renewal
	// would issue against a new key that whoever serves this certificate does
	// not have, and seal that key into a record whose key_custody says CertPilot
	// has none (#107). The caller gets the reason and the host to go to, not a
	// queued job that fails later.
	if err := renewal.KeyHeldElsewhere(c.Request.Context(), h.store, cert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	var actor, email *string
	if actorID != "" {
		actor = &actorID
	}
	if actorEmail != "" {
		email = &actorEmail
	}

	job := &store.RenewalJob{}
	created, err := h.renewals.Enqueue(c.Request.Context(), cert, store.RenewalReasonManual, actor, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	jobs, _, err := h.store.ListRenewalJobs(c.Request.Context(), store.RenewalJobFilter{
		CertificateID: id, OutstandingOnly: true, Limit: 1,
	})
	if err == nil && len(jobs) > 0 {
		job = jobs[0]
	}

	if !created {
		c.JSON(http.StatusAccepted, gin.H{
			"data":    job,
			"message": "A renewal for this certificate is already queued; this did not start a second one.",
		})
		return
	}

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.renewal_requested",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    actor,
		ActorEmail: email,
		Details:    fmt.Sprintf(`{"cn":%q,"job_id":%q}`, cert.CommonName, job.ID),
	})

	c.JSON(http.StatusAccepted, gin.H{
		"data":    job,
		"message": "Queued. Watch it at GET /api/v1/renewals/" + job.ID + ".",
	})
}

// PrivateKey handles GET /api/v1/certificates/:id/private-key.
//
// Retrieving a private key is deliberately a separate, admin-only, audited
// operation rather than a field on the certificate record. Listing certificates
// is something a dashboard does constantly; exporting a key is something a
// human should have to ask for and an auditor should be able to see.
func (h *CertificateHandler) PrivateKey(c *gin.Context) {
	id := c.Param("id")

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Read through the dedicated accessor. The record returned by
	// GetCertificate never carries the key — no list or detail query selects
	// the column — so the previous check against cert.PrivateKeyEncrypted was
	// always nil against PostgreSQL and this endpoint answered "no private key
	// is stored" for every certificate, including the ones whose keys it held.
	sealed, err := h.store.GetCertificatePrivateKey(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if sealed == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "no private key is stored for this certificate — it was either imported, discovered, or issued from a CSR whose key never left its host",
		})
		return
	}

	keyPEM, err := h.keyring.DecryptString(sealed, secrets.ContextCertificatePrivKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("failed to decrypt the stored private key: %v", err),
		})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.private_key_exported",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details:    fmt.Sprintf(`{"cn": %q, "serial": %q}`, cert.CommonName, cert.SerialNumber),
	})

	c.JSON(http.StatusOK, gin.H{
		"common_name":     cert.CommonName,
		"private_key_pem": keyPEM,
	})
}

// Delete handles DELETE /api/v1/certificates/:id.
//
// Deleting removes CertPilot's record and nothing else. It has never revoked
// anything, and while it was the only way to get rid of a certificate it was
// routinely used as though it did — which is how a compromised certificate
// could stop appearing in the estate while continuing to authenticate, valid
// until its own notAfter.
//
// It now refuses a certificate that is still live, and names the endpoint that
// does the thing the caller almost certainly meant. Stopping being watched is
// not the same as stopping being trusted, and only one of those is something a
// person can ask for by accident.
func (h *CertificateHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if cert == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such certificate"})
		return
	}

	// Expired certificates are safe to forget: they authenticate nothing.
	// Revoked ones are safe to forget: the CA has been told. Anything else is
	// still trusted by everything that trusts its issuer.
	expired := cert.NotAfter != nil && cert.NotAfter.Before(time.Now())
	if cert.Status != "REVOKED" && !expired && !boolQuery(c, "forget") {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this certificate is still valid, and deleting the record would not revoke it — " +
				"it would keep working while disappearing from the estate. Revoke it with " +
				"POST /certificates/" + id + "/revoke, or pass ?forget=true if you genuinely " +
				"want CertPilot to stop tracking a certificate that remains live",
			"status":    cert.Status,
			"not_after": cert.NotAfter,
		})
		return
	}

	if err := h.store.DeleteCertificate(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.deleted",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		// The status at deletion is recorded because it is the question an
		// incident review asks: was this forgotten because it was dealt with,
		// or forgotten while still live.
		Details: fmt.Sprintf(`{"cn": %q, "serial": %q, "status_at_deletion": %q, "forced": %t}`,
			cert.CommonName, cert.SerialNumber, cert.Status, boolQuery(c, "forget")),
	})

	c.JSON(http.StatusOK, gin.H{"message": "certificate deleted"})
}

// decryptCAConfig unseals a CA account configuration for a single outbound call.
//
// Records written before encryption existed are stored as plaintext JSON; those
// are passed through so an upgrade does not break every existing account, and
// they are re-sealed the next time the account is written.
func (h *CertificateHandler) decryptCAConfig(acc *store.CAAccount) (string, error) {
	return decryptCAConfig(h.keyring, acc)
}

func decryptCAConfig(kr *secrets.Keyring, acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := kr.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}

// keysOf is which metadata fields a request answered, for the template's own
// required list. The values have already been validated; this is about
// presence.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// custodyFor says where the private key will live.
//
// A request carrying a CSR keeps its key: the requester generated it and it
// never reaches here, which is EXTERNAL from this side. Everything else is
// generated by the gateway and sealed here.
func custodyFor(csr *x509util.CSRInfo) string {
	if csr != nil {
		return store.KeyCustodyExternal
	}
	return store.KeyCustodyCertPilot
}

// writeResolveFailure turns a resolver error into the right status.
//
// The distinction is the point: a malformed request is the caller's to fix and
// a refused one is an operator's. Reporting both as 400 tells somebody to
// correct a request that was already correct, and reporting both as 403 sends
// them to an administrator over a typo.
func writeResolveFailure(c *gin.Context, err error) {
	refusal, ok := issuance.AsRefusal(err)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	switch refusal.Rung {
	case issuance.RungRequest:
		c.JSON(http.StatusBadRequest, gin.H{"error": refusal.Message})
	case issuance.RungPolicy:
		c.JSON(http.StatusForbidden, gin.H{
			"error":      "Certificate request blocked by security policy",
			"detail":     refusal.Message,
			"violations": refusal.Violations,
		})
	default:
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "Certificate request refused by its template",
			"detail": refusal.Message,
		})
	}
}
