package acmeserver

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot-gateway-sdk/x509util"
	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

const (
	// orderLife is how long a client has to finalise an order. A client
	// finalises seconds after ordering; a day covers one that was interrupted.
	orderLife = 24 * time.Hour
	// maxIdentifiers bounds one order, as the agent bounds one request.
	maxIdentifiers = 100
)

type orderJSON struct {
	Status         string                 `json:"status"`
	Expires        string                 `json:"expires"`
	Identifiers    []store.ACMEIdentifier `json:"identifiers"`
	Authorizations []string               `json:"authorizations"`
	Finalize       string                 `json:"finalize"`
	Certificate    string                 `json:"certificate,omitempty"`
	Error          json.RawMessage        `json:"error,omitempty"`
}

func (s *Server) orderURL(c *gin.Context, tpl *store.CertificateTemplate, id string) string {
	return s.base(c, tpl.Slug) + "/order/" + id
}

func (s *Server) writeOrder(c *gin.Context, status int, tpl *store.CertificateTemplate, o *store.ACMEOrder) {
	base := s.base(c, tpl.Slug)
	out := orderJSON{
		Status:      o.Status,
		Expires:     o.ExpiresAt.UTC().Format(time.RFC3339),
		Identifiers: o.Identifiers,
		Finalize:    base + "/order/" + o.ID + "/finalize",
	}
	for i := range o.Identifiers {
		out.Authorizations = append(out.Authorizations, base+"/authz/"+o.ID+"/"+strconv.Itoa(i))
	}
	if o.Status == store.ACMEOrderValid {
		out.Certificate = base + "/cert/" + o.ID
	}
	if o.Error != "" {
		out.Error = json.RawMessage(o.Error)
	}
	c.Header("Location", s.orderURL(c, tpl, o.ID))
	c.JSON(status, out)
}

// newOrder handles POST /acme/<template>/new-order.
//
// The order is ready as soon as it exists. The account's credential was made
// for this template, so the template's own name rules are the authorisation,
// and those are applied at finalize, through the resolver, with the CSR in
// hand. Checking them here as well would need a second, partial copy of the
// rules, and a partial copy is how the agent once got a looser rulebook than a
// person.
func (s *Server) newOrder(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}

	var payload struct {
		Identifiers []store.ACMEIdentifier `json:"identifiers"`
		NotBefore   string                 `json:"notBefore"`
		NotAfter    string                 `json:"notAfter"`
	}
	if err := json.Unmarshal(req.payload, &payload); err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the payload is not valid JSON")
		return
	}
	if payload.NotBefore != "" || payload.NotAfter != "" {
		s.fail(c, http.StatusBadRequest, "malformed",
			"this endpoint does not accept notBefore or notAfter; the template "+tpl.Slug+" sets the lifetime")
		return
	}

	identifiers, problem := cleanIdentifiers(payload.Identifiers)
	if problem != "" {
		kind := "malformed"
		if strings.HasPrefix(problem, "only dns") {
			kind = "unsupportedIdentifier"
		}
		s.fail(c, http.StatusBadRequest, kind, problem)
		return
	}

	order := &store.ACMEOrder{
		AccountID:   req.account.ID,
		Status:      store.ACMEOrderReady,
		Identifiers: identifiers,
		ExpiresAt:   s.cfg.Now().Add(orderLife),
	}
	if err := s.cfg.Store.CreateACMEOrder(c.Request.Context(), order); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not create the order")
		return
	}
	s.writeOrder(c, http.StatusCreated, tpl, order)
}

// cleanIdentifiers lower-cases and de-duplicates the names, and says what is
// wrong when they cannot be used.
func cleanIdentifiers(in []store.ACMEIdentifier) ([]store.ACMEIdentifier, string) {
	if len(in) == 0 {
		return nil, "an order needs at least one identifier"
	}
	if len(in) > maxIdentifiers {
		return nil, fmt.Sprintf("an order may name at most %d identifiers", maxIdentifiers)
	}
	seen := map[string]bool{}
	out := make([]store.ACMEIdentifier, 0, len(in))
	for _, id := range in {
		if id.Type != "dns" {
			return nil, fmt.Sprintf("only dns identifiers can be ordered here, not %q", id.Type)
		}
		value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(id.Value), "."))
		if value == "" || strings.ContainsAny(value, " /\\@") {
			return nil, fmt.Sprintf("%q is not a DNS name", id.Value)
		}
		if !seen[value] {
			seen[value] = true
			out = append(out, store.ACMEIdentifier{Type: "dns", Value: value})
		}
	}
	return out, ""
}

// ownedOrder loads the order named in the URL and checks it belongs to the
// account that signed the request. Writes the refusal and returns nil when not.
func (s *Server) ownedOrder(c *gin.Context, req *signed, id string) *store.ACMEOrder {
	order, err := s.cfg.Store.GetACMEOrder(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, http.StatusNotFound, "malformed", "there is no such order")
		return nil
	}
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not read the order")
		return nil
	}
	if order.AccountID != req.account.ID {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "that order belongs to another account")
		return nil
	}
	return order
}

// order handles POST-as-GET /acme/<template>/order/<id>.
func (s *Server) order(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	order := s.ownedOrder(c, req, c.Param("id"))
	if order == nil {
		return
	}
	s.writeOrder(c, http.StatusOK, tpl, order)
}

// accountOrders handles POST-as-GET /acme/<template>/account/<id>/orders.
func (s *Server) accountOrders(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	if req.account.ID != c.Param("id") {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "that is not your account")
		return
	}
	orders, err := s.cfg.Store.ListACMEOrdersByAccount(c.Request.Context(), req.account.ID)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not list the orders")
		return
	}
	urls := make([]string, 0, len(orders))
	for _, o := range orders {
		urls = append(urls, s.orderURL(c, tpl, o.ID))
	}
	c.JSON(http.StatusOK, gin.H{"orders": urls})
}

// authorization handles POST-as-GET /acme/<template>/authz/<order>/<index>.
//
// Valid from the start, with no challenges: the credential that made this
// account is the authorisation, and the template bounds what it covers.
func (s *Server) authorization(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	order := s.ownedOrder(c, req, c.Param("order"))
	if order == nil {
		return
	}
	i, err := strconv.Atoi(c.Param("index"))
	if err != nil || i < 0 || i >= len(order.Identifiers) {
		s.fail(c, http.StatusNotFound, "malformed", "there is no such authorization")
		return
	}
	id := order.Identifiers[i]
	out := gin.H{
		"identifier": id,
		"status":     "valid",
		"expires":    order.ExpiresAt.UTC().Format(time.RFC3339),
		"challenges": []any{},
	}
	// RFC 8555 §7.1.4: a wildcard is reported without its "*." and flagged.
	if strings.HasPrefix(id.Value, "*.") {
		out["identifier"] = store.ACMEIdentifier{Type: "dns", Value: strings.TrimPrefix(id.Value, "*.")}
		out["wildcard"] = true
	}
	c.JSON(http.StatusOK, out)
}

// finalize handles POST /acme/<template>/order/<id>/finalize.
//
// The CSR goes through the resolver, so the template's and the estate's rules
// apply exactly as they do to a request made in the console, then through the
// same signer as the agent's requests. The client generated the key, so the
// certificate is recorded as EXTERNAL and never renewed here: the client
// renews it by ordering again.
func (s *Server) finalize(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	ctx := c.Request.Context()
	order := s.ownedOrder(c, req, c.Param("id"))
	if order == nil {
		return
	}
	if order.Status != store.ACMEOrderReady || !order.ExpiresAt.After(s.cfg.Now()) {
		s.fail(c, http.StatusForbidden, "orderNotReady", "this order is "+order.Status+" and cannot be finalized")
		return
	}

	var payload struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(req.payload, &payload); err != nil || payload.CSR == "" {
		s.fail(c, http.StatusBadRequest, "malformed", "the payload must carry a csr")
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "badCSR", "the csr is not base64url")
		return
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		s.fail(c, http.StatusBadRequest, "badCSR", "the csr could not be parsed, or is not signed by its own key")
		return
	}
	if problem := csrMatchesOrder(csr, order.Identifiers); problem != "" {
		s.fail(c, http.StatusBadRequest, "badCSR", problem)
		return
	}

	// Claimed before the CA is asked, so a second finalize, here or on another
	// replica, is refused instead of issuing a second certificate.
	claimed, err := s.cfg.Store.ClaimACMEOrderForFinalize(ctx, order.ID)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not claim the order")
		return
	}
	if !claimed {
		s.fail(c, http.StatusForbidden, "orderNotReady", "this order is already being finalized")
		return
	}

	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	csrInfo, err := x509util.ParseCSRPEM([]byte(csrPEM))
	if err != nil {
		s.invalidate(c, tpl, order, http.StatusBadRequest, "badCSR", err.Error())
		return
	}

	decision, err := s.cfg.Resolver.Resolve(ctx, issuance.Request{
		TemplateRef: tpl.ID,
		CSR:         csrInfo,
		// The client generated this key and CertPilot has never seen it.
		KeyCustody: store.KeyCustodyExternal,
	})
	if err != nil {
		kind := "rejectedIdentifier"
		if refusal, ok := issuance.AsRefusal(err); ok && refusal.Rung == issuance.RungRequest {
			kind = "badCSR"
		} else if !ok {
			s.invalidate(c, tpl, order, http.StatusInternalServerError, "serverInternal", err.Error())
			return
		}
		s.invalidate(c, tpl, order, http.StatusForbidden, kind, err.Error())
		return
	}

	// From here a failure is the order's, not the request's. It goes back as
	// the order, invalid with its error, as RFC 8555 §7.4 describes. Answered
	// as a 500 instead, clients retry it, and the retry is told the order is
	// not ready, which hides why.
	signed, err := s.cfg.Signer.SignCSR(ctx, decision, csrPEM)
	if err != nil {
		s.orderFailed(c, tpl, order, err.Error())
		return
	}

	cert, err := s.record(c, req, tpl, decision, signed)
	if err != nil {
		s.orderFailed(c, tpl, order, "the certificate was issued and could not be recorded")
		return
	}

	order.Status, order.CertificateID = store.ACMEOrderValid, &cert.ID
	if err := s.cfg.Store.UpdateACMEOrder(ctx, order); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not update the order")
		return
	}
	s.writeOrder(c, http.StatusOK, tpl, order)
}

// invalidate ends an order with the problem the client is about to be told.
func (s *Server) invalidate(c *gin.Context, tpl *store.CertificateTemplate, order *store.ACMEOrder, status int, kind, detail string) {
	raw, _ := json.Marshal(problem{Type: problemNS + kind, Detail: detail, Status: status})
	order.Status, order.Error = store.ACMEOrderInvalid, string(raw)
	_ = s.cfg.Store.UpdateACMEOrder(c.Request.Context(), order)
	s.fail(c, status, kind, detail)
}

// orderFailed ends an order whose issuance failed and returns it.
func (s *Server) orderFailed(c *gin.Context, tpl *store.CertificateTemplate, order *store.ACMEOrder, detail string) {
	raw, _ := json.Marshal(problem{Type: problemNS + "serverInternal", Detail: detail, Status: http.StatusInternalServerError})
	order.Status, order.Error = store.ACMEOrderInvalid, string(raw)
	if err := s.cfg.Store.UpdateACMEOrder(c.Request.Context(), order); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", detail)
		return
	}
	s.writeOrder(c, http.StatusOK, tpl, order)
}

// csrMatchesOrder checks that a CSR asks for exactly the names ordered. RFC
// 8555 §7.4 leaves a server free to refuse anything else, and anything else
// would be names nobody ordered.
func csrMatchesOrder(csr *x509.CertificateRequest, ordered []store.ACMEIdentifier) string {
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return "the csr may only carry DNS names"
	}
	asked := map[string]bool{}
	for _, name := range csr.DNSNames {
		asked[strings.ToLower(name)] = true
	}
	if cn := strings.ToLower(csr.Subject.CommonName); cn != "" {
		asked[cn] = true
	}
	want := map[string]bool{}
	for _, id := range ordered {
		want[id.Value] = true
	}
	if len(asked) != len(want) {
		return fmt.Sprintf("the csr names %s and the order is for %s", list(asked), list(want))
	}
	for name := range asked {
		if !want[name] {
			return fmt.Sprintf("the csr names %s and the order is for %s", list(asked), list(want))
		}
	}
	return ""
}

func list(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// record writes the certificate to the inventory, with its provenance and its
// custody stated.
func (s *Server) record(c *gin.Context, req *signed, tpl *store.CertificateTemplate,
	d *issuance.Decision, signed *issuance.Signed) (*store.Certificate, error) {

	info := signed.Info
	notBefore, notAfter := info.NotBefore, info.NotAfter
	certPEM := string(signed.CertificatePEM)
	accountID := d.Account.ID
	templateID, templateVersion := d.Template.ID, d.Template.Version

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
		// The client renews it by ordering again. The core holds no key, so a
		// renewal here would fail on every attempt (#107).
		AutoRenew:           false,
		RenewalLeadDays:     d.RenewBeforeDays,
		CAAccountID:         &accountID,
		TemplateID:          &templateID,
		TemplateVersion:     &templateVersion,
		CertificatePEM:      &certPEM,
		DiscoveredVia:       "ACME",
		KeyCustody:          store.KeyCustodyExternal,
		Environment:         d.Environment,
		Team:                d.Team,
		ConformanceFindings: signed.Findings,
	}
	if len(signed.ChainPEM) > 0 {
		chain := string(signed.ChainPEM)
		cert.ChainPEM = &chain
	}
	if err := s.cfg.Store.CreateCertificate(c.Request.Context(), cert); err != nil {
		return nil, err
	}

	s.audit(c, "cert.issued_via_acme", req.account.ID, req.account.ID, gin.H{
		"certificate": cert.ID, "cn": cert.CommonName, "names": cert.SANs,
		"template": tpl.Slug, "serial": cert.SerialNumber, "key_custody": cert.KeyCustody,
	})
	if s.cfg.Broker != nil {
		s.cfg.Broker.Publish(events.Event{
			Topic:    events.TopicCertIssued,
			Severity: events.SeverityInfo,
			EntityID: cert.ID,
			Payload: map[string]any{
				"common_name": cert.CommonName,
				"not_after":   notAfter.Format(time.RFC3339),
				"gateway":     signed.Gateway + " (ACME, key held by the client)",
			},
		})
	}
	return cert, nil
}

// certificate handles POST-as-GET /acme/<template>/cert/<order>.
func (s *Server) certificate(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	order := s.ownedOrder(c, req, c.Param("order"))
	if order == nil {
		return
	}
	if order.Status != store.ACMEOrderValid || order.CertificateID == nil {
		s.fail(c, http.StatusNotFound, "malformed", "this order has no certificate")
		return
	}
	cert, err := s.cfg.Store.GetCertificate(c.Request.Context(), *order.CertificateID)
	if err != nil || cert.CertificatePEM == nil {
		s.fail(c, http.StatusNotFound, "malformed", "the certificate is no longer available")
		return
	}
	chain := *cert.CertificatePEM
	if cert.ChainPEM != nil {
		chain = strings.TrimRight(chain, "\n") + "\n" + *cert.ChainPEM
	}
	c.Data(http.StatusOK, "application/pem-certificate-chain", []byte(chain))
}
