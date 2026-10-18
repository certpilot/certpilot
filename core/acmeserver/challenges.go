package acmeserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// HTTP-01 and DNS-01 (RFC 8555 §8), for credentials that require proof of
// control. A client proves each name by publishing its key authorization, the
// challenge token and its account key's thumbprint, where only somebody in
// charge of the name could: a file on the web server the name points at, or a
// TXT record in its zone. The core then looks, and compares exactly.

// NameResolver is what validation looks names up with. *net.Resolver is one.
type NameResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validation is how challenges are checked. The zero value is RFC 8555's:
// HTTP-01 on port 80, the system resolver, and ten seconds per attempt.
type Validation struct {
	HTTPPort int
	// TLSPort is where TLS-ALPN-01 connects, and the only https port an
	// HTTP-01 redirect may go to. 443 when unset.
	TLSPort  int
	Resolver NameResolver
	Timeout  time.Duration
}

func (v Validation) tlsPort() int {
	if v.TLSPort == 0 {
		return 443
	}
	return v.TLSPort
}

func (v Validation) port() int {
	if v.HTTPPort == 0 {
		return 80
	}
	return v.HTTPPort
}

func (v Validation) resolver() NameResolver {
	if v.Resolver == nil {
		return net.DefaultResolver
	}
	return v.Resolver
}

func (v Validation) timeout() time.Duration {
	if v.Timeout == 0 {
		return 10 * time.Second
	}
	return v.Timeout
}

// maxChallengeBody bounds what is read from an HTTP-01 response. A key
// authorization is under a hundred bytes.
const maxChallengeBody = 1024

// challengeFailure is a validation that did not hold, with the ACME problem
// type the client is told.
type challengeFailure struct {
	kind, detail string
}

func (e *challengeFailure) Error() string { return e.detail }

func failed(kind, format string, args ...any) error {
	return &challengeFailure{kind: kind, detail: fmt.Sprintf(format, args...)}
}

// keyAuthorization is RFC 8555 §8.1's: the token and the account key's
// thumbprint.
func keyAuthorization(token string, account *store.ACMEAccount) string {
	return token + "." + account.JWKThumbprint
}

// maxRedirects is how many redirects an HTTP-01 fetch follows, as many as
// Let's Encrypt does.
const maxRedirects = 10

// redirectRefused is a redirect HTTP-01 would not follow.
type redirectRefused struct{ to, why string }

func (e *redirectRefused) Error() string {
	return "a redirect to " + e.to + " was not followed: " + e.why
}

// dial connects to host:port, with host looked up through the validation
// resolver, trying each address in turn.
func (v Validation) dial(ctx context.Context, network, host, port string) (net.Conn, error) {
	addrs, err := v.resolver().LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, failed("dns", "%s does not resolve", host)
	}
	var d net.Dialer
	var last error
	for _, addr := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(addr, port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

// checkHTTP01 fetches http://<name>/.well-known/acme-challenge/<token>.
//
// Redirects are followed, as RFC 8555 §8.3 says, which is what lets HTTP-01
// work through an http-to-https redirect. Only to http or https, only on the
// two ports a challenge may use anyway, and only to a name: a redirect is a
// web server telling the core where to connect, and a core inside an
// organisation's network must not become a way to reach whatever address that
// server names.
func (v Validation) checkHTTP01(ctx context.Context, name, token, want string) error {
	if _, err := v.resolver().LookupHost(ctx, name); err != nil {
		return failed("dns", "%s does not resolve", name)
	}
	httpPort, tlsPort := strconv.Itoa(v.port()), strconv.Itoa(v.tlsPort())
	client := &http.Client{
		Timeout: v.timeout(),
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				// The URL's default ports stand for the challenge ports.
				switch port {
				case "80":
					port = httpPort
				case "443":
					port = tlsPort
				}
				return v.dial(ctx, network, host, port)
			},
			// RFC 8555 §8.3: a redirect to https is followed without checking
			// the certificate, which is what HTTP-01 proves and TLS does not.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see above
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			to := req.URL.String()
			if len(via) > maxRedirects {
				return &redirectRefused{to, fmt.Sprintf("more than %d redirects", maxRedirects)}
			}
			if net.ParseIP(req.URL.Hostname()) != nil {
				return &redirectRefused{to, "it names an address, not a name"}
			}
			switch req.URL.Scheme {
			case "http":
				if p := req.URL.Port(); p != "" && p != httpPort {
					return &redirectRefused{to, "http redirects may only go to port " + httpPort}
				}
			case "https":
				if p := req.URL.Port(); p != "" && p != tlsPort {
					return &redirectRefused{to, "https redirects may only go to port " + tlsPort}
				}
			default:
				return &redirectRefused{to, "only http and https are followed"}
			}
			return nil
		},
	}

	url := "http://" + name + "/.well-known/acme-challenge/" + token
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return failed("malformed", "%s is not a name that can be fetched", name)
	}
	resp, err := client.Do(req)
	if err != nil {
		var refused *redirectRefused
		if errors.As(err, &refused) {
			return failed("incorrectResponse", "%s", refused.Error())
		}
		return failed("connection", "could not fetch %s on port %s", url, httpPort)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return failed("incorrectResponse", "%s answered HTTP %d", url, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody+1))
	// RFC 8555 §8.3: trailing whitespace is ignored, which is how a file
	// written with a newline still counts.
	if strings.TrimSpace(string(body)) != want {
		return failed("incorrectResponse", "%s did not answer with this account's key authorization", url)
	}
	return nil
}

// idPeACMEIdentifier is RFC 8737's id-pe-acmeIdentifier.
var idPeACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// checkTLSALPN01 connects to <name> on the TLS port asking for acme-tls/1, and
// checks the certificate it is shown (RFC 8737 §3): for exactly that name, and
// carrying the key authorization's digest in a critical acmeIdentifier
// extension.
func (v Validation) checkTLSALPN01(ctx context.Context, name, want string) error {
	raw, err := v.dial(ctx, "tcp", name, strconv.Itoa(v.tlsPort()))
	if err != nil {
		var cf *challengeFailure
		if errors.As(err, &cf) {
			return err
		}
		return failed("connection", "could not connect to %s on port %d", name, v.tlsPort())
	}
	defer raw.Close()
	// Not verified against any root: the certificate is a self-signed one made
	// for the challenge, and what is checked is its extension.
	conn := tls.Client(raw, &tls.Config{ //nolint:gosec // see above
		ServerName: name, NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return failed("tls", "the TLS handshake with %s failed", name)
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "acme-tls/1" {
		return failed("incorrectResponse", "%s did not negotiate acme-tls/1", name)
	}
	if len(state.PeerCertificates) == 0 {
		return failed("incorrectResponse", "%s presented no certificate", name)
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.DNSNames) != 1 || !strings.EqualFold(leaf.DNSNames[0], name) ||
		len(leaf.IPAddresses) > 0 || len(leaf.EmailAddresses) > 0 || len(leaf.URIs) > 0 {
		return failed("incorrectResponse", "the certificate %s presented is not for exactly %s", name, name)
	}
	sum := sha256.Sum256([]byte(want))
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(idPeACMEIdentifier) {
			continue
		}
		var digest []byte
		if rest, err := asn1.Unmarshal(ext.Value, &digest); err != nil || len(rest) > 0 || !ext.Critical {
			return failed("incorrectResponse", "the certificate %s presented has a malformed acmeIdentifier", name)
		}
		if !bytes.Equal(digest, sum[:]) {
			return failed("incorrectResponse", "the certificate %s presented is not for this account's key authorization", name)
		}
		return nil
	}
	return failed("incorrectResponse", "the certificate %s presented has no acmeIdentifier extension", name)
}

// checkDNS01 looks for the key authorization's digest in
// _acme-challenge.<name>.
func (v Validation) checkDNS01(ctx context.Context, name, want string) error {
	sum := sha256.Sum256([]byte(want))
	digest := base64.RawURLEncoding.EncodeToString(sum[:])
	record := "_acme-challenge." + name
	values, err := v.resolver().LookupTXT(ctx, record)
	if err != nil {
		return failed("dns", "no TXT record at %s", record)
	}
	for _, value := range values {
		if value == digest {
			return nil
		}
	}
	return failed("incorrectResponse", "no TXT record at %s holds this account's key authorization", record)
}

// newToken is a challenge token: 128 bits, base64url, as RFC 8555 §8.1 asks.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// requiresProof reports whether an account's credential requires challenges.
func (s *Server) requiresProof(c *gin.Context, account *store.ACMEAccount) (bool, error) {
	cred, err := s.cfg.Store.GetACMEEABCredential(c.Request.Context(), account.EABID)
	if err != nil {
		return false, err
	}
	return cred.RequireChallenge, nil
}

// createAuthorizations stores one pending authorization per name.
func (s *Server) createAuthorizations(c *gin.Context, order *store.ACMEOrder) error {
	for i, id := range order.Identifiers {
		token, err := newToken()
		if err != nil {
			return err
		}
		value, wildcard := id.Value, false
		if strings.HasPrefix(value, "*.") {
			value, wildcard = strings.TrimPrefix(value, "*."), true
		}
		if err := s.cfg.Store.CreateACMEAuthorization(c.Request.Context(), &store.ACMEAuthorization{
			OrderID: order.ID, Index: i, Value: value, Wildcard: wildcard,
			Status: store.ACMEAuthzPending, Token: token, ExpiresAt: order.ExpiresAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

// challengeTypes are those an authorization offers. A wildcard can only use
// DNS-01 (RFC 8555 §8.3, RFC 8737 §3): one server answering says nothing
// about every name under it.
func challengeTypes(a *store.ACMEAuthorization) []string {
	if a.Wildcard {
		return []string{"dns-01"}
	}
	return []string{"http-01", "dns-01", "tls-alpn-01"}
}

func (s *Server) challengeURL(c *gin.Context, tpl *store.CertificateTemplate, a *store.ACMEAuthorization, kind string) string {
	return s.base(c, tpl.Slug) + "/chall/" + a.OrderID + "/" + strconv.Itoa(a.Index) + "/" + kind
}

func (s *Server) authzURL(c *gin.Context, tpl *store.CertificateTemplate, a *store.ACMEAuthorization) string {
	return s.base(c, tpl.Slug) + "/authz/" + a.OrderID + "/" + strconv.Itoa(a.Index)
}

// challengeJSON is one challenge as RFC 8555 §8 shows it. Its status follows
// the authorization: the challenge that decided it is valid or invalid, and
// the others stay pending.
func (s *Server) challengeJSON(c *gin.Context, tpl *store.CertificateTemplate, a *store.ACMEAuthorization, kind string) gin.H {
	out := gin.H{"type": kind, "url": s.challengeURL(c, tpl, a, kind), "token": a.Token, "status": "pending"}
	if a.ValidatedWith == kind {
		out["status"] = a.Status
		if a.ValidatedAt != nil {
			out["validated"] = a.ValidatedAt.UTC().Format(time.RFC3339)
		}
		if a.Error != "" {
			out["error"] = json.RawMessage(a.Error)
		}
	}
	return out
}

func (s *Server) writeStoredAuthorization(c *gin.Context, tpl *store.CertificateTemplate, a *store.ACMEAuthorization) {
	challenges := []gin.H{}
	for _, kind := range challengeTypes(a) {
		challenges = append(challenges, s.challengeJSON(c, tpl, a, kind))
	}
	out := gin.H{
		"identifier": store.ACMEIdentifier{Type: "dns", Value: a.Value},
		"status":     a.Status,
		"expires":    a.ExpiresAt.UTC().Format(time.RFC3339),
		"challenges": challenges,
	}
	if a.Wildcard {
		out["wildcard"] = true
	}
	c.JSON(http.StatusOK, out)
}

// storedAuthorization returns an order's stored authorization at index, or
// nil when the order's are derived rather than stored.
func (s *Server) storedAuthorization(c *gin.Context, order *store.ACMEOrder, index int) (*store.ACMEAuthorization, []*store.ACMEAuthorization, error) {
	all, err := s.cfg.Store.ListACMEAuthorizations(c.Request.Context(), order.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, a := range all {
		if a.Index == index {
			return a, all, nil
		}
	}
	return nil, all, nil
}

// respondToChallenge handles POST /acme/<template>/chall/<order>/<index>/<type>:
// the client saying it has published the answer, and the core looking.
//
// Checked while the client waits, rather than queued: one look at one name is
// quick, and the answer is then on the authorization by the time the client
// polls it.
func (s *Server) respondToChallenge(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, byKID)
	if req == nil {
		return
	}
	order := s.ownedOrder(c, req, c.Param("order"))
	if order == nil {
		return
	}
	index, err := strconv.Atoi(c.Param("index"))
	if err != nil {
		s.fail(c, http.StatusNotFound, "malformed", "there is no such challenge")
		return
	}
	authz, all, err := s.storedAuthorization(c, order, index)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not read the authorization")
		return
	}
	kind := c.Param("type")
	offered := false
	if authz != nil {
		for _, t := range challengeTypes(authz) {
			offered = offered || t == kind
		}
	}
	if !offered {
		s.fail(c, http.StatusNotFound, "malformed", "there is no such challenge")
		return
	}
	c.Header("Link", "<"+s.authzURL(c, tpl, authz)+`>;rel="up"`)

	// Answered again, not validated again: an authorization is decided once.
	if authz.Status != store.ACMEAuthzPending || order.Status != store.ACMEOrderPending {
		c.JSON(http.StatusOK, s.challengeJSON(c, tpl, authz, kind))
		return
	}

	now := s.cfg.Now()
	var proof error
	if !authz.ExpiresAt.After(now) {
		proof = failed("unauthorized", "this authorization has expired")
	} else {
		ctx, cancel := context.WithTimeout(c.Request.Context(), s.cfg.Validation.timeout())
		want := keyAuthorization(authz.Token, req.account)
		switch kind {
		case "http-01":
			proof = s.cfg.Validation.checkHTTP01(ctx, authz.Value, authz.Token, want)
		case "tls-alpn-01":
			proof = s.cfg.Validation.checkTLSALPN01(ctx, authz.Value, want)
		default:
			proof = s.cfg.Validation.checkDNS01(ctx, authz.Value, want)
		}
		cancel()
	}

	authz.ValidatedWith = kind
	if proof == nil {
		authz.Status, authz.ValidatedAt = store.ACMEAuthzValid, &now
	} else {
		var cf *challengeFailure
		kindOf, detail := "serverInternal", proof.Error()
		if errors.As(proof, &cf) {
			kindOf = cf.kind
		}
		raw, _ := json.Marshal(problem{Type: problemNS + kindOf, Detail: detail, Status: http.StatusForbidden})
		authz.Status, authz.Error = store.ACMEAuthzInvalid, string(raw)
	}
	if err := s.cfg.Store.UpdateACMEAuthorization(c.Request.Context(), authz); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not record the result")
		return
	}

	// The order follows its authorizations: ready when every one is valid,
	// invalid as soon as one is not (RFC 8555 §7.1.6).
	switch {
	case authz.Status == store.ACMEAuthzInvalid:
		order.Status, order.Error = store.ACMEOrderInvalid, authz.Error
	case allValid(all, authz):
		order.Status = store.ACMEOrderReady
	}
	if order.Status != store.ACMEOrderPending {
		if err := s.cfg.Store.UpdateACMEOrder(c.Request.Context(), order); err != nil {
			s.fail(c, http.StatusInternalServerError, "serverInternal", "could not update the order")
			return
		}
	}
	s.audit(c, "acme.challenge_"+authz.Status, req.account.ID, req.account.ID, gin.H{
		"template": tpl.Slug, "order": order.ID, "name": authz.Value, "challenge": kind,
	})
	c.JSON(http.StatusOK, s.challengeJSON(c, tpl, authz, kind))
}

// allValid reports whether every authorization is valid, counting just as
// the one just decided.
func allValid(all []*store.ACMEAuthorization, just *store.ACMEAuthorization) bool {
	for _, a := range all {
		status := a.Status
		if a.ID == just.ID {
			status = just.Status
		}
		if status != store.ACMEAuthzValid {
			return false
		}
	}
	return true
}
