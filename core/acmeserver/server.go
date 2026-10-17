// Package acmeserver serves ACME (RFC 8555) from the core, so that certbot,
// acme.sh, win-acme, Caddy and the rest can get certificates from CertPilot
// without the host agent (#140).
//
// It is a third way into the same issuance path. The REST API and the agent
// API already send every request through issuance.Resolver, which applies the
// template, the policy and the CA pinning. An ACME order does the same, so a
// certificate obtained this way is held to exactly the rules one requested in
// the console is, and is recorded the same way: the client generated the key,
// so it is key_custody EXTERNAL and the core never renews it.
//
// One directory per template, at /acme/<template-slug>/directory. A template
// already pins its CA, its allowed names and its validity, so the template is
// the unit an administrator hands out access to.
//
// Registration is closed. An account can only be made with an External Account
// Binding credential an administrator created for that template.
package acmeserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// Config is what the server needs from the rest of the core.
type Config struct {
	Store   store.Store
	Keyring *secrets.Keyring
	// ExternalURL is the address clients reach this core on, such as
	// https://certpilot.example.com. Every URL the server hands out is built
	// from it, and a request is refused unless it was signed for the URL the
	// server would have handed out. Empty derives it from each request, which
	// is right for a core reached directly and wrong behind a proxy that
	// changes the scheme or host.
	ExternalURL string
	// Now is replaceable so tests can move the clock.
	Now func() time.Time
}

// Server holds the ACME endpoints.
type Server struct {
	cfg Config
}

// New creates a server.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg}
}

const (
	ctxTemplate = "acme.template"
	problemNS   = "urn:ietf:params:acme:error:"
)

// Register mounts the endpoints. They are public in the HTTP sense: an ACME
// client has no session. Every request that changes anything is authenticated
// by the signature on its body instead.
func (s *Server) Register(engine *gin.Engine) {
	g := engine.Group("/acme/:template", s.perRequest)
	g.GET("/directory", s.directory)
	g.HEAD("/directory", s.directory)
	g.GET("/new-nonce", s.newNonce)
	g.HEAD("/new-nonce", s.newNonce)
	g.POST("/new-account", s.newAccount)
	g.POST("/new-order", s.newOrderNotYet)
	g.POST("/account/:id", s.account)
}

// problem is an RFC 7807 document with the ACME error namespace.
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (s *Server) fail(c *gin.Context, status int, kind, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, problem{Type: problemNS + kind, Detail: detail, Status: status})
}

// Origin is the scheme and host clients reach this server on: the configured
// external URL when there is one, otherwise what the request itself says.
func Origin(externalURL string, r *http.Request) string {
	if externalURL != "" {
		return strings.TrimRight(externalURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// DirectoryURL is the address of a template's ACME directory.
func DirectoryURL(externalURL string, r *http.Request, slug string) string {
	return Origin(externalURL, r) + "/acme/" + slug + "/directory"
}

func (s *Server) origin(c *gin.Context) string {
	return Origin(s.cfg.ExternalURL, c.Request)
}

func (s *Server) base(c *gin.Context, slug string) string {
	return s.origin(c) + "/acme/" + slug
}

// perRequest resolves the template and gives every response a fresh nonce,
// errors included, because a client that is told its nonce was bad needs
// another one to retry with.
func (s *Server) perRequest(c *gin.Context) {
	slug := c.Param("template")
	tpl, err := s.cfg.Store.GetCertificateTemplateBySlug(c.Request.Context(), slug)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not read the template")
		return
	}
	// One answer for a template that does not exist and one that is switched
	// off, so the endpoint does not list which slugs are real.
	if tpl == nil || !tpl.IsEnabled {
		s.fail(c, http.StatusNotFound, "malformed", "there is no ACME endpoint here")
		return
	}
	c.Set(ctxTemplate, tpl)

	nonce, err := s.mintNonce()
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not create a nonce")
		return
	}
	c.Header("Replay-Nonce", nonce)
	c.Header("Cache-Control", "no-store")
	c.Header("Link", `<`+s.base(c, slug)+`/directory>;rel="index"`)
	c.Next()
}

func templateOf(c *gin.Context) *store.CertificateTemplate {
	v, _ := c.Get(ctxTemplate)
	tpl, _ := v.(*store.CertificateTemplate)
	return tpl
}

func (s *Server) directory(c *gin.Context) {
	base := s.base(c, templateOf(c).Slug)
	c.JSON(http.StatusOK, gin.H{
		"newNonce":   base + "/new-nonce",
		"newAccount": base + "/new-account",
		// Clients take the presence of newOrder as the sign of an RFC 8555
		// server and refuse a directory without it. Accounts land first, so
		// for now it answers with a plain refusal.
		"newOrder": base + "/new-order",
		"meta": gin.H{
			// Said up front so a client that would try to register without
			// one is told to bring a credential, not left to find out.
			"externalAccountRequired": true,
		},
	})
}

func (s *Server) newNonce(c *gin.Context) {
	// RFC 8555 §7.2: 200 for HEAD, 204 for GET.
	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}
	c.Status(http.StatusNoContent)
}

// audit records something a client did. There is no signed-in person, so the
// actor is the credential it used.
func (s *Server) audit(c *gin.Context, action, accountID, kid string, details any) {
	raw, _ := json.Marshal(details)
	actor := "acme:" + kid
	ip := c.ClientIP()
	_ = s.cfg.Store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "acme_account",
		EntityID:   &accountID,
		ActorEmail: &actor,
		Details:    string(raw),
		IPAddress:  &ip,
	})
}

// newOrderNotYet is replaced by the real endpoint in the next change.
func (s *Server) newOrderNotYet(c *gin.Context) {
	s.fail(c, http.StatusNotImplemented, "serverInternal", "ordering certificates is not available on this endpoint yet")
}
