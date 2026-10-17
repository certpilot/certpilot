package acmeserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type accountJSON struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

type newAccountPayload struct {
	Contact              []string        `json:"contact"`
	OnlyReturnExisting   bool            `json:"onlyReturnExisting"`
	ExternalAccountBind  json.RawMessage `json:"externalAccountBinding"`
	TermsOfServiceAgreed bool            `json:"termsOfServiceAgreed"`
}

func (s *Server) accountURL(c *gin.Context, tpl *store.CertificateTemplate, id string) string {
	return s.base(c, tpl.Slug) + "/account/" + id
}

func (s *Server) writeAccount(c *gin.Context, status int, tpl *store.CertificateTemplate, a *store.ACMEAccount) {
	c.Header("Location", s.accountURL(c, tpl, a.ID))
	c.JSON(status, accountJSON{Status: a.Status, Contact: a.Contacts,
		Orders: s.accountURL(c, tpl, a.ID) + "/orders"})
}

// newAccount handles POST /acme/<template>/new-account.
func (s *Server) newAccount(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, true)
	if req == nil {
		return
	}
	ctx := c.Request.Context()

	var payload newAccountPayload
	if len(req.payload) > 0 {
		if err := json.Unmarshal(req.payload, &payload); err != nil {
			s.fail(c, http.StatusBadRequest, "malformed", "the payload is not valid JSON")
			return
		}
	}

	thumb, err := thumbprint(req.key)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the account key is not usable")
		return
	}

	// A key that is already registered gets its account back. That is how a
	// client that lost the account URL finds it again, and how a retry after a
	// dropped response is harmless.
	existing, err := s.cfg.Store.GetACMEAccountByThumbprint(ctx, tpl.ID, thumb)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the account up")
		return
	}
	if existing != nil {
		if existing.Status != store.ACMEAccountValid {
			s.fail(c, http.StatusUnauthorized, "unauthorized", "this account is "+existing.Status)
			return
		}
		s.writeAccount(c, http.StatusOK, tpl, existing)
		return
	}
	if payload.OnlyReturnExisting {
		s.fail(c, http.StatusBadRequest, "accountDoesNotExist", "no account is registered for this key")
		return
	}

	if len(payload.ExternalAccountBind) == 0 {
		s.fail(c, http.StatusForbidden, "externalAccountRequired",
			"this endpoint does not allow open registration; ask an administrator for an external account binding")
		return
	}
	contacts, ok := cleanContacts(payload.Contact)
	if !ok {
		s.fail(c, http.StatusBadRequest, "unsupportedContact", `a contact must be a "mailto:" address`)
		return
	}

	cred := s.checkBinding(c, tpl, req.key, thumb, payload.ExternalAccountBind)
	if cred == nil {
		return
	}

	acct := &store.ACMEAccount{
		TemplateID: tpl.ID, EABID: cred.ID, JWKThumbprint: thumb,
		JWK: mustJSON(req.key), Contacts: contacts,
	}
	if err := s.cfg.Store.CreateACMEAccount(ctx, acct); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Lost a race with another request using the same credential.
			s.fail(c, http.StatusUnauthorized, "unauthorized", "this credential has already been used to register an account")
			return
		}
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not create the account")
		return
	}
	s.audit(c, "acme.account_created", acct.ID, cred.KID, gin.H{
		"template": tpl.Slug, "credential": cred.Name, "contacts": contacts,
	})
	s.writeAccount(c, http.StatusCreated, tpl, acct)
}

var bindingAlgs = map[string]bool{"HS256": true, "HS384": true, "HS512": true}

// checkBinding verifies an External Account Binding (RFC 8555 §7.3.4): a JWS,
// keyed with the credential's HMAC key, whose payload is the account key being
// registered. Proving it proves the client holds a credential an administrator
// handed out, and that the credential is being used for this key and no other.
//
// Writes the refusal and returns nil when it does not hold.
func (s *Server) checkBinding(c *gin.Context, tpl *store.CertificateTemplate, accountKey jwk.Key, thumb string, raw json.RawMessage) *store.ACMEEABCredential {
	deny := func(detail string) *store.ACMEEABCredential {
		s.fail(c, http.StatusUnauthorized, "unauthorized", detail)
		return nil
	}

	msg, err := jws.Parse(raw, jws.WithJSON())
	if err != nil || len(msg.Signatures()) != 1 {
		s.fail(c, http.StatusBadRequest, "malformed", "the external account binding is not a flattened JWS")
		return nil
	}
	hdrs := msg.Signatures()[0].ProtectedHeaders()
	if hdrs == nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the external account binding has no protected header")
		return nil
	}
	alg, ok := hdrs.Algorithm()
	if !ok || !bindingAlgs[alg.String()] {
		s.fail(c, http.StatusBadRequest, "badSignatureAlgorithm", "the external account binding must be signed with HS256, HS384 or HS512")
		return nil
	}
	kid, _ := hdrs.KeyID()
	var url string
	_ = hdrs.Get("url", &url)
	if kid == "" || url != s.requestURL(c) {
		return deny("the external account binding must name its credential and be signed for this URL")
	}

	cred, err := s.cfg.Store.GetACMEEABCredentialByKID(c.Request.Context(), kid)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the credential up")
		return nil
	}
	// One message for unknown and for another template's, so a credential id is
	// not an oracle for what other endpoints exist.
	if cred == nil || cred.TemplateID != tpl.ID {
		return deny("the external account binding was not accepted")
	}
	if cred.RevokedAt != nil {
		return deny("this credential has been revoked")
	}

	key, err := s.cfg.Keyring.Decrypt(cred.HMACKeySealed, secrets.ContextACMEEABKey)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not open the credential")
		return nil
	}
	if _, err := jws.Verify(raw, jws.WithKey(alg, key)); err != nil {
		return deny("the external account binding was not accepted")
	}

	// The binding's payload is the key being registered, so that a binding made
	// for one client cannot be lifted onto another's registration.
	bound, err := jwk.ParseKey(msg.Payload())
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the external account binding does not carry a key")
		return nil
	}
	if boundThumb, err := thumbprint(bound); err != nil || boundThumb != thumb {
		return deny("the external account binding is for a different account key")
	}

	if used, err := s.cfg.Store.GetACMEAccountByEAB(c.Request.Context(), cred.ID); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not check the credential")
		return nil
	} else if used != nil {
		return deny("this credential has already been used to register an account")
	}
	_ = accountKey
	return cred
}

// account handles POST /acme/<template>/account/<id>: read, update, deactivate.
func (s *Server) account(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, false)
	if req == nil {
		return
	}
	// An account can only act on itself.
	if req.account.ID != c.Param("id") {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "that is not your account")
		return
	}
	acct := req.account

	// POST-as-GET sends an empty payload.
	if len(req.payload) > 0 {
		var update struct {
			Contact []string `json:"contact"`
			Status  string   `json:"status"`
		}
		if err := json.Unmarshal(req.payload, &update); err != nil {
			s.fail(c, http.StatusBadRequest, "malformed", "the payload is not valid JSON")
			return
		}
		changed := false
		if update.Contact != nil {
			contacts, ok := cleanContacts(update.Contact)
			if !ok {
				s.fail(c, http.StatusBadRequest, "unsupportedContact", `a contact must be a "mailto:" address`)
				return
			}
			acct.Contacts, changed = contacts, true
		}
		switch update.Status {
		case "":
		case store.ACMEAccountDeactivated:
			acct.Status, changed = store.ACMEAccountDeactivated, true
		default:
			s.fail(c, http.StatusBadRequest, "malformed", `the only status a client may set is "deactivated"`)
			return
		}
		if changed {
			if err := s.cfg.Store.UpdateACMEAccount(c.Request.Context(), acct); err != nil {
				s.fail(c, http.StatusInternalServerError, "serverInternal", "could not update the account")
				return
			}
			if acct.Status == store.ACMEAccountDeactivated {
				s.audit(c, "acme.account_deactivated", acct.ID, acct.ID, gin.H{"template": tpl.Slug})
			}
		}
	}
	s.writeAccount(c, http.StatusOK, tpl, acct)
}

// cleanContacts accepts mailto: addresses only. The spec allows other schemes,
// but nothing here would send to them, and an address that goes nowhere is a
// contact that gives a false sense of being reachable.
func cleanContacts(in []string) ([]string, bool) {
	if len(in) > 10 {
		return nil, false
	}
	out := make([]string, 0, len(in))
	for _, contact := range in {
		if !strings.HasPrefix(contact, "mailto:") || len(contact) > 255 || len(contact) == len("mailto:") {
			return nil, false
		}
		out = append(out, contact)
	}
	return out, true
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

var _ = jwa.ES256
