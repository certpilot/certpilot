package acmeserver

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// keyChange handles POST /acme/<template>/key-change (RFC 8555 §7.3.5).
//
// The outer request is an ordinary one, signed by the account's current key.
// Its payload is a second JWS, signed by the new key, that names the account
// and its old key. So a rollover needs both keys: the old one to say this
// account wants a new key, the new one to say its holder agrees to be this
// account. Either alone would let one key take over what the other names.
func (s *Server) keyChange(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, byKID)
	if req == nil {
		return
	}
	acct := req.account

	inner, err := jws.Parse(req.payload, jws.WithJSON())
	if err != nil || len(inner.Signatures()) != 1 {
		s.fail(c, http.StatusBadRequest, "malformed", "the payload must be a flattened JWS signed by the new key")
		return
	}
	hdrs := inner.Signatures()[0].ProtectedHeaders()
	if hdrs == nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the inner JWS has no protected header")
		return
	}
	alg, ok := hdrs.Algorithm()
	if !ok || !accountAlgs[alg.String()] {
		s.fail(c, http.StatusBadRequest, "badSignatureAlgorithm",
			"the new key must sign with ES256, ES384, ES512, RS256, RS384, RS512 or EdDSA")
		return
	}
	newKey, hasJWK := hdrs.JWK()
	if _, hasKID := hdrs.KeyID(); !hasJWK || hasKID {
		s.fail(c, http.StatusBadRequest, "malformed", `the inner JWS must carry the new key as "jwk"`)
		return
	}
	// The outer request's nonce already prevents replay. One on the inner
	// request would be a second nonce spent for nothing, and the RFC forbids it.
	var nonce string
	if hdrs.Get("nonce", &nonce) == nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the inner JWS must not carry a nonce")
		return
	}
	var innerURL string
	if hdrs.Get("url", &innerURL) != nil || innerURL != s.requestURL(c) {
		s.fail(c, http.StatusBadRequest, "malformed", "the inner JWS must be signed for this URL")
		return
	}
	if hasPrivateParts(newKey) {
		s.fail(c, http.StatusBadRequest, "malformed", "the new key contains private key material; send only the public key")
		return
	}
	if _, err := jws.Verify(req.payload, jws.WithKey(alg, newKey)); err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the inner JWS does not verify against the key it carries")
		return
	}

	var payload struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if err := json.Unmarshal(inner.Payload(), &payload); err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the inner payload must name the account and its old key")
		return
	}
	if payload.Account != s.accountURL(c, tpl, acct.ID) {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "the new key was signed over for a different account")
		return
	}
	oldKey, err := jwk.ParseKey(payload.OldKey)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "oldKey is not a JWK")
		return
	}
	oldThumb, err := thumbprint(oldKey)
	if err != nil || oldThumb != acct.JWKThumbprint {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "oldKey is not this account's current key")
		return
	}

	newThumb, err := thumbprint(newKey)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the new key is not usable")
		return
	}
	if newThumb == oldThumb {
		s.fail(c, http.StatusBadRequest, "malformed", "the new key is the account's current key")
		return
	}
	// Checked first for the Location header the RFC asks for. The store's
	// uniqueness rule is what actually holds against a race.
	if other, err := s.cfg.Store.GetACMEAccountByThumbprint(c.Request.Context(), tpl.ID, newThumb); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not check the new key")
		return
	} else if other != nil {
		s.keyInUse(c, tpl, other.ID)
		return
	}

	if err := s.cfg.Store.UpdateACMEAccountKey(c.Request.Context(), acct.ID, mustJSON(newKey), newThumb); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.keyInUse(c, tpl, "")
			return
		}
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not change the account key")
		return
	}
	s.audit(c, "acme.account_key_changed", acct.ID, acct.ID, gin.H{
		"template": tpl.Slug, "old_thumbprint": oldThumb, "new_thumbprint": newThumb,
	})
	acct.JWK, acct.JWKThumbprint = mustJSON(newKey), newThumb
	s.writeAccount(c, http.StatusOK, tpl, acct)
}

func (s *Server) keyInUse(c *gin.Context, tpl *store.CertificateTemplate, otherID string) {
	if otherID != "" {
		c.Header("Location", s.accountURL(c, tpl, otherID))
	}
	s.fail(c, http.StatusConflict, "malformed", "another account already uses that key")
}
