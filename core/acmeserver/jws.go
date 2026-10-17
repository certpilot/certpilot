package acmeserver

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const maxBody = 64 << 10

// accountAlgs are the signature algorithms an account key may use. All
// asymmetric: an account key is a public key the server stores, and a MAC
// algorithm would have the client and the server sharing the secret that
// proves who is asking.
var accountAlgs = map[string]bool{
	"ES256": true, "ES384": true, "ES512": true,
	"RS256": true, "RS384": true, "RS512": true,
	"EdDSA": true,
}

// signed is a request whose signature has been checked.
type signed struct {
	payload []byte
	// key is the account key. When the request named itself with a jwk it is
	// the key it carried; when it used a kid it is the stored account's.
	key jwk.Key
	// account is set when the request used a kid.
	account *store.ACMEAccount
	// usedJWK is true for the requests allowed to introduce a key.
	usedJWK bool
}

// requestURL is what a signature has to have been made for: the URL the server
// would have handed out for this request.
func (s *Server) requestURL(c *gin.Context) string {
	return s.origin(c) + c.Request.URL.Path
}

// verify checks a request's JWS: the media type, the algorithm, the nonce, the
// URL it was signed for, and the signature itself. It writes the refusal and
// returns nil when any of that fails.
func (s *Server) verify(c *gin.Context, tpl *store.CertificateTemplate, wantJWK bool) *signed {
	if ct := c.GetHeader("Content-Type"); !strings.HasPrefix(ct, "application/jose+json") {
		s.fail(c, http.StatusUnsupportedMediaType, "malformed", `the body must be application/jose+json`)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		s.fail(c, http.StatusBadRequest, "malformed", "the request body is missing or too large")
		return nil
	}

	msg, err := jws.Parse(body, jws.WithJSON())
	if err != nil || len(msg.Signatures()) != 1 {
		s.fail(c, http.StatusBadRequest, "malformed", "the body is not a flattened JWS with one signature")
		return nil
	}
	hdrs := msg.Signatures()[0].ProtectedHeaders()
	if hdrs == nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the JWS has no protected header")
		return nil
	}

	alg, ok := hdrs.Algorithm()
	if !ok || !accountAlgs[alg.String()] {
		s.fail(c, http.StatusBadRequest, "badSignatureAlgorithm",
			"the signature algorithm must be one of ES256, ES384, ES512, RS256, RS384, RS512 or EdDSA")
		return nil
	}

	var nonce, signedURL string
	if hdrs.Get("nonce", &nonce) != nil || nonce == "" {
		s.fail(c, http.StatusBadRequest, "malformed", "the protected header has no nonce")
		return nil
	}
	if hdrs.Get("url", &signedURL) != nil || signedURL == "" {
		s.fail(c, http.StatusBadRequest, "malformed", "the protected header has no url")
		return nil
	}

	if err := s.spendNonce(c.Request.Context(), nonce); err != nil {
		if errors.Is(err, errBadNonce) {
			s.fail(c, http.StatusBadRequest, "badNonce", err.Error())
		} else {
			s.fail(c, http.StatusInternalServerError, "serverInternal", "could not check the nonce")
		}
		return nil
	}

	// After the nonce, so a refused request still burns its nonce rather than
	// letting an attacker probe URLs with one.
	if signedURL != s.requestURL(c) {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "the request was signed for a different URL")
		return nil
	}

	embedded, hasJWK := hdrs.JWK()
	kid, hasKID := hdrs.KeyID()
	if hasJWK == hasKID {
		s.fail(c, http.StatusBadRequest, "malformed", `the protected header must have exactly one of "jwk" and "kid"`)
		return nil
	}
	if hasJWK != wantJWK {
		if wantJWK {
			s.fail(c, http.StatusBadRequest, "malformed", `this request must carry the account key as "jwk"`)
		} else {
			s.fail(c, http.StatusBadRequest, "malformed", `this request must name its account with "kid"`)
		}
		return nil
	}

	out := &signed{usedJWK: hasJWK}
	if hasJWK {
		if hasPrivateParts(embedded) {
			s.fail(c, http.StatusBadRequest, "malformed", "the account key contains private key material; send only the public key")
			return nil
		}
		out.key = embedded
	} else {
		acct := s.accountFromKID(c, tpl, kid)
		if acct == nil {
			return nil
		}
		key, err := jwk.ParseKey([]byte(acct.JWK))
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "serverInternal", "the stored account key could not be read")
			return nil
		}
		out.key, out.account = key, acct
	}

	if _, err := jws.Verify(body, jws.WithKey(alg, out.key)); err != nil {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "the signature does not verify against the account key")
		return nil
	}
	out.payload = msg.Payload()
	return out
}

// accountFromKID resolves the account URL a request names itself with.
func (s *Server) accountFromKID(c *gin.Context, tpl *store.CertificateTemplate, kid string) *store.ACMEAccount {
	prefix := s.base(c, tpl.Slug) + "/account/"
	if !strings.HasPrefix(kid, prefix) {
		s.fail(c, http.StatusBadRequest, "accountDoesNotExist", "that is not an account of this endpoint")
		return nil
	}
	acct, err := s.cfg.Store.GetACMEAccount(c.Request.Context(), strings.TrimPrefix(kid, prefix))
	if errors.Is(err, store.ErrNotFound) || (err == nil && acct.TemplateID != tpl.ID) {
		s.fail(c, http.StatusBadRequest, "accountDoesNotExist", "there is no such account")
		return nil
	}
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not read the account")
		return nil
	}
	if acct.Status != store.ACMEAccountValid {
		s.fail(c, http.StatusUnauthorized, "unauthorized", "this account is "+acct.Status)
		return nil
	}
	return acct
}

// hasPrivateParts reports whether a JWK carries anything a public key does not.
func hasPrivateParts(key jwk.Key) bool {
	raw, err := json.Marshal(key)
	if err != nil {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, found := fields[private]; found {
			return true
		}
	}
	return false
}

// thumbprint is the RFC 7638 SHA-256 thumbprint, base64url without padding.
func thumbprint(key jwk.Key) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

var _ = jwa.ES256
