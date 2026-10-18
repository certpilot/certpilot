package acmeserver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/issuance"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// revokeCert handles POST /acme/<template>/revoke-cert (RFC 8555 §7.6).
//
// Two kinds of request may revoke: the account that ordered the certificate,
// and anyone signing with the certificate's own private key. The second is how
// a key that has leaked gets reported by whoever found it. Any other account on
// the same template may not: the credential that made it authorises it to
// order names, not to end certificates another team depends on.
//
// The revocation itself goes through the same revoker as the console's, so the
// CA is told first and the record changes only when it agreed.
func (s *Server) revokeCert(c *gin.Context) {
	tpl := templateOf(c)
	req := s.verify(c, tpl, byEither)
	if req == nil {
		return
	}
	ctx := c.Request.Context()

	var payload struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := json.Unmarshal(req.payload, &payload); err != nil || payload.Certificate == "" {
		s.fail(c, http.StatusBadRequest, "malformed", "the payload must carry the certificate")
		return
	}
	der, err := base64.RawURLEncoding.DecodeString(payload.Certificate)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the certificate is not base64url")
		return
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		s.fail(c, http.StatusBadRequest, "malformed", "the certificate is not a DER X.509 certificate")
		return
	}
	reason := 0 // RFC 8555 §7.6: absent means unspecified.
	if payload.Reason != nil {
		reason = *payload.Reason
	}
	if !store.ValidRevocationReason(reason) {
		s.fail(c, http.StatusBadRequest, "badRevocationReason",
			fmt.Sprintf("%d is not a revocation reason this server accepts; use one of %s", reason, reasonList()))
		return
	}

	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])
	cert, err := s.cfg.Store.GetCertificateByFingerprint(ctx, fp)
	// A renewal writes its successor over the record, so the certificate it
	// replaced is found through the record that replaced it. Renew, then revoke
	// the old one, is what a client does when a key leaks.
	replaced := false
	if err == nil && cert == nil {
		cert, err = s.cfg.Store.GetCertificateBySupersededFingerprint(ctx, fp)
		replaced = cert != nil
	}
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the certificate up")
		return
	}
	// One answer for a certificate CertPilot has never seen, one another
	// template issued and one another account ordered, so this endpoint does
	// not say what else is in the inventory.
	const notYours = "this endpoint did not issue that certificate to you"
	if cert == nil || cert.TemplateID == nil || *cert.TemplateID != tpl.ID {
		s.fail(c, http.StatusForbidden, "unauthorized", notYours)
		return
	}

	var actor, accountID string
	if req.account != nil {
		order, err := s.cfg.Store.GetACMEOrderByCertificate(ctx, cert.ID)
		if err != nil {
			s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the order up")
			return
		}
		if order == nil || order.AccountID != req.account.ID {
			s.fail(c, http.StatusForbidden, "unauthorized", notYours)
			return
		}
		accountID, actor = req.account.ID, "acme:"+req.account.ID
	} else {
		// The signature already verified against the key the request carried,
		// so what is left is whether that key is the certificate's.
		if !sameKey(req.key, leaf.PublicKey) {
			s.fail(c, http.StatusForbidden, "unauthorized",
				"the request is signed neither by an account that ordered this certificate nor by its key")
			return
		}
		actor = "acme:certificate-key"
	}

	if replaced {
		replacedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		if err := s.cfg.Revoker.RevokeReplaced(ctx, cert, replacedPEM, fp, reason); err != nil {
			s.revokeFailed(c, err)
			return
		}
		s.auditRevocation(c, tpl, cert, reason, actor, accountID, gin.H{
			"fingerprint": fp, "serial": leaf.SerialNumber.String(), "replaced_by": cert.FingerprintSHA256,
		})
		c.Status(http.StatusOK)
		return
	}

	revoked, err := s.cfg.Revoker.Revoke(ctx, cert, reason, actor)
	if err != nil {
		s.revokeFailed(c, err)
		return
	}

	s.auditRevocation(c, tpl, revoked, reason, actor, accountID, nil)
	if s.cfg.Broker != nil {
		s.cfg.Broker.Publish(events.Event{
			Topic:    "cert.revoked",
			Severity: "WARNING",
			EntityID: revoked.ID,
			Payload: map[string]any{
				"common_name": revoked.CommonName,
				"reason":      store.RevocationReasons[reason],
				"revoked_by":  actor,
			},
			Timestamp: time.Now(),
		})
	}
	c.Status(http.StatusOK)
}

func (s *Server) revokeFailed(c *gin.Context, err error) {
	status, kind := http.StatusInternalServerError, "serverInternal"
	if re, ok := issuance.AsRevokeError(err); ok {
		switch re.Kind {
		case issuance.RevokeAlreadyRevoked:
			status, kind = http.StatusBadRequest, "alreadyRevoked"
		case issuance.RevokeBadReason:
			status, kind = http.StatusBadRequest, "badRevocationReason"
		case issuance.RevokeNotPossible:
			status, kind = http.StatusBadRequest, "malformed"
		}
	}
	s.fail(c, status, kind, err.Error())
}

// sameKey reports whether a JWK and a certificate's public key are one key.
func sameKey(key jwk.Key, certKey any) bool {
	fromCert, err := jwk.Import(certKey)
	if err != nil {
		return false
	}
	a, errA := thumbprint(key)
	b, errB := thumbprint(fromCert)
	return errA == nil && errB == nil && a == b
}

// auditRevocation records it under the same action as a revocation made in the
// console, so one search finds every revocation however it was asked for.
//
// extra overrides or adds details: a replaced certificate is recorded with its
// own fingerprint and the fingerprint of the one that replaced it.
func (s *Server) auditRevocation(c *gin.Context, tpl *store.CertificateTemplate, cert *store.Certificate, reason int, actor, accountID string, extra gin.H) {
	details := gin.H{
		"common_name": cert.CommonName, "reason": store.RevocationReasons[reason], "reason_code": reason,
		"fingerprint": cert.FingerprintSHA256, "via": "acme", "template": tpl.Slug, "acme_account": accountID,
	}
	for k, v := range extra {
		details[k] = v
	}
	raw, _ := json.Marshal(details)
	ip := c.ClientIP()
	_ = s.cfg.Store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "certificate.revoked",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorEmail: &actor,
		Details:    string(raw),
		IPAddress:  &ip,
	})
}

func reasonList() string {
	codes := make([]int, 0, len(store.RevocationReasons))
	for code := range store.RevocationReasons {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, fmt.Sprintf("%d (%s)", code, store.RevocationReasons[code]))
	}
	return strings.Join(parts, ", ")
}
