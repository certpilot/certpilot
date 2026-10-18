package acmeserver

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// ACME Renewal Information (RFC 9773). A client asks when to renew each
// certificate it holds, and names the one it is replacing when it orders.
// Both are what let the core, rather than each client's own timer, decide when
// a certificate is renewed: a revoked certificate is answered "now".

// ariRetryAfter is how long a client is told to wait before asking again.
const ariRetryAfter = 6 * time.Hour

// certIdentifier is an RFC 9773 certificate identifier: the issuer's key
// identifier and the serial's DER content octets, each base64url, joined by a
// dot.
type certIdentifier struct {
	aki    []byte
	serial *big.Int
}

func parseCertID(raw string) (certIdentifier, bool) {
	akiPart, serialPart, ok := strings.Cut(raw, ".")
	if !ok {
		return certIdentifier{}, false
	}
	aki, err1 := base64.RawURLEncoding.DecodeString(akiPart)
	serial, err2 := base64.RawURLEncoding.DecodeString(serialPart)
	// A DER INTEGER for a serial is positive, so its first octet has the high
	// bit clear.
	if err1 != nil || err2 != nil || len(aki) == 0 || len(serial) == 0 || serial[0]&0x80 != 0 {
		return certIdentifier{}, false
	}
	return certIdentifier{aki: aki, serial: new(big.Int).SetBytes(serial)}, true
}

// String is the canonical form, so that two spellings of one identifier
// compare equal.
func (id certIdentifier) String() string {
	serial := id.serial.Bytes()
	if len(serial) == 0 || serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(id.aki) + "." + base64.RawURLEncoding.EncodeToString(serial)
}

// leafOf parses the certificate a record currently holds.
func leafOf(cert *store.Certificate) *x509.Certificate {
	if cert.CertificatePEM == nil {
		return nil
	}
	block, _ := pem.Decode([]byte(*cert.CertificatePEM))
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// identifies reports whether id names the certificate a record holds now.
func (id certIdentifier) identifies(cert *store.Certificate) bool {
	leaf := leafOf(cert)
	return leaf != nil && leaf.SerialNumber.Cmp(id.serial) == 0 && bytes.Equal(leaf.AuthorityKeyId, id.aki)
}

// certificateFor finds the record holding the certificate id names, under this
// template. nil when there is none: never issued here, or since renewed over.
func (s *Server) certificateFor(c *gin.Context, tpl *store.CertificateTemplate, id certIdentifier) (*store.Certificate, error) {
	candidates, err := s.cfg.Store.GetCertificatesBySerial(c.Request.Context(), id.serial.Text(16))
	if err != nil {
		return nil, err
	}
	for _, cert := range candidates {
		if cert.TemplateID != nil && *cert.TemplateID == tpl.ID && id.identifies(cert) {
			return cert, nil
		}
	}
	return nil, nil
}

// renewalInfo handles GET /acme/<template>/renewal-info/<certID>.
//
// Unauthenticated, as RFC 9773 has it: a suggested window says nothing a
// certificate's own dates do not, except when the core wants it replaced early.
func (s *Server) renewalInfo(c *gin.Context) {
	tpl := templateOf(c)
	id, ok := parseCertID(c.Param("certid"))
	if !ok {
		s.fail(c, http.StatusBadRequest, "malformed", "that is not an RFC 9773 certificate identifier")
		return
	}
	cert, err := s.certificateFor(c, tpl, id)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the certificate up")
		return
	}
	if cert == nil || cert.NotAfter == nil {
		s.fail(c, http.StatusNotFound, "malformed", "this endpoint has no record of that certificate")
		return
	}

	start, end := suggestedWindow(cert, s.cfg.Now())
	c.Header("Retry-After", strconv.Itoa(int(ariRetryAfter.Seconds())))
	c.JSON(http.StatusOK, gin.H{"suggestedWindow": gin.H{
		"start": start.UTC().Format(time.RFC3339),
		"end":   end.UTC().Format(time.RFC3339),
	}})
}

// suggestedWindow is when the core would itself renew this certificate: its
// own renewal lead before expiry, the same rule the renewal sweep applies.
// A revoked certificate is due now, which a window already past says.
func suggestedWindow(cert *store.Certificate, now time.Time) (time.Time, time.Time) {
	if cert.Status == "REVOKED" {
		return now.Add(-2 * time.Hour), now.Add(-time.Hour)
	}
	var notBefore time.Time
	if cert.NotBefore != nil {
		notBefore = *cert.NotBefore
	}
	lead := store.RenewalLead(notBefore, *cert.NotAfter, cert.RenewalLeadDays)
	start := cert.NotAfter.Add(-lead)
	return start, start.Add(lead / 3)
}

// replacing checks the replaces field of a new order (RFC 9773 §5) and returns
// the record it names, or nil. Writes the refusal and reports false when the
// order cannot go ahead.
//
// A certificate CertPilot has no record of is not a refusal. RFC 9773 lets a
// server refuse, but the likeliest reason is a record somebody deleted, and a
// client that cannot renew over that is worse than one that renews as new.
func (s *Server) replacing(c *gin.Context, tpl *store.CertificateTemplate, account *store.ACMEAccount,
	raw string, identifiers []store.ACMEIdentifier) (*store.Certificate, string, bool) {

	id, ok := parseCertID(raw)
	if !ok {
		s.fail(c, http.StatusBadRequest, "malformed", "replaces is not an RFC 9773 certificate identifier")
		return nil, "", false
	}
	ctx := c.Request.Context()
	// Asked first: once replaced, the record holds the successor, so the
	// identifier no longer finds it and would look like one never issued.
	if done, err := s.cfg.Store.GetACMEOrderReplacing(ctx, id.String()); err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not check whether it was already replaced")
		return nil, "", false
	} else if done != nil {
		s.fail(c, http.StatusConflict, "alreadyReplaced", "another order has already replaced that certificate")
		return nil, "", false
	}
	cert, err := s.certificateFor(c, tpl, id)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the replaced certificate up")
		return nil, "", false
	}
	if cert == nil {
		return nil, "", true
	}

	order, err := s.cfg.Store.GetACMEOrderByCertificate(ctx, cert.ID)
	if err != nil {
		s.fail(c, http.StatusInternalServerError, "serverInternal", "could not look the replaced certificate's order up")
		return nil, "", false
	}
	if order == nil || order.AccountID != account.ID {
		s.fail(c, http.StatusForbidden, "unauthorized", "the certificate named in replaces was not issued to this account")
		return nil, "", false
	}
	if !sharesAName(cert, identifiers) {
		s.fail(c, http.StatusBadRequest, "malformed", "this order shares no name with the certificate it says it replaces")
		return nil, "", false
	}
	return cert, id.String(), true
}

func sharesAName(cert *store.Certificate, identifiers []store.ACMEIdentifier) bool {
	for _, name := range append([]string{cert.CommonName}, cert.SANs...) {
		for _, id := range identifiers {
			if strings.EqualFold(strings.TrimSuffix(name, "."), id.Value) {
				return true
			}
		}
	}
	return false
}

// replacedRecord is the record an order said it replaces, if it still holds
// that certificate and is still live. A record renewed over since, by another
// order, is not this order's to write over.
func (s *Server) replacedRecord(c *gin.Context, order *store.ACMEOrder) (*store.Certificate, error) {
	if order.ReplacesCertificateID == nil || order.Replaces == "" {
		return nil, nil
	}
	id, ok := parseCertID(order.Replaces)
	if !ok {
		return nil, nil
	}
	cert, err := s.cfg.Store.GetCertificate(c.Request.Context(), *order.ReplacesCertificateID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !liveStatuses[cert.Status] || !id.identifies(cert) {
		return nil, nil
	}
	return cert, nil
}
