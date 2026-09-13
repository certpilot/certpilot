package x509util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"
)

// CSRInfo is what a certificate signing request asks for, after it has been
// proven to be a genuine request rather than an assertion.
type CSRInfo struct {
	CommonName string   `json:"common_name"`
	DNSNames   []string `json:"dns_names"`
	// IPAddresses and EmailAddresses are reported so a caller can tell the
	// requester they were dropped, rather than silently issuing a certificate
	// that does not cover what was asked for.
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
	URIs           []string `json:"uris,omitempty"`
	SubjectDN      string   `json:"subject_dn"`
	// Subject carries the structured components of the subject, keyed by the
	// short attribute names a policy or a template names them by: O, OU, C, L,
	// ST. SubjectDN above is a display string in RFC 2253 form, and comparing
	// an organisation against one means parsing it — which is how a rule about
	// the subject ends up matching a substring of somebody's locality.
	//
	// An attribute with several values is joined with ", ". A template supplies
	// one value per attribute, so a multi-valued request differs from it, which
	// is the right answer rather than a lossy one.
	Subject map[string]string `json:"subject,omitempty"`

	// RequestsCA and RequestsKeyCertSign report a request asking to become an
	// authority rather than an end entity.
	//
	// Reported here rather than refused here, because parsing and deciding are
	// different jobs: a screen showing an operator what a CSR asks for needs to
	// parse one it would never issue. The refusal belongs wherever issuance is
	// decided, which is one place.
	//
	// A correct CA builds its own template and ignores everything in a request
	// but the public key and the names, and the gateways here do. But "the code
	// downstream is careful" is not a control — it is a hope about code that
	// may be a third-party gateway next year.
	RequestsCA          bool `json:"requests_ca,omitempty"`
	RequestsKeyCertSign bool `json:"requests_key_cert_sign,omitempty"`

	KeyType            string `json:"key_type"`
	KeySize            int    `json:"key_size"`
	Curve              string `json:"curve,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

// Names returns the certificate's requested names, common name first.
//
// Deduplicated, because a CSR that repeats its common name in the SAN list is
// both extremely common and correct — CAB Forum rules require the CN to appear
// as a SAN — and passing the duplicate through produces a certificate with the
// same name listed twice.
func (c *CSRInfo) Names() []string {
	seen := make(map[string]bool, len(c.DNSNames)+1)
	var names []string
	for _, n := range append([]string{c.CommonName}, c.DNSNames...) {
		n = strings.TrimSpace(n)
		if n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		names = append(names, n)
	}
	return names
}

// ParseCSRPEM decodes a PEM certificate signing request and verifies it.
//
// **The signature check is the point of this function**, not a formality.
//
// A CSR is a public key plus a set of requested names, signed by the private
// key that matches that public key. The signature is the only thing making it a
// *request* rather than a claim: without checking it, anyone can paste a CSR
// containing somebody else's public key and have a CA issue a certificate for
// names they control, bound to a key they do not have. That certificate is then
// usable by whoever does hold the key.
//
// Go's x509.ParseCertificateRequest does not check the signature. It has to be
// asked, and this is the only place in CertPilot that accepts a CSR from
// outside, so it is asked here.
func ParseCSRPEM(csrPEM []byte) (*CSRInfo, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("not PEM-encoded data; expected a block beginning -----BEGIN CERTIFICATE REQUEST-----")
	}
	switch block.Type {
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
	case "CERTIFICATE":
		// Worth naming, because it is the commonest paste error and the generic
		// message sends people looking in the wrong place.
		return nil, fmt.Errorf("this is a certificate, not a signing request")
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		// Do not echo any of it back, and do not proceed.
		return nil, fmt.Errorf("this is a private key, not a signing request — do not paste private keys here")
	default:
		return nil, fmt.Errorf("expected a CERTIFICATE REQUEST block, found %q", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse the signing request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf(
			"the signing request's signature is not valid, so it does not prove possession of the private key: %w", err)
	}

	info := &CSRInfo{
		CommonName:         csr.Subject.CommonName,
		DNSNames:           append([]string(nil), csr.DNSNames...),
		EmailAddresses:     append([]string(nil), csr.EmailAddresses...),
		SubjectDN:          csr.Subject.String(),
		Subject:            subjectComponents(csr.Subject),
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm.String(),
	}
	for _, ip := range csr.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, u := range csr.URIs {
		info.URIs = append(info.URIs, u.String())
	}
	info.RequestsCA, info.RequestsKeyCertSign = authorityRequest(csr)
	sort.Strings(info.DNSNames)

	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType, info.KeySize = "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType, info.KeySize = "ECDSA", pub.Curve.Params().BitSize
		info.Curve = pub.Curve.Params().Name
	case ed25519.PublicKey:
		info.KeyType, info.KeySize = "Ed25519", 256
	default:
		return nil, fmt.Errorf("unsupported public key type %T in the signing request", csr.PublicKey)
	}

	if len(info.Names()) == 0 {
		return nil, fmt.Errorf(
			"the signing request asks for no DNS names: it has neither a common name nor any subject alternative names")
	}

	return info, nil
}

// DroppedNames lists what the request asked for that a domain-oriented issuance
// path cannot carry.
//
// The gateway contract takes a list of domains. A CSR carrying IP or email SANs
// would have them silently discarded, and the requester would receive a
// certificate that does not do what they asked — a failure they would discover
// in production rather than here.
func (c *CSRInfo) DroppedNames() []string {
	var dropped []string
	for _, ip := range c.IPAddresses {
		if net.ParseIP(ip) != nil {
			dropped = append(dropped, "IP:"+ip)
		}
	}
	for _, email := range c.EmailAddresses {
		dropped = append(dropped, "email:"+email)
	}
	return dropped
}

// subjectComponents pulls out the attributes a template can supply.
//
// Only the ones a template names. The rest of a subject is carried through to
// the CA in the request itself and is not something this codebase decides.
func subjectComponents(name pkix.Name) map[string]string {
	out := map[string]string{}
	for key, values := range map[string][]string{
		"O":  name.Organization,
		"OU": name.OrganizationalUnit,
		"C":  name.Country,
		"L":  name.Locality,
		"ST": name.Province,
	} {
		if len(values) > 0 {
			out[key] = strings.Join(values, ", ")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// OIDs for the extensions a request has no business asking for.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// authorityRequest reports whether a request asks to be an authority.
//
// An extension that will not parse is not a claim, so it is ignored rather than
// guessed at. The two answers are separate because they are separate asks: a
// certificate can be a CA without keyCertSign, and a leaf with keyCertSign is
// its own problem.
func authorityRequest(csr *x509.CertificateRequest) (isCA, keyCertSign bool) {
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidBasicConstraints):
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				isCA = true
			}
		case ext.Id.Equal(oidKeyUsage):
			var usage asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &usage); err != nil {
				continue
			}
			// Bit 5 is keyCertSign in the KeyUsage bit string.
			const keyCertSignBit = 5
			if usage.BitLength > keyCertSignBit && usage.At(keyCertSignBit) == 1 {
				keyCertSign = true
			}
		}
	}
	return isCA, keyCertSign
}
