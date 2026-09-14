package agent

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Formats a destination may be written in.
const (
	// FormatPEM is what every destination wrote before keystores existed, and
	// stays the default: an empty format means PEM.
	FormatPEM = "PEM"
	// FormatPKCS12 is one file holding the certificate, its chain and the key.
	FormatPKCS12 = "PKCS12"
)

// format is what this destination writes, defaulted.
func (d *Destination) format() string {
	if d.Format == "" {
		return FormatPEM
	}
	return strings.ToUpper(strings.TrimSpace(d.Format))
}

// keystore reports whether this destination writes one file rather than
// several. The whole difference downstream: paths, modes, checks and rollback
// are identical either way.
func (d *Destination) keystore() bool { return d.format() != FormatPEM }

// password resolves the keystore password from whichever field supplied it.
//
// Read at render time rather than at parse time, so a password file that is
// missing fails the destination that needs it rather than the whole spec — one
// unreadable file must not stop every other destination on the host installing.
func (d *Destination) password() (string, error) {
	if d.KeystorePassword != "" {
		return d.KeystorePassword, nil
	}
	body, err := os.ReadFile(d.KeystorePasswordFile)
	if err != nil {
		return "", fmt.Errorf(
			"keystore_password_file %s could not be read: %w", d.KeystorePasswordFile, err)
	}
	// Trailing whitespace only. A password with a leading space is a password
	// somebody meant, and `echo secret > file` leaves a newline that nobody did.
	pw := strings.TrimRight(string(body), " \t\r\n")
	if pw == "" {
		return "", fmt.Errorf("keystore_password_file %s is empty", d.KeystorePasswordFile)
	}
	return pw, nil
}

// encodeKeystore turns the issued material into one keystore file.
//
// The chain goes in as CA certificates rather than being concatenated onto the
// leaf. A keystore is a structure, not a file of PEM blocks, and a consumer
// that asks it for the chain gets nothing if the intermediates were stapled to
// the certificate instead of stored as what they are.
func encodeKeystore(d *Destination, m *material) ([]byte, error) {
	password, err := d.password()
	if err != nil {
		return nil, err
	}

	leaf, err := firstCertificate(m.certPEM)
	if err != nil {
		return nil, fmt.Errorf("the issued certificate: %w", err)
	}
	key, err := parsePrivateKey(m.keyPEM)
	if err != nil {
		return nil, err
	}
	chain, err := allCertificates(m.chainPEM)
	if err != nil {
		return nil, fmt.Errorf("the chain: %w", err)
	}

	switch d.format() {
	case FormatPKCS12:
		// Modern, not Legacy: LegacyRC2 and LegacyDES exist for reading files
		// written decades ago, and writing one would hand an estate RC2 in
		// 2026 to satisfy a JDK that has read the modern encoding since 9.
		pfx, err := pkcs12.Modern.Encode(key, leaf, chain, password)
		if err != nil {
			return nil, err
		}
		// Naming the entry is a second pass over what Encode produced, because
		// go-pkcs12 has no way to pass an alias through. Returns pfx untouched
		// when no alias was asked for.
		return setKeystoreAlias(pfx, password, strings.TrimSpace(d.KeystoreAlias))
	default:
		return nil, fmt.Errorf(
			"format %q is not one this build writes. PEM or PKCS12", d.Format)
	}
}

// parsePrivateKey accepts the three shapes a PEM private key comes in.
//
// An agent generated this key itself, so in practice it is always the same
// shape — but a key restored from a backup, or written by an older agent, is
// not, and failing on it would be failing at install time on a host that has a
// perfectly good key.
func parsePrivateKey(keyPEM []byte) (any, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("the private key is not PEM-encoded")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf(
		"the private key is a %q block this build cannot parse as PKCS#8, PKCS#1 or SEC 1", block.Type)
}

func firstCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("not PEM-encoded")
	}
	return x509.ParseCertificate(block.Bytes)
}

func allCertificates(chainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
}

// validateKeystore checks a keystore destination against itself.
//
// Refused here rather than at install time. A spec that cannot work should fail
// when it is read, on a host that is still serving the certificate it has,
// rather than after the previous file has already been captured and replaced.
func (d *Destination) validateKeystore() error {
	if d.format() != FormatPKCS12 {
		return fmt.Errorf(
			"format %q is not one this build writes. PEM, or PKCS12 for a keystore", d.Format)
	}
	if d.CertPath == "" {
		return fmt.Errorf("cert_path is required: it is the keystore file")
	}
	if d.KeyPath != "" {
		return fmt.Errorf(
			"key_path must be omitted for a %s destination — the key goes inside the keystore, "+
				"and naming a second path would write it to disk in the clear as well", d.format())
	}
	if d.ChainPath != "" || d.FullChainPath != "" {
		return fmt.Errorf(
			"chain_path and fullchain_path do not apply to a %s destination — the chain is "+
				"stored inside the keystore as CA certificates", d.format())
	}
	// cert_mode would be accepted and ignored: a keystore holds the key, so it
	// takes key_mode and its 0600 default. Silently ignoring a mode somebody
	// wrote is how a file ends up at a permission they think they set.
	if d.CertMode != "" {
		return fmt.Errorf(
			"cert_mode does not apply to a %s destination — the keystore holds the private key, "+
				"so it takes key_mode and defaults to 0600", d.format())
	}
	switch {
	case d.KeystorePassword != "" && d.KeystorePasswordFile != "":
		return fmt.Errorf("give keystore_password or keystore_password_file, not both")
	case d.KeystorePassword == "" && d.KeystorePasswordFile == "":
		// No default, deliberately. See the field comment: `changeit` is what
		// every Java tutorial uses, and defaulting to it would look like
		// protection while being none.
		return fmt.Errorf(
			"a %s destination needs keystore_password or keystore_password_file. There is no "+
				"default: this value has to match what the application reading the keystore is "+
				"configured with, and a well-known one would be worse than none", d.format())
	}
	return nil
}
