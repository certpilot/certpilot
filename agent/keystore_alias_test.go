package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// keystoreFixture builds a leaf genuinely signed by a CA, so that a decoded
// chain means something.
func keystoreFixture(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leafKey, leaf, ca
}

func encodeFixture(t *testing.T, password string) []byte {
	t.Helper()
	key, leaf, ca := keystoreFixture(t)
	out, err := pkcs12.Modern.Encode(key, leaf, []*x509.Certificate{ca}, password)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMacMatchesLibrary is what makes the hand-written KDF trustworthy.
//
// pbkdf here is a reimplementation of RFC 7292 appendix B.2, because
// go-pkcs12 does not export the one it uses. Rather than trust that, this
// recomputes the MAC of a keystore the library has just written and requires
// the bytes to be identical. If the derivation is wrong in any respect — the
// diversifier, the block arithmetic, the password encoding — the digests
// differ and this fails.
func TestMacMatchesLibrary(t *testing.T) {
	const password = "correct horse battery staple"
	pfxData := encodeFixture(t, password)

	var pfx pfxPdu
	if _, err := asn1.Unmarshal(pfxData, &pfx); err != nil {
		t.Fatal(err)
	}
	var authSafeDER []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeDER); err != nil {
		t.Fatal(err)
	}

	written := append([]byte(nil), pfx.MacData.Mac.Digest...)
	if len(written) == 0 {
		t.Fatal("the library wrote no MAC, so this test proves nothing")
	}

	pfx.MacData.Mac.Digest = nil
	if err := recomputeMac(&pfx.MacData, authSafeDER, password); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, pfx.MacData.Mac.Digest) {
		t.Fatalf("MAC derived here does not match the library's\n library: %x\n    here: %x",
			written, pfx.MacData.Mac.Digest)
	}
}

// TestSetKeystoreAliasRoundTrips proves the rewritten keystore is still a
// keystore: same key, same chain, same password.
func TestSetKeystoreAliasRoundTrips(t *testing.T) {
	const password = "changeit"
	original := encodeFixture(t, password)

	beforeKey, beforeLeaf, beforeCA, err := pkcs12.DecodeChain(original, password)
	if err != nil {
		t.Fatal(err)
	}

	named, err := setKeystoreAlias(original, password, "tomcat")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, named) {
		t.Fatal("setKeystoreAlias returned the input unchanged")
	}

	afterKey, afterLeaf, afterCA, err := pkcs12.DecodeChain(named, password)
	if err != nil {
		t.Fatalf("the named keystore no longer decodes: %v", err)
	}
	if !afterLeaf.Equal(beforeLeaf) {
		t.Error("the certificate changed")
	}
	if len(afterCA) != len(beforeCA) {
		t.Fatalf("chain length changed: %d -> %d", len(beforeCA), len(afterCA))
	}
	for i := range afterCA {
		if !afterCA[i].Equal(beforeCA[i]) {
			t.Errorf("chain entry %d changed", i)
		}
	}
	// Compared as encoded keys rather than by reaching into the struct:
	// ecdsa.PrivateKey.D is deprecated in Go 1.26, and marshalling is what the
	// keystore did with the key in the first place.
	beforeDER, err := x509.MarshalPKCS8PrivateKey(beforeKey)
	if err != nil {
		t.Fatal(err)
	}
	afterDER, err := x509.MarshalPKCS8PrivateKey(afterKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeDER, afterDER) {
		t.Error("the private key changed")
	}
}

// TestSetKeystoreAliasWritesFriendlyName checks the attribute is actually
// present on the key bag, which is where Java reads the alias from. Decoding
// alone would not notice its absence.
func TestSetKeystoreAliasWritesFriendlyName(t *testing.T) {
	const password = "changeit"
	named, err := setKeystoreAlias(encodeFixture(t, password), password, "tomcat")
	if err != nil {
		t.Fatal(err)
	}

	found := keyBagAliases(t, named)
	if len(found) != 1 || found[0] != "tomcat" {
		t.Fatalf("expected one key entry named %q, got %v", "tomcat", found)
	}
}

// TestSetKeystoreAliasMacIsValid proves the MAC was recomputed rather than left
// stale. A stale MAC decodes as a wrong password, so this breaks the
// implementation deliberately to show the check is load-bearing.
func TestSetKeystoreAliasMacIsValid(t *testing.T) {
	const password = "changeit"
	named, err := setKeystoreAlias(encodeFixture(t, password), password, "tomcat")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pkcs12.DecodeChain(named, password); err != nil {
		t.Fatalf("the named keystore rejects its own password: %v", err)
	}
	if _, _, _, err := pkcs12.DecodeChain(named, "not-the-password"); err == nil {
		t.Fatal("the named keystore accepted the wrong password")
	}
}

func TestSetKeystoreAliasEmptyIsNoOp(t *testing.T) {
	original := encodeFixture(t, "changeit")
	out, err := setKeystoreAlias(original, "changeit", "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, out) {
		t.Fatal("an empty alias changed the keystore")
	}
}

func TestSetKeystoreAliasRejectsUnencodableAlias(t *testing.T) {
	// U+1F512, outside the basic multilingual plane.
	_, err := setKeystoreAlias(encodeFixture(t, "changeit"), "changeit", "lock\U0001F512")
	if err == nil {
		t.Fatal("expected an alias outside the BMP to be refused")
	}
	if !strings.Contains(err.Error(), "cannot be encoded") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestSetKeystoreAliasRejectsRubbish(t *testing.T) {
	if _, err := setKeystoreAlias([]byte("not a keystore"), "changeit", "tomcat"); err == nil {
		t.Fatal("expected non-PKCS#12 input to be refused")
	}
}

// keyBagAliases reads back the friendlyName on every key bag, the same way a
// JDK would.
func keyBagAliases(t *testing.T, pfxData []byte) []string {
	t.Helper()

	var pfx pfxPdu
	if _, err := asn1.Unmarshal(pfxData, &pfx); err != nil {
		t.Fatal(err)
	}
	var authSafeDER []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafeDER); err != nil {
		t.Fatal(err)
	}
	var safes []contentInfo
	if _, err := asn1.Unmarshal(authSafeDER, &safes); err != nil {
		t.Fatal(err)
	}

	var out []string
	for _, safe := range safes {
		if !safe.ContentType.Equal(oidDataContentType) {
			continue
		}
		var bagsDER []byte
		if _, err := asn1.Unmarshal(safe.Content.Bytes, &bagsDER); err != nil {
			t.Fatal(err)
		}
		var bags []safeBag
		if _, err := asn1.Unmarshal(bagsDER, &bags); err != nil {
			t.Fatal(err)
		}
		for _, bag := range bags {
			if !bag.Id.Equal(oidKeyBag) && !bag.Id.Equal(oidPKCS8ShroundedKeyBag) {
				continue
			}
			for _, attr := range bag.Attributes {
				if !attr.Id.Equal(oidFriendlyName) {
					continue
				}
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(attr.Value.Bytes, &raw); err != nil {
					t.Fatal(err)
				}
				out = append(out, decodeBMP(t, raw.Bytes))
			}
		}
	}
	return out
}

func decodeBMP(t *testing.T, b []byte) string {
	t.Helper()
	if len(b)%2 != 0 {
		t.Fatalf("BMPString of odd length %d", len(b))
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 2 {
		sb.WriteRune(rune(b[i])<<8 | rune(b[i+1]))
	}
	return sb.String()
}
