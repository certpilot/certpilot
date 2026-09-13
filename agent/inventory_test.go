package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
)

// writePair creates a certificate and, optionally, its key on disk.
func writePair(t *testing.T, dir, stem, commonName string, keyMode os.FileMode, sameFile bool) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if sameFile {
		if err := os.WriteFile(filepath.Join(dir, stem+".pem"), append(certPEM, keyPEM...), keyMode); err != nil {
			t.Fatalf("write: %v", err)
		}
		return key
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".crt"), certPEM, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if keyMode != 0 {
		if err := os.WriteFile(filepath.Join(dir, stem+".key"), keyPEM, keyMode); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return key
}

func find(t *testing.T, report agentapi.InventoryReport, suffix string) agentapi.Discovered {
	t.Helper()
	for _, c := range report.Certificates {
		if filepath.Base(c.Path) == suffix {
			return c
		}
	}
	t.Fatalf("%s was not found in the report; got %d files", suffix, len(report.Certificates))
	return agentapi.Discovered{}
}

// TestTheScanReportsWhatOnlyTheHostCanSee — the permissions on the private key,
// and whether it belongs to the certificate beside it. Neither is visible to
// anything watching from the network.
func TestTheScanReportsWhatOnlyTheHostCanSee(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "exposed", "exposed.example.com", 0o644, false)
	writePair(t, dir, "safe", "safe.example.com", 0o600, false)

	report := Scan([]string{dir})

	exposed := find(t, report, "exposed.crt")
	if exposed.PrivateKeyMode != "0644" {
		t.Fatalf("the key's mode should be reported, got %q", exposed.PrivateKeyMode)
	}
	if !exposed.PrivateKeyMatches {
		t.Fatal("a key generated for this certificate should match it")
	}

	safe := find(t, report, "safe.crt")
	if safe.PrivateKeyMode != "0600" {
		t.Fatalf("expected 0600, got %q", safe.PrivateKeyMode)
	}
}

// TestAMismatchedPairIsSeenAsOne. Quiet until something restarts the service,
// and then an outage that looks like it came from nowhere.
func TestAMismatchedPairIsSeenAsOne(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "site", "site.example.com", 0o600, false)

	// Somebody replaced the certificate and forgot the key — or the reverse.
	writePair(t, filepath.Join(dir), "other", "other.example.com", 0o600, false)
	otherKey, err := os.ReadFile(filepath.Join(dir, "other.key"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "site.key"), otherKey, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	site := find(t, Scan([]string{dir}), "site.crt")
	if site.PrivateKeyPath == "" {
		t.Fatal("the key beside it should have been found")
	}
	if site.PrivateKeyMatches {
		t.Fatal("a key for a different certificate must not be reported as matching")
	}
}

// TestACombinedFileIsMarkedAsOne. HAProxy requires this layout, and the file's
// permissions then matter as much as a key file's — which is very often not how
// they are set.
func TestACombinedFileIsMarkedAsOne(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "haproxy", "lb.example.com", 0o644, true)

	found := find(t, Scan([]string{dir}), "haproxy.pem")
	if !found.PrivateKeyInSameFile {
		t.Fatal("a certificate concatenated with its key should be marked as such")
	}
	if found.PrivateKeyMode != "0644" {
		t.Fatalf("the combined file's own mode is the key's mode, got %q", found.PrivateKeyMode)
	}
	if !found.PrivateKeyMatches {
		t.Fatal("the key in the same file should match")
	}
}

// TestATrustStoreIsOneRowNotAHundred. The distribution manages those roots and
// nobody here is responsible for them; a hundred findings would bury every real
// one on the host.
func TestATrustStoreIsOneRowNotAHundred(t *testing.T) {
	dir := t.TempDir()

	var bundle []byte
	for i := 0; i < 25; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "Root " + string(rune('A'+i))},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-bundle.crt"), bundle, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	report := Scan([]string{dir})
	if len(report.Certificates) != 1 {
		t.Fatalf("a bundle should be one row, got %d", len(report.Certificates))
	}
	found := report.Certificates[0]
	if found.Kind != agentapi.KindBundle {
		t.Fatalf("expected kind bundle, got %q", found.Kind)
	}
	if found.CertificateCount != 25 {
		t.Fatalf("the count is what makes it legible, got %d", found.CertificateCount)
	}
}

// TestAConfigurationReferenceIsFound, which is what turns "a file exists" into
// "something is serving this".
func TestAConfigurationReferenceIsFound(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "site", "site.example.com", 0o600, false)

	conf := "server {\n  listen 443 ssl;\n  ssl_certificate " +
		filepath.Join(dir, "site.crt") + ";\n  ssl_certificate_key " +
		filepath.Join(dir, "site.key") + ";\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	found := find(t, Scan([]string{dir}), "site.crt")
	if len(found.ReferencedBy) != 1 {
		t.Fatalf("the nginx configuration should have been matched, got %v", found.ReferencedBy)
	}
}

// TestASymlinkFarmIsOneRow. Certbot lays out live/ as symlinks into archive/,
// and reporting both would double every certbot host's inventory.
func TestASymlinkFarmIsOneRow(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")
	live := filepath.Join(dir, "live")
	for _, d := range []string{archive, live} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	writePair(t, archive, "cert1", "site.example.com", 0o600, false)
	if err := os.Symlink(filepath.Join(archive, "cert1.crt"), filepath.Join(live, "cert.crt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	report := Scan([]string{dir})
	if len(report.Certificates) != 1 {
		paths := []string{}
		for _, c := range report.Certificates {
			paths = append(paths, c.Path)
		}
		t.Fatalf("the same file reached twice should be one row, got %v", paths)
	}
}

// TestNoPrivateKeyCanTravelInAReport. The property the whole agent rests on,
// asserted against the serialized bytes rather than against the struct, because
// what matters is what goes on the wire.
func TestNoPrivateKeyCanTravelInAReport(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "site", "site.example.com", 0o600, false)
	writePair(t, dir, "combined", "lb.example.com", 0o644, true)

	report := Scan([]string{dir})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("a private key appeared in a report")
	}
	if len(report.Certificates) == 0 {
		t.Fatal("nothing was found, so this proves nothing")
	}
}

// TestASelfSignedServerCertificateIsALeaf.
//
// OpenSSL's `req -x509` sets basicConstraints CA:TRUE by default, so most
// self-signed certificates on an internal estate claim to be authorities.
// Trusting that claim classified them as CAs and made them skip every finding
// that only applies to leaves — which is most of the interesting ones.
func TestASelfSignedServerCertificateIsALeaf(t *testing.T) {
	dir := t.TempDir()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	server := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "internal.example.com"},
		DNSNames:              []string{"internal.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true, // exactly what openssl req -x509 produces
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, server, server, &key.PublicKey, key)
	if err := os.WriteFile(filepath.Join(dir, "server.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// And a genuine root: same claim, no names, nothing it could be serving.
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Example Internal Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err := os.WriteFile(filepath.Join(dir, "root.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	report := Scan([]string{dir})
	if got := find(t, report, "server.crt").Kind; got != agentapi.KindLeaf {
		t.Fatalf("a self-signed certificate with a hostname is a leaf, got %q", got)
	}
	if got := find(t, report, "root.crt").Kind; got != agentapi.KindCA {
		t.Fatalf("a certificate with no names is an authority, got %q", got)
	}
}

// TestAGuessedKeyNameIsNotAMismatch.
//
// A directory holding a leaf, its chain, and one `key.pem` is completely
// ordinary. Pairing the chain with that key by filename and reporting the
// failure as a mismatch produced a CRITICAL alert about a CA certificate whose
// "key" was the leaf's — the kind of false positive that teaches people to
// ignore the real ones.
func TestAGuessedKeyNameIsNotAMismatch(t *testing.T) {
	dir := t.TempDir()

	// The layout the agent itself writes: cert.pem, chain.pem, key.pem.
	writePair(t, dir, "leaf", "site.example.com", 0o600, false)
	leafCert, _ := os.ReadFile(filepath.Join(dir, "leaf.crt"))
	leafKey, _ := os.ReadFile(filepath.Join(dir, "leaf.key"))
	writePair(t, dir, "other", "Some Issuing CA", 0o600, false)
	chain, _ := os.ReadFile(filepath.Join(dir, "other.crt"))

	for name, body := range map[string][]byte{
		"cert.pem": leafCert, "key.pem": leafKey, "chain.pem": chain,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, stale := range []string{"leaf.crt", "leaf.key", "other.crt", "other.key"} {
		_ = os.Remove(filepath.Join(dir, stale))
	}

	report := Scan([]string{dir})

	leaf := find(t, report, "cert.pem")
	if leaf.PrivateKeyPath == "" || !leaf.PrivateKeyMatches {
		t.Fatalf("the leaf's key should be found by convention and match: %+v", leaf)
	}

	other := find(t, report, "chain.pem")
	if other.PrivateKeyPath != "" {
		t.Fatalf("a guessed key that does not match is evidence the key is elsewhere, not a mismatch: %+v", other)
	}
}

// TestAStemNamedKeyThatDoesNotMatchIsStillAMismatch. `site.key` beside
// `site.crt` is a statement that the two belong together.
func TestAStemNamedKeyThatDoesNotMatchIsStillAMismatch(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "site", "site.example.com", 0o600, false)
	writePair(t, dir, "other", "other.example.com", 0o600, false)

	otherKey, _ := os.ReadFile(filepath.Join(dir, "other.key"))
	if err := os.WriteFile(filepath.Join(dir, "site.key"), otherKey, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	site := find(t, Scan([]string{dir}), "site.crt")
	if site.PrivateKeyPath == "" || site.PrivateKeyMatches {
		t.Fatalf("a stem-named key that does not match is a real mismatch: %+v", site)
	}
}
