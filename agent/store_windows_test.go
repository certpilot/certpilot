//go:build windows

package agent

// The half of the certificate store that only a real Windows kernel can answer.
//
// store_test.go covers the ordering — what is imported, bound, named and
// removed, and in which order when something fails — against a fake, on
// whatever machine somebody is sitting at. None of that touches CryptoAPI.
//
// What is here is everything that would pass a cross-compile and fail on a
// host: whether Windows will read the PKCS#12 this agent encodes, whether the
// friendly name it marks its own work with survives a round trip through the
// registry, whether an intermediate ends up where schannel looks for it, and
// whether deleting a certificate takes its private key with it. Every one of
// those has a plausible implementation that builds.
//
// CurrentUser\My rather than LocalMachine\My, deliberately. The stores behave
// identically for everything asserted below, and writing to the machine store
// needs an elevated process — so a suite that used it would pass on a runner
// that happens to be elevated and fail on a developer's desktop, which is the
// worst of both. The machine store is exercised end to end by the IIS job,
// where being elevated is the point.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var testStore = storeName{location: "CurrentUser", name: "My", text: `CurrentUser\My`}
var testCAStore = storeName{location: "CurrentUser", name: "CA", text: `CurrentUser\CA`}

// cleanUp takes a thumbprint out of a store at the end of a test, so a failing
// run does not leave certificates behind on a machine somebody is using.
func cleanUp(t *testing.T, sn storeName, thumbprint string) {
	t.Helper()
	t.Cleanup(func() { _ = windowsStore{}.remove(sn, thumbprint) })
}

// TestWindowsReadsWhatTheAgentEncodes.
//
// The first thing that could be wrong and would never show up in a build.
// pkcs12.Modern writes AES-256-CBC with PBKDF2 and a SHA-256 MAC, and the
// alternative in that library writes RC2 — so this is the test that decides
// whether the modern encoding was the right call or whether an estate would
// have been handed a decade-old cipher to satisfy an importer.
func TestWindowsReadsWhatTheAgentEncodes(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "roundtrip.example.com")
	material, err := readMaterial(held)
	if err != nil {
		t.Fatal(err)
	}
	pfx, password, err := encodeForStore(material)
	if err != nil {
		t.Fatal(err)
	}

	cleanUp(t, testStore, thumbprint)
	added, err := windowsStore{}.importPFX(testStore, pfx, password)
	if err != nil {
		t.Fatalf("Windows would not import what this agent encodes: %v", err)
	}
	if !contains(added, thumbprint) {
		t.Fatalf("the import reported %v and not %s", added, thumbprint)
	}
}

// TestTheAgentRecognisesItsOwnWork.
//
// The friendly name is how a renewal finds the certificate it is replacing, and
// therefore the only thing a rollback has to go back to. If it did not survive
// being written into the store and read out of it, every renewal would look
// like a first install: nothing to remove, and nothing to put the binding back
// to when one failed.
func TestTheAgentRecognisesItsOwnWork(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "named.example.com")
	material, err := readMaterial(held)
	if err != nil {
		t.Fatal(err)
	}
	pfx, password, err := encodeForStore(material)
	if err != nil {
		t.Fatal(err)
	}

	store := windowsStore{}
	cleanUp(t, testStore, thumbprint)
	if _, err := store.importPFX(testStore, pfx, password); err != nil {
		t.Fatal(err)
	}

	// Before it is named, it is not this destination's.
	found, err := store.thumbprintNamed(testStore, "CertPilot: iis")
	if err != nil {
		t.Fatal(err)
	}
	if found != "" {
		t.Fatalf("an unnamed certificate was claimed as this destination's: %s", found)
	}

	if err := store.setFriendlyName(testStore, thumbprint, "CertPilot: iis"); err != nil {
		t.Fatalf("could not name it: %v", err)
	}
	found, err = store.thumbprintNamed(testStore, "CertPilot: iis")
	if err != nil {
		t.Fatal(err)
	}
	if found != thumbprint {
		t.Fatalf("the name did not survive the store: found %q, want %s", found, thumbprint)
	}

	// And a different destination's name does not match it, which is what keeps
	// two destinations on one host from removing each other's certificates.
	other, err := store.thumbprintNamed(testStore, "CertPilot: exchange")
	if err != nil {
		t.Fatal(err)
	}
	if other != "" {
		t.Errorf("a certificate named for one destination was found under another: %s", other)
	}
}

// TestTheChainGoesWhereSchannelLooksForIt.
//
// A leaf, a real intermediate and a self-signed root. Schannel builds the chain
// it sends from the CA store rather than from whatever arrived beside the leaf,
// so an intermediate that stayed in My is an intermediate never sent — the same
// defect as an nginx configuration naming cert.pem instead of fullchain.pem.
//
// And the root goes nowhere, which is the more important half. The store that
// would make it work is Root, and writing to Root is making a certificate
// authority trusted by every program on the machine.
func TestTheChainGoesWhereSchannelLooksForIt(t *testing.T) {
	leaf, intermediate, root, pfx, password := threeDeepChain(t)

	store := windowsStore{}
	cleanUp(t, testStore, leaf)
	cleanUp(t, testCAStore, intermediate)

	added, err := store.importPFX(testStore, pfx, password)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if !inStore(t, testStore, leaf) {
		t.Errorf("the issued certificate is not in %s", testStore)
	}
	if inStore(t, testStore, intermediate) {
		t.Errorf("the intermediate was left in %s, where schannel does not look for it", testStore)
	}
	if !inStore(t, testCAStore, intermediate) {
		t.Errorf("the intermediate is not in %s, so schannel would send the leaf alone", testCAStore)
	}
	if !contains(added, intermediate) {
		t.Errorf("the import did not report the intermediate it added: %v", added)
	}

	// The assertion that matters most, and the one whose failure is silent: a
	// certificate authority the machine now trusts because a renewal ran.
	for _, sn := range []storeName{
		testStore,
		testCAStore,
		{location: "CurrentUser", name: "Root", text: `CurrentUser\Root`},
	} {
		if inStore(t, sn, root) {
			t.Errorf("the root was imported into %s; installing a certificate is not the same "+
				"as making its authority trusted", sn)
		}
	}
	if contains(added, root) {
		t.Errorf("the import reported adding the root: %v", added)
	}
}

// TestRemovingACertificateTakesItsPrivateKeyWithIt.
//
// Deleting a certificate from a store does not delete its key: the key lives in
// the storage provider and the certificate merely points at it. So the obvious
// implementation leaks one key blob per renewal, on every host, forever — a few
// hundred bytes each, which is nothing, and a growing directory of unreferenced
// private key material, which is not.
//
// Counted on disk rather than asserted through the API, because the claim is
// about what is left behind rather than about what a handle says.
func TestRemovingACertificateTakesItsPrivateKeyWithIt(t *testing.T) {
	keys := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Crypto", "Keys")
	before, err := os.ReadDir(keys)
	if err != nil {
		t.Skipf("this runner keeps CNG keys somewhere else; %s: %v", keys, err)
	}

	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "keydeletion.example.com")
	material, err := readMaterial(held)
	if err != nil {
		t.Fatal(err)
	}
	pfx, password, err := encodeForStore(material)
	if err != nil {
		t.Fatal(err)
	}

	store := windowsStore{}
	cleanUp(t, testStore, thumbprint)
	if _, err := store.importPFX(testStore, pfx, password); err != nil {
		t.Fatal(err)
	}

	during, err := os.ReadDir(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(during) <= len(before) {
		// Nothing was written where this test can see it, so the assertion
		// below would pass whatever the implementation did.
		t.Skipf("importing wrote no key into %s, so there is nothing here to prove", keys)
	}

	if err := store.remove(testStore, thumbprint); err != nil {
		t.Fatalf("remove: %v", err)
	}
	after, err := os.ReadDir(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Errorf("removing the certificate left %d private key file(s) behind in %s; every "+
			"renewal on this host would add another", len(after)-len(before), keys)
	}
}

// TestRemovingSomethingThatIsNotThereIsNotAnError. It is the state the caller
// asked for, and a rollback that failed because it had already succeeded would
// turn a recoverable failure into a reported one.
func TestRemovingSomethingThatIsNotThereIsNotAnError(t *testing.T) {
	if err := (windowsStore{}).remove(testStore, strings.Repeat("AB", 20)); err != nil {
		t.Errorf("removing an absent certificate reported an error: %v", err)
	}
}

// ── The destination, read the way the agent reads it ────────

// TestTheIISProfileProducesAnInstallableDestination is the counterpart of the
// catalogue test in profile_test.go, which skips this profile because it is not
// for the platform that test runs on.
func TestTheIISProfileProducesAnInstallableDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installs.json")
	body := `{"destinations":[{"name":"iis","certificate":"www.example.com","profile":"iis",
		"verify":"{{ .Certificate }}:443"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadInstallSpec(path)
	if err != nil {
		t.Fatalf("the iis profile does not produce a valid destination: %v", err)
	}
	d := spec.Destinations[0]
	if d.Store != `LocalMachine\My` {
		t.Errorf("store = %q", d.Store)
	}
	if !hasThumbprintPlaceholder(d.Bind) {
		t.Errorf("bind carries no thumbprint: %v", d.Bind)
	}
	if d.Verify != "www.example.com:443" {
		t.Errorf("verify = %q, want the certificate name substituted", d.Verify)
	}
	if d.friendlyName() != "CertPilot: iis" {
		t.Errorf("friendly name = %q", d.friendlyName())
	}
}

// TestAStoreDestinationRefusesWhatItWouldIgnore.
//
// Every field here is one an operator would otherwise set, see accepted, and
// believe had taken effect — a mode on a file that is never written, a keystore
// password for a keystore that is never produced, a check on a platform that
// has none.
func TestAStoreDestinationRefusesWhatItWouldIgnore(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Destination)
		mustSay string
	}{
		{"cert_path", func(d *Destination) { d.CertPath = `C:\certpilot\cert.pem` }, "writes no file at all"},
		{"key_path", func(d *Destination) { d.KeyPath = `C:\certpilot\privkey.pem` }, "writes no file at all"},
		{"format", func(d *Destination) { d.Format = FormatPKCS12 }, "writes none"},
		{"key_mode", func(d *Destination) { d.KeyMode = "0600" }, "writes no file"},
		{"keystore_password", func(d *Destination) { d.KeystorePassword = "changeit" }, "generates and discards"},
		{"keystore_alias", func(d *Destination) { d.KeystoreAlias = "tomcat" }, "found by thumbprint"},
		{"check", func(d *Destination) { d.Check = []string{`C:\check.exe`} }, "no `nginx -t` for a certificate store"},
		{"owner", func(d *Destination) { d.Owner = "IIS_IUSRS" }, "does not have"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Destination{
				Name: "iis", Certificate: "www.example.com",
				Store: `LocalMachine\My`,
				Bind:  []string{`C:\bind.exe`, thumbprintPlaceholder},
			}
			tc.mutate(&d)
			err := d.validate()
			if err == nil {
				t.Fatalf("a store destination accepted %s and would have ignored it", tc.name)
			}
			if !strings.Contains(err.Error(), tc.mustSay) {
				t.Errorf("the message does not explain it: %v", err)
			}
		})
	}
}

// A bind with no thumbprint in it runs, exits 0, and re-points nothing — so the
// host keeps serving the certificate it had until that one expires. Refused
// when the spec is read, which is the only moment anybody is watching.
func TestABindWithNoThumbprintIsRefused(t *testing.T) {
	d := Destination{
		Name: "iis", Certificate: "www.example.com",
		Store: `LocalMachine\My`,
		Bind:  []string{`C:\bind.exe`, "--site", "Default Web Site"},
	}
	err := d.validate()
	if err == nil {
		t.Fatal("a bind command that re-points nothing was accepted")
	}
	if !strings.Contains(err.Error(), thumbprintPlaceholder) {
		t.Errorf("the message does not say what is missing: %v", err)
	}
}

// TestAWindowsCommandGetsAnEnvironmentItCanStartIn.
//
// powershell.exe exits before running a word without SystemRoot, and
// Import-Module WebAdministration — which is how a certificate is bound to an
// IIS site — finds nothing without PSModulePath. The environment a command runs
// in was a single hard-coded Unix PATH for as long as the only destinations
// that ran commands were Linux ones.
func TestAWindowsCommandGetsAnEnvironmentItCanStartIn(t *testing.T) {
	env := map[string]string{}
	for _, entry := range commandEnv() {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	for _, required := range []string{"SystemRoot", "PATH", "PSModulePath", "PATHEXT", "ComSpec"} {
		if strings.TrimSpace(env[required]) == "" {
			t.Errorf("%s is not set, and a Windows bind command needs it to start", required)
		}
	}
	if !strings.Contains(strings.ToLower(env["PSModulePath"]), "windowspowershell") {
		t.Errorf("PSModulePath does not include the system module directory: %q", env["PSModulePath"])
	}
	// The whole point of a bare environment: nothing of the agent's own.
	for _, leaked := range []string{"CERTPILOT_AGENT_STATE", "CERTPILOT_TOKEN", "USERPROFILE"} {
		if _, ok := env[leaked]; ok {
			t.Errorf("%s was passed through to a command out of the install spec", leaked)
		}
	}
}

// ── Fixtures ────────────────────────────────────────────────

// threeDeepChain builds root → intermediate → leaf, encodes it the way the
// agent would, and returns each thumbprint alongside the blob.
func threeDeepChain(t *testing.T) (leaf, intermediate, root string, pfx []byte, password string) {
	t.Helper()
	rootCert, rootKey := certificateAuthority(t, "Fixture Root", nil, nil)
	interCert, interKey := certificateAuthority(t, "Fixture Issuing CA", rootCert, rootKey)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "chain.example.com"},
		DNSNames:     []string{"chain.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, interCert, &key.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	pfx, password = encodeChain(t, leafCert, key, []*x509.Certificate{interCert, rootCert})
	return thumbprintOf(leafDER), thumbprintOf(interCert.Raw), thumbprintOf(rootCert.Raw), pfx, password
}

func inStore(t *testing.T, sn storeName, thumbprint string) bool {
	t.Helper()
	store, err := openStore(sn)
	if err != nil {
		t.Fatalf("could not open %s: %v", sn, err)
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	ctx, err := findByThumbprint(store, thumbprint)
	if err != nil {
		t.Fatalf("could not search %s: %v", sn, err)
	}
	if ctx == nil {
		return false
	}
	_ = windows.CertFreeCertificateContext(ctx)
	return true
}

// certificateAuthority signs, so the fixtures below are a real chain rather than
// three self-signed certificates that would all be treated as roots.
func certificateAuthority(t *testing.T, name string, parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func encodeChain(t *testing.T, leaf *x509.Certificate, key *ecdsa.PrivateKey,
	cas []*x509.Certificate) ([]byte, string) {
	t.Helper()
	pfx, err := pkcs12.Modern.Encode(key, leaf, cas, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	return pfx, "fixture"
}
