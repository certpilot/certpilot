package agent

// The certificate store, tested everywhere.
//
// No build tag, deliberately. Windows is the only platform with a certificate
// store to install into, and the part of this most likely to be wrong is not
// the syscalls — it is the order of the four steps taken when something fails
// halfway through, which is ordinary Go and whose failure is an outage rather
// than an inconvenience.
//
// So certStore is an interface, the fake below records what it was asked to do
// and when, and the command runner writes into the same log. That makes
// "the binding was put back before the certificate was removed" an assertion
// somebody can run and break on the machine they are sitting at, rather than
// something confirmed by pushing to CI and reading a Windows log.
//
// What genuinely needs Windows — that PFXImportCertStore accepts what this
// encodes, that the friendly name survives a round trip, that a key is deleted
// with its certificate — is in store_windows_test.go and runs on a real runner.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ── A fake store that remembers the order it was used in ────

type fakeStore struct {
	log *[]string

	held map[string]string // thumbprint -> friendly name

	importErr error
	readErr   error
	nameErr   error
	removeErr error
}

func (f *fakeStore) record(format string, args ...any) {
	*f.log = append(*f.log, fmt.Sprintf(format, args...))
}

func (f *fakeStore) importPFX(sn storeName, pfx []byte, password string) ([]string, error) {
	if f.importErr != nil {
		f.record("import failed")
		return nil, f.importErr
	}
	// Decoded rather than accepted, so that a change to encodeForStore which
	// produced something no importer could read would fail here rather than on
	// a Windows host six weeks later.
	thumbprints, err := thumbprintsIn(pfx, password)
	if err != nil {
		return nil, err
	}
	for _, t := range thumbprints {
		if _, ok := f.held[t]; !ok {
			f.held[t] = ""
		}
	}
	f.record("import %s into %s", strings.Join(thumbprints, "+"), sn)
	return thumbprints, nil
}

func (f *fakeStore) thumbprintNamed(sn storeName, friendly string) (string, error) {
	if f.readErr != nil {
		return "", f.readErr
	}
	f.record("read %s", sn)
	for thumbprint, name := range f.held {
		if name == friendly {
			return thumbprint, nil
		}
	}
	return "", nil
}

func (f *fakeStore) setFriendlyName(sn storeName, thumbprint, friendly string) error {
	if f.nameErr != nil {
		return f.nameErr
	}
	if _, ok := f.held[thumbprint]; !ok {
		return fmt.Errorf("%s holds no %s", sn, thumbprint)
	}
	f.held[thumbprint] = friendly
	f.record("name %s %q", thumbprint, friendly)
	return nil
}

func (f *fakeStore) remove(sn storeName, thumbprint string) error {
	if f.removeErr != nil {
		f.record("remove %s failed", thumbprint)
		return f.removeErr
	}
	delete(f.held, thumbprint)
	f.record("remove %s", thumbprint)
	return nil
}

// thumbprintsIn reads a PKCS#12 back the way the importer would.
func thumbprintsIn(pfx []byte, password string) ([]string, error) {
	_, leaf, cas, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, fmt.Errorf("what the agent encoded could not be read back: %w", err)
	}
	out := []string{thumbprintOf(leaf.Raw)}
	for _, ca := range cas {
		out = append(out, thumbprintOf(ca.Raw))
	}
	return out, nil
}

// ── The command runner, writing into the same log ───────────

type boundCommands struct {
	log    *[]string
	failOn map[string]int
}

func (b *boundCommands) run(_ context.Context, argv []string) (string, error) {
	text := commandText(argv)
	if b.failOn[text] > 0 {
		b.failOn[text]--
		*b.log = append(*b.log, "run(failed) "+text)
		return "the binding was refused", errors.New("exit status 1")
	}
	*b.log = append(*b.log, "run "+text)
	return "", nil
}

// ── A host with one certificate on it ───────────────────────

// storeHeld writes a certificate and its issuer into a state directory, and
// returns what the agent would hold plus the thumbprint Windows would know the
// leaf by.
//
// The CA genuinely signs the leaf, so the chain has two certificates in it. A
// self-signed fixture would make every chain length one and hide the half of
// this that decides where an intermediate goes.
func storeHeld(t *testing.T, stateDir, commonName string) (*Held, string) {
	t.Helper()
	dir := filepath.Join(stateDir, certsDir, slugOf(commonName))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name string, body []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), body, mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write(certFileName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o644)
	write(keyFileName, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	write(chainFileName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)

	held := &Held{
		CertificateID: "cert-" + commonName,
		Names:         []string{commonName},
		NotAfter:      leafTmpl.NotAfter,
		RenewAfter:    time.Now().Add(60 * 24 * time.Hour),
		Directory:     dir,
	}
	body, _ := json.MarshalIndent(held, "", "  ")
	write(metaFileName, append(body, '\n'), 0o600)
	return held, thumbprintOf(leafDER)
}

// storeInstaller wires a destination to a fake store and a recorded runner,
// both writing into one log so the order of what happened is a single list.
func storeInstaller(t *testing.T, dest Destination, held ...*Held) (*Installer, *fakeStore, *[]string) {
	t.Helper()
	log := &[]string{}
	store := &fakeStore{log: log, held: map[string]string{}}
	inst := NewInstaller(InstallSpec{Destinations: []Destination{dest}, Found: true}, "test-spec", held)
	inst.store = store
	inst.run = (&boundCommands{log: log, failOn: map[string]int{}}).run
	// Short, because three of the tests below turn on a verify that cannot
	// succeed and the default is a deadline for a real binding to go live.
	inst.verifyFor = 250 * time.Millisecond
	return inst, store, log
}

func failCommand(inst *Installer, log *[]string, text string, times int) {
	inst.run = (&boundCommands{log: log, failOn: map[string]int{text: times}}).run
}

func iisDestination() Destination {
	return Destination{
		Name: "iis", Certificate: "www.example.com",
		Store: `LocalMachine\My`,
		Bind:  []string{`C:\bind.exe`, "--thumbprint", thumbprintPlaceholder},
	}
}

func onlyInstallation(t *testing.T, report agentapi.InstallationReport) agentapi.Installation {
	t.Helper()
	if len(report.Installations) != 1 {
		t.Fatalf("expected one destination, got %d", len(report.Installations))
	}
	return report.Installations[0]
}

// indexOf finds an event in the log, or -1.
func indexOf(log []string, prefix string) int {
	for i, line := range log {
		if strings.HasPrefix(line, prefix) {
			return i
		}
	}
	return -1
}

func mustHappenBefore(t *testing.T, log []string, first, second string) {
	t.Helper()
	a, b := indexOf(log, first), indexOf(log, second)
	if a < 0 {
		t.Fatalf("%q never happened; the log was %v", first, log)
	}
	if b < 0 {
		t.Fatalf("%q never happened; the log was %v", second, log)
	}
	if a > b {
		t.Errorf("%q happened after %q; the log was %v", first, second, log)
	}
}

// ── The happy path ──────────────────────────────────────────

func TestACertificateIsImportedAndTheBindingIsRePointedAtIt(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	inst, store, log := storeInstaller(t, dest, held)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if store.held[thumbprint] != "CertPilot: iis" {
		t.Errorf("the certificate was not marked as this destination's: %v", store.held)
	}
	if !strings.Contains(strings.Join(*log, "|"), "run "+`C:\bind.exe --thumbprint `+thumbprint) {
		t.Errorf("the bind command did not receive the thumbprint; the log was %v", *log)
	}
	// Where it went, so the central view can answer it without logging in.
	if len(got.Paths) != 1 || got.Paths[0] != `LocalMachine\My` {
		t.Errorf("paths = %v, want the store", got.Paths)
	}
}

// The order settle() depends on. Naming the certificate before the binding is
// proved would leave the mark on something that is not serving anything, and
// the next renewal would roll back to it.
func TestTheCertificateIsNamedOnlyAfterItIsBound(t *testing.T) {
	state := t.TempDir()
	held, _ := storeHeld(t, state, "www.example.com")
	inst, _, log := storeInstaller(t, iisDestination(), held)

	if got := onlyInstallation(t, inst.Apply(context.Background(), nil)); got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	mustHappenBefore(t, *log, "run ", "name ")
}

// A renewal. The certificate the agent installed last time is removed, and only
// after the new one is bound — an installer that left one behind on every
// renewal would fill the store with expired certificates, which is a finding
// this same agent reports.
func TestTheCertificateItReplacesIsRemovedAfterTheNewOneIsBound(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	inst, store, log := storeInstaller(t, dest, held)
	store.held["OLDTHUMBPRINT"] = "CertPilot: iis"

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if _, still := store.held["OLDTHUMBPRINT"]; still {
		t.Error("the certificate this one replaces is still in the store")
	}
	if store.held[thumbprint] != "CertPilot: iis" {
		t.Error("the new certificate did not take the name")
	}
	mustHappenBefore(t, *log, "run ", "remove OLDTHUMBPRINT")
}

// A certificate nobody named is not this agent's to remove. Somebody else's
// certificate in the same store is somebody else's.
func TestACertificateThisAgentDidNotInstallIsLeftAlone(t *testing.T) {
	state := t.TempDir()
	held, _ := storeHeld(t, state, "www.example.com")

	inst, store, _ := storeInstaller(t, iisDestination(), held)
	store.held["SOMEONEELSES"] = "Exchange Auth Certificate"

	if got := onlyInstallation(t, inst.Apply(context.Background(), nil)); got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if _, still := store.held["SOMEONEELSES"]; !still {
		t.Error("a certificate this agent did not install was removed from the store")
	}
}

func TestNothingIsImportedWhenTheStoreAlreadyHoldsIt(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	inst, store, log := storeInstaller(t, iisDestination(), held)
	store.held[thumbprint] = "CertPilot: iis"

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if indexOf(*log, "import") >= 0 || indexOf(*log, "run ") >= 0 {
		t.Errorf("an unchanged destination imported or re-bound something: %v", *log)
	}
	if !strings.Contains(got.Detail, "nothing was imported") {
		t.Errorf("the report does not say nothing happened: %q", got.Detail)
	}
}

// What the core asks for when somebody presses deploy.
func TestForceReImportsWhatTheStoreAlreadyHolds(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	inst, store, log := storeInstaller(t, iisDestination(), held)
	store.held[thumbprint] = "CertPilot: iis"

	got := onlyInstallation(t, inst.Apply(context.Background(), map[string]bool{"iis": true}))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if indexOf(*log, "import") < 0 {
		t.Errorf("force did not re-import: %v", *log)
	}
}

// ── Failing, which is the point of the file ─────────────────

// Nothing was re-pointed, so the rollback is one step: take the import back out.
func TestABindThatFailsLeavesTheStoreAsItWasFound(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	inst, store, log := storeInstaller(t, dest, held)
	store.held["OLDTHUMBPRINT"] = "CertPilot: iis"
	failCommand(inst, log, commandText(withThumbprint(dest.Bind, thumbprint)), 5)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallFailed {
		t.Fatalf("a failed bind was reported as %s", got.Status)
	}
	if !got.RolledBack {
		t.Error("a failed bind that removed the import again is a rollback and is not reported as one")
	}
	if _, still := store.held[thumbprint]; still {
		t.Error("the certificate that could not be bound was left in the store")
	}
	if store.held["OLDTHUMBPRINT"] != "CertPilot: iis" {
		t.Error("the certificate that was working was disturbed")
	}
}

// The failure this whole file exists for. The binding has been changed, the new
// certificate does not work, and the previous one has to be back before
// anything else happens.
func TestAFailedVerifyPutsTheBindingBackBeforeRemovingAnything(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	// An address nothing is listening on, so verify cannot succeed. Real, not
	// faked: the check being tested is a TCP connection.
	dest.Verify = deadAddress(t)
	inst, store, log := storeInstaller(t, dest, held)
	store.held["OLDTHUMBPRINT"] = "CertPilot: iis"

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallFailed {
		t.Fatalf("a certificate nothing is serving was reported as %s", got.Status)
	}
	if !got.RolledBack {
		t.Errorf("the binding was put back and the report does not say so: %q", got.Detail)
	}

	mustHappenBefore(t,
		*log,
		"run "+commandText(withThumbprint(dest.Bind, "OLDTHUMBPRINT")),
		"remove "+thumbprint)

	if store.held["OLDTHUMBPRINT"] != "CertPilot: iis" {
		t.Error("the certificate the binding was put back to is no longer in the store")
	}
	if _, still := store.held[thumbprint]; still {
		t.Error("the certificate that failed was left in the store")
	}
}

// The one case where leaving the new certificate in place is right. A binding
// that names a certificate which is not there serves nothing at all, which is
// worse than serving the wrong one.
func TestTheImportIsLeftAloneWhenTheBindingCannotBePutBack(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	dest.Verify = deadAddress(t)
	inst, store, log := storeInstaller(t, dest, held)
	store.held["OLDTHUMBPRINT"] = "CertPilot: iis"
	// The re-bind is the command that fails, not the first bind.
	failCommand(inst, log, commandText(withThumbprint(dest.Bind, "OLDTHUMBPRINT")), 5)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.RolledBack {
		t.Error("a rollback that failed is reported as a rollback that worked")
	}
	if _, still := store.held[thumbprint]; !still {
		t.Fatal("the certificate a binding still names was removed, so the endpoint now serves nothing")
	}
	if !strings.Contains(got.Detail, "could not be put back") {
		t.Errorf("the report does not say the binding is wrong: %q", got.Detail)
	}
}

// The first install on a host. There is no earlier certificate of this agent's,
// so there is nothing to put the binding back to, and saying so is the whole
// of what can be done.
func TestTheFirstInstallSaysWhenItCannotBeUndone(t *testing.T) {
	state := t.TempDir()
	held, thumbprint := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	dest.Verify = deadAddress(t)
	inst, store, _ := storeInstaller(t, dest, held)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallFailed {
		t.Fatalf("status = %s", got.Status)
	}
	if got.RolledBack {
		t.Error("nothing was put back and the report says it was")
	}
	if _, still := store.held[thumbprint]; !still {
		t.Error("the certificate the binding now names was removed")
	}
	if !strings.Contains(got.Detail, "first certificate") {
		t.Errorf("the report does not explain why nothing could be undone: %q", got.Detail)
	}
}

// A store that cannot be read is a store that cannot be rolled back, so nothing
// is changed in it.
func TestAStoreThatCannotBeReadStopsBeforeImporting(t *testing.T) {
	state := t.TempDir()
	held, _ := storeHeld(t, state, "www.example.com")

	inst, store, log := storeInstaller(t, iisDestination(), held)
	store.readErr = errors.New("access is denied")

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallFailed {
		t.Fatalf("status = %s", got.Status)
	}
	if indexOf(*log, "import") >= 0 {
		t.Errorf("something was imported into a store that could not be read: %v", *log)
	}
	if !strings.Contains(got.Error, "nothing was imported") {
		t.Errorf("the report does not say nothing was done: %q", got.Error)
	}
}

// A store that would not be tidied is worth saying and is not worth undoing a
// working deployment for.
func TestAStoreThatCannotBeTidiedIsStillASuccessfulInstall(t *testing.T) {
	state := t.TempDir()
	held, _ := storeHeld(t, state, "www.example.com")

	inst, store, _ := storeInstaller(t, iisDestination(), held)
	store.held["OLDTHUMBPRINT"] = "CertPilot: iis"
	store.removeErr = errors.New("access is denied")

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("a bound and working certificate was reported as %s: %s", got.Status, got.Error)
	}
	if !strings.Contains(got.Detail, "OLDTHUMBPRINT") {
		t.Errorf("the report does not name what was left behind: %q", got.Detail)
	}
}

// A destination with no bind is legitimate — importing a certificate something
// else will pick up — and must not silently look like a binding.
func TestADestinationWithNoBindSaysNothingWasRePointed(t *testing.T) {
	state := t.TempDir()
	held, _ := storeHeld(t, state, "www.example.com")

	dest := iisDestination()
	dest.Bind = nil
	inst, _, _ := storeInstaller(t, dest, held)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallInstalled {
		t.Fatalf("status = %s: %s", got.Status, got.Error)
	}
	if !strings.Contains(got.Detail, "No bind is declared") {
		t.Errorf("the report reads as though something was bound: %q", got.Detail)
	}
}

// A destination for a name this host has not been granted. Reported from
// paths() rather than from cert_path, which a store destination leaves empty —
// "nothing has been written to " with the sentence ending there reads like a
// defect in the agent rather than a typo in the spec.
func TestAStoreDestinationForACertificateThisHostDoesNotHoldSaysWhereNothingWent(t *testing.T) {
	dest := iisDestination()
	dest.Certificate = "not.granted.example.com"
	inst, _, _ := storeInstaller(t, dest)

	got := onlyInstallation(t, inst.Apply(context.Background(), nil))
	if got.Status != agentapi.InstallUnfulfilled {
		t.Fatalf("status = %s", got.Status)
	}
	if !strings.Contains(got.Detail, `imported into LocalMachine\My`) {
		t.Errorf("the report does not say where nothing went: %q", got.Detail)
	}
}

// ── Verify, against a real listener ─────────────────────────

func TestVerifyRecognisesTheCertificateItIsServed(t *testing.T) {
	addr, thumbprint := serveTLS(t, "www.example.com")
	if err := verifyServes(context.Background(), addr, "www.example.com", thumbprint); err != nil {
		t.Fatalf("a listener serving exactly this certificate was not recognised: %v", err)
	}
}

func TestVerifyNoticesADifferentCertificate(t *testing.T) {
	addr, _ := serveTLS(t, "www.example.com")
	_, other := serveTLS(t, "other.example.com")

	err := verifyServes(context.Background(), addr, "www.example.com", other)
	if err == nil {
		t.Fatal("a listener serving a different certificate was accepted")
	}
	if !strings.Contains(err.Error(), "is serving") {
		t.Errorf("the error does not say what it found: %v", err)
	}
}

// The check has to work against a certificate no client would trust, because
// that is the common case: a private CA, or a certificate whose chain this host
// has not been told about. Asking whether it is trusted would refuse correct
// installations for reasons that have nothing to do with the installation.
func TestVerifyDoesNotRequireTheCertificateToBeTrusted(t *testing.T) {
	addr, thumbprint := serveTLS(t, "www.example.com")
	if _, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "www.example.com"}); err == nil {
		t.Fatal("the fixture is trusted, so this test proves nothing")
	}
	if err := verifyServes(context.Background(), addr, "www.example.com", thumbprint); err != nil {
		t.Fatalf("an untrusted certificate the agent had just installed was refused: %v", err)
	}
}

// serveTLS starts a listener presenting a fresh certificate and returns its
// address and thumbprint.
func serveTLS(t *testing.T, commonName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// A handshake and nothing else: the check reads the certificate out
			// of the handshake and closes.
			go func() {
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.Close()
			}()
		}
	}()
	return listener.Addr().String(), thumbprintOf(der)
}

// deadAddress is a port that was listening and is not any more, so a connection
// to it is refused rather than hanging until the deadline.
func deadAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// ── Reading a store name ────────────────────────────────────

func TestStoreNamesAreReadTheWayPeopleWriteThem(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`LocalMachine\My`, `LocalMachine\My`},
		{`localmachine\my`, `LocalMachine\my`},
		{`CurrentUser\My`, `CurrentUser\My`},
		{`Cert:\LocalMachine\WebHosting`, `LocalMachine\WebHosting`},
		{` LocalMachine/My `, `LocalMachine\My`},
	} {
		got, err := parseStoreName(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("%q became %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The location is closed on purpose. A certificate imported into CurrentUser\My
// when LocalMachine\My was meant is invisible to every service on the machine
// and perfectly visible to the account that ran the agent — a failure with no
// symptom except that nothing works.
func TestAnUnknownStoreLocationIsRefused(t *testing.T) {
	for _, bad := range []string{`Machine\My`, `My`, `LocalMachine\`, `a\b\c`, ``} {
		if _, err := parseStoreName(bad); err == nil {
			t.Errorf("%q was accepted as a certificate store", bad)
		}
	}
}

// ── The two kinds of destination do not mix ─────────────────

func TestBindAndVerifyAreRefusedOnADestinationThatWritesFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Destination)
	}{
		{"bind", func(d *Destination) { d.Bind = []string{"/bin/true", thumbprintPlaceholder} }},
		{"verify", func(d *Destination) { d.Verify = "www.example.com:443" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Destination{
				Name: "web", Certificate: "www.example.com",
				CertPath: absolutePath("cert.pem"), KeyPath: absolutePath("privkey.pem"),
			}
			tc.mutate(&d)
			err := d.validate()
			if err == nil {
				t.Fatal("a file destination accepted a field that only a store destination has")
			}
			if !strings.Contains(err.Error(), "certificate store") {
				t.Errorf("the message does not explain it: %v", err)
			}
		})
	}
}

// absolutePath makes a path the running platform calls absolute, so this test
// is about bind and verify rather than about path syntax.
func absolutePath(name string) string {
	if runtime.GOOS == "windows" {
		return `C:\certpilot\` + name
	}
	return "/etc/certpilot/" + name
}
