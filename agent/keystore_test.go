package agent

import (
	"context"
	"crypto/ecdsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestAKeystoreLandsWhereTheJVMReadsIt.
//
// The whole point of the format: a JVM estate is invisible to this agent
// otherwise. Decoded with the format's own reader rather than checked for
// length, because a file that is non-empty and unreadable by Java is exactly
// the failure this exists to prevent.
func TestAKeystoreLandsWhereTheJVMReadsIt(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "app.example.com")

	dest := Destination{
		Name: "tomcat", Certificate: "app.example.com",
		Format:           FormatPKCS12,
		CertPath:         filepath.Join(served, "keystore.p12"),
		KeystorePassword: "not-changeit",
		Check:            []string{"/bin/true", "-t"},
		Reload:           []string{"/bin/true", "reload"},
	}
	installer, rec := installerFor(t, dest, held)

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallInstalled {
		t.Fatalf("expected INSTALLED, got %s: %s", result.Status, result.Error)
	}

	body, err := os.ReadFile(dest.CertPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(body, "not-changeit")
	if err != nil {
		t.Fatalf("the keystore this agent wrote cannot be decoded: %v", err)
	}
	if leaf.Subject.CommonName != "app.example.com" {
		t.Errorf("the keystore holds a certificate for %q", leaf.Subject.CommonName)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("the private key came back as %T", key)
	}
	// The chain is stored as CA certificates, not stapled onto the leaf. A
	// consumer asking the keystore for the chain gets nothing if it was
	// concatenated instead.
	if len(chain) == 0 {
		t.Error("the chain was not stored as CA certificates")
	}

	// A keystore holds the key, so it takes the key's mode.
	if info, _ := os.Stat(dest.CertPath); info.Mode().Perm() != 0o600 {
		t.Errorf("the keystore landed at %04o, not 0600", info.Mode().Perm())
	}
	// And nothing else was written: the key is inside, not beside.
	entries, _ := os.ReadDir(served)
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a keystore destination wrote %v; the key must not also be on disk in the clear", names)
	}
	if len(rec.calls) != 2 {
		t.Errorf("check then reload, got %v", rec.calls)
	}
}

// TestTheKeystoreOpensWithKeytool is the assertion that matters and the one a
// round trip through this codebase cannot make.
//
// go-pkcs12 reading what go-pkcs12 wrote proves the two agree. It does not
// prove a JDK agrees, and a keystore Go can read and Java cannot is precisely
// the defect this format exists to avoid. Skipped rather than failed where
// there is no JDK, and said out loud.
func TestTheKeystoreOpensWithKeytool(t *testing.T) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		t.Skip("no keytool on this machine; the JDK-side assertion did not run")
	}
	// macOS ships a keytool stub that is on PATH with no JDK behind it and
	// fails with "Unable to locate a Java Runtime". LookPath succeeding is not
	// the same as a JDK being installed, and treating it as such turns a
	// missing dependency into a failing test.
	if out, err := exec.Command(keytool, "-help").CombinedOutput(); err != nil &&
		strings.Contains(string(out), "Unable to locate a Java Runtime") {
		t.Skip("keytool is on PATH but no JDK is installed; the JDK-side assertion did not run")
	}

	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "app.example.com")
	dest := Destination{
		Name: "tomcat", Certificate: "app.example.com",
		Format: FormatPKCS12, CertPath: filepath.Join(served, "keystore.p12"),
		KeystorePassword: "not-changeit",
	}
	installer, _ := installerFor(t, dest, held)
	if r := onlyResult(t, installer.Apply(context.Background(), nil)); r.Status != agentapi.InstallInstalled {
		t.Fatalf("install: %s", r.Error)
	}

	out, err := exec.Command(keytool, "-list", "-keystore", dest.CertPath,
		"-storetype", "PKCS12", "-storepass", "not-changeit").CombinedOutput()
	if err != nil {
		t.Fatalf("keytool could not read the keystore: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PrivateKeyEntry") {
		t.Errorf("keytool read the keystore and found no private key:\n%s", out)
	}
}

// TestAKeystoreSpecIsRefusedBeforeItCanDoAnyHarm.
//
// At parse time, on a host still serving the certificate it has — rather than
// after the previous file has been captured and replaced.
func TestAKeystoreSpecIsRefusedBeforeItCanDoAnyHarm(t *testing.T) {
	base := func() Destination {
		return Destination{
			Name: "tomcat", Certificate: "app.example.com",
			Format: FormatPKCS12, CertPath: "/opt/tomcat/keystore.p12",
			KeystorePassword: "not-changeit",
		}
	}

	for _, tc := range []struct {
		name     string
		mutate   func(*Destination)
		contains string
	}{
		{
			name:     "a key path beside the keystore",
			mutate:   func(d *Destination) { d.KeyPath = "/opt/tomcat/app.key" },
			contains: "in the clear as well",
		},
		{
			name:     "a chain path a keystore has no use for",
			mutate:   func(d *Destination) { d.ChainPath = "/opt/tomcat/chain.pem" },
			contains: "stored inside the keystore",
		},
		{
			name:     "no password at all",
			mutate:   func(d *Destination) { d.KeystorePassword = "" },
			contains: "There is no default",
		},
		{
			name: "a password given twice",
			mutate: func(d *Destination) {
				d.KeystorePasswordFile = "/opt/tomcat/keystore.pass"
			},
			contains: "not both",
		},
		{
			name:     "a cert mode that would be ignored",
			mutate:   func(d *Destination) { d.CertMode = "0644" },
			contains: "does not apply",
		},
		{
			name:     "a format this build does not write",
			mutate:   func(d *Destination) { d.Format = "JKS" },
			contains: "PEM, or PKCS12",
		},
		{
			name:     "a world-readable keystore",
			mutate:   func(d *Destination) { d.KeyMode = "0644" },
			contains: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base()
			tc.mutate(&d)
			err := d.validate()
			if err == nil {
				t.Fatal("a destination that cannot work was accepted")
			}
			if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("the message does not explain it: %v", err)
			}
		})
	}

	// And the shape that is correct stays correct.
	valid := base()
	if err := valid.validate(); err != nil {
		t.Fatalf("a valid keystore destination was refused: %v", err)
	}
}

// TestAPasswordFileLosesItsTrailingNewlineAndNothingElse.
//
// `echo secret > file` leaves a newline nobody typed. A leading space is a
// space somebody meant.
func TestAPasswordFileLosesItsTrailingNewlineAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.pass")
	if err := os.WriteFile(path, []byte(" s3cret \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := Destination{Format: FormatPKCS12, KeystorePasswordFile: path}
	got, err := d.password()
	if err != nil {
		t.Fatal(err)
	}
	if got != " s3cret" {
		t.Errorf("password came back as %q", got)
	}

	// An empty file is a missing password, not an empty one.
	empty := filepath.Join(dir, "empty.pass")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Destination{Format: FormatPKCS12, KeystorePasswordFile: empty}).password(); err == nil {
		t.Error("an empty password file was accepted")
	}
}

// TestAPEMDestinationIsUnchanged. The format defaults, and every destination
// written before this existed has no `format` field at all.
func TestAPEMDestinationIsUnchanged(t *testing.T) {
	d := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: "/etc/nginx/shop.crt", KeyPath: "/etc/nginx/shop.key",
	}
	if d.format() != FormatPEM {
		t.Errorf("an unset format resolved to %q", d.format())
	}
	if d.keystore() {
		t.Error("a PEM destination reported itself a keystore")
	}
	if err := d.validate(); err != nil {
		t.Errorf("a destination valid before this change was refused: %v", err)
	}
}

// TestTheKeystoreOpensWithOpenSSL is the external assertion that can run here.
//
// go-pkcs12 reading what go-pkcs12 wrote proves only that the two agree. This
// proves a tool written by somebody else, in another language, against the same
// specification, can open the file — which is the claim the format is making.
func TestTheKeystoreOpensWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on this machine")
	}

	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "app.example.com")
	dest := Destination{
		Name: "tomcat", Certificate: "app.example.com",
		Format: FormatPKCS12, CertPath: filepath.Join(served, "keystore.p12"),
		KeystorePassword: "not-changeit",
	}
	installer, _ := installerFor(t, dest, held)
	if r := onlyResult(t, installer.Apply(context.Background(), nil)); r.Status != agentapi.InstallInstalled {
		t.Fatalf("install: %s", r.Error)
	}

	out, err := exec.Command(openssl, "pkcs12", "-info", "-in", dest.CertPath,
		"-passin", "pass:not-changeit", "-passout", "pass:not-changeit", "-nodes").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl could not read the keystore: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"PRIVATE KEY", "app.example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl read the keystore and did not find %q:\n%s", want, text)
		}
	}
	// The wrong password must not open it, or the password is decoration.
	if _, err := exec.Command(openssl, "pkcs12", "-info", "-in", dest.CertPath,
		"-passin", "pass:changeit", "-nodes").CombinedOutput(); err == nil {
		t.Error("the keystore opened with the wrong password")
	}
}
