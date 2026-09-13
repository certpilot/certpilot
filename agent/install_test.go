package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
)

// heldOn writes a certificate into a state directory the way a real issuance
// would, and returns what the agent would hold.
//
// Real files rather than a fake, because the whole of this package's value is
// what it does to a filesystem. A rollback that only works against a mock is
// not a rollback.
func heldOn(t *testing.T, stateDir, commonName string) *Held {
	t.Helper()
	dir := filepath.Join(stateDir, certsDir, slugOf(commonName))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

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
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	write := func(name string, body []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), body, mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write(certFileName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	write(keyFileName, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	write(chainFileName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)

	held := &Held{
		CertificateID: "cert-" + commonName,
		Names:         []string{commonName},
		NotAfter:      tmpl.NotAfter,
		RenewAfter:    time.Now().Add(60 * 24 * time.Hour),
		Directory:     dir,
	}
	body, _ := json.MarshalIndent(held, "", "  ")
	write(metaFileName, append(body, '\n'), 0o600)
	return held
}

// recorder is a command runner that remembers what it was asked to run and can
// be made to fail.
type recorder struct {
	calls  []string
	failOn map[string]int // command text -> how many times it should still fail
}

func (r *recorder) run(ctx context.Context, argv []string) (string, error) {
	text := commandText(argv)
	r.calls = append(r.calls, text)
	if r.failOn != nil && r.failOn[text] > 0 {
		r.failOn[text]--
		return "configuration test failed", fmt.Errorf("exit status 1")
	}
	return "ok", nil
}

func installerFor(t *testing.T, dest Destination, held ...*Held) (*Installer, *recorder) {
	t.Helper()
	rec := &recorder{failOn: map[string]int{}}
	inst := NewInstaller(InstallSpec{Destinations: []Destination{dest}, Found: true}, "test-spec", held)
	inst.run = rec.run
	return inst, rec
}

func onlyResult(t *testing.T, report agentapi.InstallationReport) agentapi.Installation {
	t.Helper()
	if len(report.Installations) != 1 {
		t.Fatalf("expected one destination, got %d", len(report.Installations))
	}
	return report.Installations[0]
}

func TestACertificateLandsWhereTheServerReadsIt(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")

	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath:  filepath.Join(served, "shop.crt"),
		KeyPath:   filepath.Join(served, "shop.key"),
		ChainPath: filepath.Join(served, "chain.pem"),
		KeyMode:   "0600",
		Check:     []string{"/bin/true", "-t"},
		Reload:    []string{"/bin/true", "reload"},
	}
	installer, rec := installerFor(t, dest, held)

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallInstalled {
		t.Fatalf("expected INSTALLED, got %s: %s", result.Status, result.Error)
	}

	onDisk, err := os.ReadFile(dest.CertPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	original, _ := os.ReadFile(filepath.Join(held.Directory, certFileName))
	if string(onDisk) != string(original) {
		t.Fatal("the installed certificate is not the one this host holds")
	}
	if info, _ := os.Stat(dest.KeyPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("the private key landed at %04o, not 0600", info.Mode().Perm())
	}
	// The check runs before the reload, which is the whole reason they are two
	// steps rather than one.
	if len(rec.calls) != 2 || !strings.HasPrefix(rec.calls[0], "/bin/true -t") {
		t.Fatalf("expected check then reload, got %v", rec.calls)
	}
	if result.ReloadedAt == nil {
		t.Fatal("a destination that reloaded should say when")
	}
}

func TestNothingIsWrittenOrReloadedWhenTheFilesAlreadyMatch(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")
	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: filepath.Join(served, "shop.crt"),
		KeyPath:  filepath.Join(served, "shop.key"),
		Reload:   []string{"/bin/true", "reload"},
	}

	installer, rec := installerFor(t, dest, held)
	installer.Apply(context.Background(), nil)
	first := len(rec.calls)

	installer, rec = installerFor(t, dest, held)
	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallInstalled {
		t.Fatalf("expected INSTALLED, got %s", result.Status)
	}
	// An agent that reloaded nginx every cycle because it could would be a
	// worse problem than the stale certificate it was fixing.
	if len(rec.calls) != 0 {
		t.Fatalf("a second pass ran %v; the first ran %d command(s)", rec.calls, first)
	}
}

func TestAFailedCheckPutsBackWhatWasThereAndNeverReloads(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")

	certPath := filepath.Join(served, "shop.crt")
	keyPath := filepath.Join(served, "shop.key")
	if err := os.WriteFile(certPath, []byte("the certificate that is working\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("the key that is working\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: certPath, KeyPath: keyPath,
		Check:  []string{"/bin/false", "-t"},
		Reload: []string{"/bin/true", "reload"},
	}
	installer, rec := installerFor(t, dest, held)
	rec.failOn["/bin/false -t"] = 1

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallFailed {
		t.Fatalf("expected FAILED, got %s", result.Status)
	}
	if !result.RolledBack {
		t.Fatal("a check that refused the certificate should have rolled back")
	}
	for path, want := range map[string]string{
		certPath: "the certificate that is working\n",
		keyPath:  "the key that is working\n",
	} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != want {
			t.Fatalf("%s was not put back: %q (%v)", path, string(body), err)
		}
	}
	// Nothing was ever loaded, so nothing needed reloading onto the old files.
	for _, call := range rec.calls {
		if strings.Contains(call, "reload") {
			t.Fatalf("the reload ran after a failed check: %v", rec.calls)
		}
	}
}

func TestAFailedReloadPutsBackTheOldMaterialAndReloadsOntoIt(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")

	certPath := filepath.Join(served, "shop.crt")
	if err := os.WriteFile(certPath, []byte("working\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: certPath, KeyPath: filepath.Join(served, "shop.key"),
		Reload: []string{"/bin/true", "reload"},
	}
	installer, rec := installerFor(t, dest, held)
	// Fails once — the reload against the new material — and succeeds on the
	// second call, which is the one that puts the server back on what worked.
	rec.failOn["/bin/true reload"] = 1

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallFailed || !result.RolledBack {
		t.Fatalf("expected a rolled-back failure, got %s (rolled back: %t)", result.Status, result.RolledBack)
	}
	if body, _ := os.ReadFile(certPath); string(body) != "working\n" {
		t.Fatalf("the previous certificate was not restored: %q", string(body))
	}
	if len(rec.calls) != 2 {
		t.Fatalf("expected the reload to run again against the restored files, got %v", rec.calls)
	}
	// A key that did not exist before must not be left behind: half a pair is
	// how a service comes up on material nobody chose.
	if _, err := os.Stat(dest.KeyPath); !os.IsNotExist(err) {
		t.Fatalf("a key written during a failed install was left on disk (%v)", err)
	}
}

func TestAKeySomebodyWidenedIsPutBackWithoutAReload(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")
	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: filepath.Join(served, "shop.crt"),
		KeyPath:  filepath.Join(served, "shop.key"),
		Reload:   []string{"/bin/true", "reload"},
	}

	installer, _ := installerFor(t, dest, held)
	installer.Apply(context.Background(), nil)

	// The finding step 4b reports as CRITICAL, arriving here from an incident
	// three weeks ago rather than from this agent.
	if err := os.Chmod(dest.KeyPath, 0o644); err != nil {
		t.Fatal(err)
	}

	installer, rec := installerFor(t, dest, held)
	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallInstalled {
		t.Fatalf("expected INSTALLED, got %s", result.Status)
	}
	if info, _ := os.Stat(dest.KeyPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("the key is still at %04o", info.Mode().Perm())
	}
	if len(rec.calls) != 0 {
		t.Fatalf("correcting a file mode should not reload anything, ran %v", rec.calls)
	}
}

func TestADestinationForACertificateThisHostDoesNotHoldSaysSo(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")

	dest := Destination{
		// One character wrong, which is what this almost always is.
		Name: "nginx", Certificate: "shop.exmaple.com",
		CertPath: filepath.Join(served, "shop.crt"),
		KeyPath:  filepath.Join(served, "shop.key"),
		Reload:   []string{"/bin/true", "reload"},
	}
	installer, rec := installerFor(t, dest, held)

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallUnfulfilled {
		t.Fatalf("expected UNFULFILLED, got %s", result.Status)
	}
	if !strings.Contains(result.Detail, "shop.exmaple.com") {
		t.Fatalf("the detail should name what was asked for: %q", result.Detail)
	}
	if len(rec.calls) != 0 || fileExists(dest.CertPath) {
		t.Fatal("nothing should have been written or run for a destination with no certificate")
	}
}

func TestACombinedFileTakesTheKeysMode(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")

	combined := filepath.Join(served, "shop.pem")
	dest := Destination{
		Name: "haproxy", Certificate: "shop.example.com",
		CertPath: combined, KeyPath: combined,
		CertMode: "0644", KeyMode: "0640",
	}
	installer, _ := installerFor(t, dest, held)

	result := onlyResult(t, installer.Apply(context.Background(), nil))
	if result.Status != agentapi.InstallInstalled {
		t.Fatalf("expected INSTALLED, got %s: %s", result.Status, result.Error)
	}
	info, err := os.Stat(combined)
	if err != nil {
		t.Fatal(err)
	}
	// The layout 4b keeps finding at 0644. A file holding a private key takes
	// the key's mode whatever the certificate's says.
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("the combined file is at %04o, not 0640", info.Mode().Perm())
	}
	body, _ := os.ReadFile(combined)
	if !strings.Contains(string(body), "PRIVATE KEY") || !strings.Contains(string(body), "CERTIFICATE") {
		t.Fatal("the combined file should hold both halves")
	}
	if result.Paths[0] != combined || len(result.Paths) != 1 {
		t.Fatalf("a combined destination writes one file, reported %v", result.Paths)
	}
}

func TestASpecIsRefusedBeforeItCanDoAnyHarm(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		expects string
	}{
		{
			name: "a world-readable key mode",
			spec: `{"destinations":[{"name":"n","certificate":"a.example.com",
			        "cert_path":"/etc/ssl/a.crt","key_path":"/etc/ssl/a.key","key_mode":"0644"}]}`,
			// The agent must not create the finding it exists to report.
			expects: "readable by any account on this host",
		},
		{
			name: "a combined file at an explicit certificate mode",
			spec: `{"destinations":[{"name":"n","certificate":"a.example.com",
			        "cert_path":"/etc/ssl/a.pem","key_path":"/etc/ssl/a.pem","cert_mode":"0644"}]}`,
			expects: "holds the private key",
		},
		{
			name: "a relative command",
			spec: `{"destinations":[{"name":"n","certificate":"a.example.com",
			        "cert_path":"/etc/ssl/a.crt","key_path":"/etc/ssl/a.key","reload":["systemctl","reload","nginx"]}]}`,
			expects: "absolute path",
		},
		{
			name: "a relative destination",
			spec: `{"destinations":[{"name":"n","certificate":"a.example.com",
			        "cert_path":"ssl/a.crt","key_path":"/etc/ssl/a.key"}]}`,
			expects: "absolute path",
		},
		{
			name: "two destinations with one name",
			spec: `{"destinations":[
			        {"name":"n","certificate":"a.example.com","cert_path":"/a.crt","key_path":"/a.key"},
			        {"name":"n","certificate":"b.example.com","cert_path":"/b.crt","key_path":"/b.key"}]}`,
			expects: "both called",
		},
		{
			name:    "no certificate name",
			spec:    `{"destinations":[{"name":"n","cert_path":"/a.crt","key_path":"/a.key"}]}`,
			expects: "say which certificate belongs here",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "installs.json")
			if err := os.WriteFile(path, []byte(tc.spec), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadInstallSpec(path)
			if err == nil {
				t.Fatal("this spec should have been refused")
			}
			if !strings.Contains(err.Error(), tc.expects) {
				t.Fatalf("expected an error mentioning %q, got: %v", tc.expects, err)
			}
		})
	}
}

// TestACombinedFileNeedsNoCertModeAtAll.
//
// The HAProxy layout written the obvious way, with no cert_mode, is the one
// this project keeps finding at 0644 and wants people to write. Refusing it
// because the *default* certificate mode is world-readable would reject the
// correct destination — caught by a live run, not by the tests above.
func TestACombinedFileNeedsNoCertModeAtAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installs.json")
	body := `{"destinations":[{"name":"haproxy","certificate":"a.example.com",
	          "cert_path":"/etc/ssl/a.pem","key_path":"/etc/ssl/a.pem","key_mode":"0640"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInstallSpec(path); err != nil {
		t.Fatalf("the ordinary HAProxy destination was refused: %v", err)
	}
}

func TestAMissingSpecIsNotAnErrorAndIsNotAnEmptyOne(t *testing.T) {
	spec, err := LoadInstallSpec(filepath.Join(t.TempDir(), "installs.json"))
	if err != nil {
		t.Fatalf("a host that declares no destinations is the commonest case: %v", err)
	}
	// The distinction that stops every agent in the fleet appearing as a
	// deployment target with nothing in it.
	if spec.Found {
		t.Fatal("a file that does not exist was reported as found")
	}

	path := filepath.Join(t.TempDir(), "installs.json")
	if err := os.WriteFile(path, []byte(`{"destinations":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err = LoadInstallSpec(path)
	if err != nil || !spec.Found {
		t.Fatalf("an empty spec that exists should be found: %v", err)
	}
}

func TestForcingRewritesAndReloadsAnAlreadyCorrectDestination(t *testing.T) {
	state, served := t.TempDir(), t.TempDir()
	held := heldOn(t, state, "shop.example.com")
	dest := Destination{
		Name: "nginx", Certificate: "shop.example.com",
		CertPath: filepath.Join(served, "shop.crt"),
		KeyPath:  filepath.Join(served, "shop.key"),
		Reload:   []string{"/bin/true", "reload"},
	}

	installer, _ := installerFor(t, dest, held)
	installer.Apply(context.Background(), nil)

	installer, rec := installerFor(t, dest, held)
	installer.Apply(context.Background(), map[string]bool{"nginx": true})
	if len(rec.calls) != 1 {
		t.Fatalf("a forced install should reload, ran %v", rec.calls)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
