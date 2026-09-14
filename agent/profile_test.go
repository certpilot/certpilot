//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSpec puts a spec on disk and loads it the way the agent does, rather
// than calling applyProfile directly. The order matters — a profile is filled
// in before the destination is validated, and testing the two separately would
// not notice if that order were reversed, which is the one way this feature
// can break every profiled destination at once.
func writeSpec(t *testing.T, body string) (InstallSpec, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "installs.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadInstallSpec(path)
}

func TestAProfileFillsInTheDestination(t *testing.T) {
	spec, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com","profile":"nginx"}
	]}`)
	if err != nil {
		t.Fatalf("loading a profiled destination: %v", err)
	}
	d := spec.Destinations[0]

	if want := "/etc/certpilot/live/www.example.com/cert.pem"; d.CertPath != want {
		t.Errorf("cert_path = %q, want %q", d.CertPath, want)
	}
	if want := "/etc/certpilot/live/www.example.com/privkey.pem"; d.KeyPath != want {
		t.Errorf("key_path = %q, want %q", d.KeyPath, want)
	}
	if want := "/etc/certpilot/live/www.example.com/fullchain.pem"; d.FullChainPath != want {
		t.Errorf("fullchain_path = %q, want %q", d.FullChainPath, want)
	}
	if strings.Join(d.Check, " ") != "/usr/sbin/nginx -t" {
		t.Errorf("check = %v, want nginx -t", d.Check)
	}
	if strings.Join(d.Reload, " ") != "/usr/sbin/nginx -s reload" {
		t.Errorf("reload = %v, want nginx -s reload", d.Reload)
	}
}

// The promise the documentation makes: a profile is a default, not a lock.
func TestWhatTheOperatorWroteWins(t *testing.T) {
	spec, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com","profile":"nginx",
		 "cert_path":"/srv/tls/www.crt","key_path":"/srv/tls/www.key",
		 "reload":["/usr/bin/systemctl","reload","nginx"]}
	]}`)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	d := spec.Destinations[0]

	if d.CertPath != "/srv/tls/www.crt" {
		t.Errorf("the profile overwrote cert_path: %q", d.CertPath)
	}
	if d.KeyPath != "/srv/tls/www.key" {
		t.Errorf("the profile overwrote key_path: %q", d.KeyPath)
	}
	if strings.Join(d.Reload, " ") != "/usr/bin/systemctl reload nginx" {
		t.Errorf("the profile overwrote reload: %v", d.Reload)
	}
	// Untouched fields still come from the profile.
	if d.FullChainPath == "" {
		t.Error("overriding two paths dropped the rest of the profile")
	}
}

// An explicitly empty list is a decision, not an omission. Somebody who wrote
// "reload": [] has said this destination reloads by some other means, and
// filling it back in would run a command they had deliberately removed.
func TestAnEmptyReloadIsNotFilledIn(t *testing.T) {
	spec, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com","profile":"nginx","reload":[]}
	]}`)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got := spec.Destinations[0].Reload; len(got) != 0 {
		t.Errorf("an explicit empty reload was replaced with %v", got)
	}
}

func TestAnUnknownProfileIsRefusedAndListsTheRealOnes(t *testing.T) {
	_, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com","profile":"ngnix"}
	]}`)
	if err == nil {
		t.Fatal("a misspelled profile was accepted")
	}
	if !strings.Contains(err.Error(), "nginx") {
		t.Errorf("the error does not name the alternatives: %v", err)
	}
}

// A placeholder nobody implemented must be an error rather than a literal
// path. A file called "{{ .Name }}.crt" is not something to discover from a
// failed handshake.
func TestAnUnknownPlaceholderIsRefused(t *testing.T) {
	_, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com",
		 "cert_path":"/srv/{{ .Name }}.crt","key_path":"/srv/www.key"}
	]}`)
	if err == nil {
		t.Fatal("an unknown placeholder was written into a path verbatim")
	}
	if !strings.Contains(err.Error(), "{{ .Name }}") {
		t.Errorf("the error does not quote the placeholder it refused: %v", err)
	}
}

func TestThePlaceholderExpandsWithoutAProfile(t *testing.T) {
	spec, err := writeSpec(t, `{"destinations":[
		{"name":"web","certificate":"www.example.com",
		 "cert_path":"/srv/{{ .Certificate }}.crt","key_path":"/srv/{{ .Certificate }}.key"}
	]}`)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got := spec.Destinations[0].CertPath; got != "/srv/www.example.com.crt" {
		t.Errorf("cert_path = %q, want the name substituted", got)
	}
}

// ── The catalogue itself ──────────────────────────────────────────────
//
// Every one of these is an invariant that a new profile could break by hand,
// where the failure would be discovered on somebody's production host rather
// than here.

func TestEveryProfileProducesAnInstallableDestination(t *testing.T) {
	for _, p := range Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			body := `{"destinations":[{"name":"x","certificate":"www.example.com","profile":"` +
				p.Name + `"` + keystoreFields(p) + `}]}`
			if _, err := writeSpec(t, body); err != nil {
				t.Fatalf("a catalogue profile does not produce a valid destination: %v", err)
			}
		})
	}
}

// keystoreFields supplies what a keystore profile deliberately does not: there
// is no default password and there must not be one.
func keystoreFields(p Profile) string {
	if p.Format == FormatPKCS12 {
		return `,"keystore_password":"test"`
	}
	return ""
}

func TestEveryProfileNamesAbsolutePathsAndCommands(t *testing.T) {
	for _, p := range Profiles() {
		t.Run(p.Name, func(t *testing.T) {
			for _, path := range append(append([]string{}, p.Detect...),
				p.CertPath, p.KeyPath, p.ChainPath, p.FullChainPath) {
				if path == "" {
					continue
				}
				if !strings.HasPrefix(path, "/") {
					t.Errorf("%q is not an absolute path", path)
				}
			}
			// Compared against "/" rather than with filepath.IsAbs, which asks
			// whether a path is absolute on the machine running the test. These
			// profiles describe Linux hosts wherever they are read, and on
			// Windows filepath.IsAbs says /usr/sbin/apachectl is relative.
			for _, argv := range [][]string{p.Check, p.Reload} {
				if len(argv) > 0 && !strings.HasPrefix(argv[0], "/") {
					t.Errorf("%q is not an absolute command; this runs with the service "+
						"manager's PATH, not an operator's", argv[0])
				}
			}
		})
	}
}

// Every profile has to say what it was run against. A profile with no evidence
// behind it is the defect this whole feature was written to avoid — a claim
// that a platform is supported, made by somebody who never installed to it.
func TestEveryProfileRecordsWhatItWasVerifiedAgainst(t *testing.T) {
	for _, p := range Profiles() {
		if strings.TrimSpace(p.Verified) == "" {
			t.Errorf("profile %q claims a platform and records no verification", p.Name)
		}
		if strings.TrimSpace(p.Summary) == "" {
			t.Errorf("profile %q has no summary", p.Name)
		}
	}
}

// A keystore is one file and the key is inside it, so a profile that also set
// key_path would be refused at load — but by then it is in somebody's release.
func TestKeystoreProfilesDoNotSetAKeyPath(t *testing.T) {
	for _, p := range Profiles() {
		if p.Format == FormatPKCS12 && p.KeyPath != "" {
			t.Errorf("profile %q writes a keystore and also names a key_path", p.Name)
		}
	}
}

func TestNoProfileWritesAWorldReadableKey(t *testing.T) {
	for _, p := range Profiles() {
		mode, err := parseMode(p.KeyMode, 0o600)
		if err != nil {
			t.Errorf("profile %q: key_mode %q: %v", p.Name, p.KeyMode, err)
			continue
		}
		if mode&0o004 != 0 {
			t.Errorf("profile %q would write a key readable by any account on the host (%s)",
				p.Name, p.KeyMode)
		}
	}
}

func TestProfileNamesAreUniqueAndLowercase(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Profiles() {
		if seen[p.Name] {
			t.Errorf("two profiles are both called %q", p.Name)
		}
		seen[p.Name] = true
		if p.Name != strings.ToLower(p.Name) {
			t.Errorf("profile %q is not lowercase; lookup is case-insensitive and this "+
				"would be the one nobody could find", p.Name)
		}
	}
}

// Profiles() must hand out a copy. A caller that could sort or truncate the
// result would change what every later caller sees.
func TestProfilesReturnsACopy(t *testing.T) {
	first := Profiles()
	if len(first) == 0 {
		t.Fatal("the catalogue is empty")
	}
	first[0].Name = "clobbered"
	if Profiles()[0].Name == "clobbered" {
		t.Error("Profiles() hands out the catalogue itself, so a caller can rewrite it")
	}
}
