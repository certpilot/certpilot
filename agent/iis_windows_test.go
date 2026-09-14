//go:build windows && iis

package agent

// IIS, for real.
//
// Built only with `-tags iis`, because it needs a Windows host with the web
// server installed, an https binding on Default Web Site, and a process
// elevated enough to write LocalMachine\My. That is a CI job rather than
// something anybody should trip over running `go test`. The job that sets it up
// is `iis` in .github/workflows/ci.yml.
//
// This is the bar every deployment profile in the catalogue is held to, applied
// to the first one that is not a Linux service: install a certificate with the
// agent's own installer, through the profile as shipped, and complete a TLS
// handshake against the running service proving it is serving that certificate.
// Nothing here is faked — the store is CryptoAPI, the binding is the PowerShell
// out of the catalogue, and the handshake is a socket.
//
// The three parts are in order on purpose and share the host between them. A
// first install proves the mechanism; a renewal proves the part that actually
// breaks estates, because a binding that is made once and never moved again is
// a certificate that expires on a working server; and a failure proves the
// rollback, which is the claim hardest to believe and the one whose absence is
// an outage.

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
)

const (
	iisName = "iis.certpilot.test"
	iisAddr = "127.0.0.1:443"
)

func TestIISServesWhatTheAgentInstalls(t *testing.T) {
	store := windowsStore{}
	machine := storeName{location: "LocalMachine", name: "My", text: `LocalMachine\My`}

	// Built through applyProfile and validate, the way LoadInstallSpec builds
	// it. Constructing the Destination by hand here would test a destination
	// nobody writes and leave the catalogue's own bind command unexercised —
	// which is the thing most likely to be wrong.
	destination := func(t *testing.T, verify string) Destination {
		t.Helper()
		d := Destination{
			Name: "ci-iis", Certificate: iisName,
			Profile: "iis", Verify: verify,
		}
		if err := d.applyProfile(); err != nil {
			t.Fatalf("the iis profile: %v", err)
		}
		if err := d.validate(); err != nil {
			t.Fatalf("the destination the iis profile produced is invalid: %v", err)
		}
		return d
	}

	install := func(t *testing.T, d Destination, held *Held) (string, string) {
		t.Helper()
		report := NewInstaller(
			InstallSpec{Destinations: []Destination{d}, Found: true}, "ci", []*Held{held},
		).Apply(context.Background(), nil)
		if len(report.Installations) != 1 {
			t.Fatalf("expected one installation, got %d", len(report.Installations))
		}
		got := report.Installations[0]
		return got.Status, got.Detail + " " + got.Error
	}

	var first, second string

	// Every certificate this test imports, removed when all three parts are
	// done rather than as each one finishes.
	//
	// t.Cleanup inside a subtest runs when that subtest ends. Registering the
	// removal there took the certificate the third part has to roll back to out
	// of the store before the third part ran, and the result looked exactly
	// like a broken rollback: IIS still serving the certificate that failed.
	// The agent had behaved correctly — asked to bind a thumbprint the store no
	// longer held, it could not, left the new certificate in place rather than
	// leaving a binding naming nothing, and said so. A fixture that can produce
	// that reading of a correct implementation is worse than no fixture.
	var installed []string
	t.Cleanup(func() {
		for _, thumbprint := range installed {
			_ = windowsStore{}.remove(machine, thumbprint)
		}
	})

	t.Run("a first install is bound and served", func(t *testing.T) {
		held, thumbprint := storeHeld(t, t.TempDir(), iisName)
		first = thumbprint
		installed = append(installed, thumbprint)

		status, detail := install(t, destination(t, iisAddr), held)
		if status != agentapi.InstallInstalled {
			t.Fatalf("status = %s: %s", status, detail)
		}

		// Asked again, from outside the installer. The installer's own verify
		// passing proves the installer believes itself.
		served := whatIISIsServing(t)
		if served != thumbprint {
			t.Fatalf("IIS is serving %s, and the agent installed %s", served, thumbprint)
		}
		if named, err := store.thumbprintNamed(machine, "CertPilot: ci-iis"); err != nil {
			t.Fatal(err)
		} else if named != thumbprint {
			t.Errorf("the store does not record this as the agent's own work: %q", named)
		}
	})

	t.Run("a renewal moves the binding and clears up after itself", func(t *testing.T) {
		if first == "" {
			t.Skip("the first install did not complete")
		}
		held, thumbprint := storeHeld(t, t.TempDir(), iisName)
		second = thumbprint
		installed = append(installed, thumbprint)

		status, detail := install(t, destination(t, iisAddr), held)
		if status != agentapi.InstallInstalled {
			t.Fatalf("status = %s: %s", status, detail)
		}

		if served := whatIISIsServing(t); served != thumbprint {
			t.Fatalf("after a renewal IIS is serving %s, which is not the certificate just installed (%s)",
				served, thumbprint)
		}
		// The certificate it replaced is gone. Left behind, one accumulates per
		// renewal on every host — and this agent's own inventory reports an
		// expired certificate on a host as a finding.
		if inStore(t, machine, first) {
			t.Errorf("the certificate this renewal replaced is still in %s", machine)
		}
	})

	t.Run("a certificate that cannot be proved is put back", func(t *testing.T) {
		if second == "" {
			t.Skip("the renewal did not complete")
		}
		// The precondition, checked rather than assumed. Without the
		// certificate this part rolls back to, the agent is right to refuse to
		// bind it and the assertions below would be reading a correct refusal
		// as a broken rollback.
		if !inStore(t, machine, second) {
			t.Fatalf("%s is not in %s, so there is nothing for the rollback to return to; "+
				"the fixture is wrong rather than the rollback", second, machine)
		}

		held, thumbprint := storeHeld(t, t.TempDir(), iisName)
		installed = append(installed, thumbprint)

		// Verified against a port nothing is listening on, so the check cannot
		// pass however well the binding worked. The binding itself is real and
		// is really changed, which is the point: what is being tested is
		// whether it is changed back.
		status, detail := install(t, destination(t, "127.0.0.1:1"), held)
		if status != agentapi.InstallFailed {
			t.Fatalf("a certificate nothing could be shown to serve was reported as %s: %s", status, detail)
		}

		// The agent's own account first. If it says the binding could not be put
		// back, the assertion below will fail too, and knowing which of the two
		// happened is the difference between a rollback that did not run and
		// one that ran and did not take.
		if !strings.Contains(detail, "put back") {
			t.Errorf("the agent does not report putting the binding back: %q", detail)
		}
		if served := whatIISIsServing(t); served != second {
			t.Fatalf("after a failed install IIS is serving %s; it was serving %s before and should be again",
				served, second)
		}
		if inStore(t, machine, thumbprint) {
			t.Errorf("the certificate that failed was left in %s", machine)
		}
	})
}

// whatIISIsServing completes a handshake against the running web server and
// returns the thumbprint of the certificate it presented.
func whatIISIsServing(t *testing.T) string {
	t.Helper()
	conn, err := tls.Dial("tcp", iisAddr, &tls.Config{
		// Identity by thumbprint, not by trust: the fixture's CA is not one
		// this host has been told about, and asking whether it is trusted would
		// be asking a different question.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         iisName,
	})
	if err != nil {
		t.Fatalf("could not reach IIS on %s: %v", iisAddr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("IIS completed a handshake and presented no certificate")
	}
	return thumbprintOf(certs[0].Raw)
}
