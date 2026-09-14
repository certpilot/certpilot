//go:build windows

package agent

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/certpilot/certpilot-agent-sdk/agentauth"
	"golang.org/x/sys/windows"
)

// dacl reads back the access control list actually on a file.
func dacl(t *testing.T, path string) (*windows.ACL, windows.SECURITY_DESCRIPTOR_CONTROL) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("could not read the ACL of %s: %v", path, err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("could not take the DACL apart: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("could not read the descriptor control bits: %v", err)
	}
	return acl, control
}

func grants(t *testing.T, acl *windows.ACL, who *windows.SID) bool {
	t.Helper()
	for _, sid := range aclTrustees(acl) {
		if windows.EqualSid(sid, who) {
			return true
		}
	}
	return false
}

// TestAPrivateKeyIsNotReadableByOtherAccounts is the Windows half of the
// guarantee this agent exists to keep.
//
// On Unix it is a file mode and the installer refuses any mode that breaches
// it. Windows has no file modes: the 0600 passed to Chmod is accepted and
// ignored, and the file inherits its directory's ACL. So the assertion here is
// not "the mode is 0600" — that would pass while the file was readable by
// everyone — but "the accounts an ordinary user belongs to are not on the list".
func TestAPrivateKeyIsNotReadableByOtherAccounts(t *testing.T) {
	dir := t.TempDir()

	// A directory that hands out broad access to everything created inside it,
	// which is the situation restrictToOwner exists to undo. Without this the
	// test could pass on a TempDir that happened to be restrictive already.
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	loose, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, loose, nil); err != nil {
		t.Fatalf("could not loosen the test directory: %v", err)
	}

	key := filepath.Join(dir, "privkey.pem")
	if err := writeAtomic(key, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600, nil); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}

	acl, control := dacl(t, key)

	// Inheritance off. Without this the parent's grant to Everyone is still in
	// force no matter what else was added.
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the key still inherits its directory's permissions")
	}

	// The assertion that matters.
	if grants(t, acl, everyone) {
		t.Error("the private key is readable by Everyone")
	}
	for _, wk := range []struct {
		name string
		id   windows.WELL_KNOWN_SID_TYPE
	}{
		{"Authenticated Users", windows.WinAuthenticatedUserSid},
		{"BUILTIN\\Users", windows.WinBuiltinUsersSid},
	} {
		sid, err := windows.CreateWellKnownSid(wk.id)
		if err != nil {
			t.Fatal(err)
		}
		if grants(t, acl, sid) {
			t.Errorf("the private key is readable by %s", wk.name)
		}
	}

	// And the accounts that must keep access, because a key no administrator
	// can read is unrecoverable rather than safe.
	owner, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !grants(t, acl, owner) {
		t.Error("the account that wrote the key cannot read it")
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if !grants(t, acl, system) {
		t.Error("SYSTEM cannot read the key, so a service could not either")
	}
}

// TestACertificateIsLeftReadable.
//
// The rule is the mode's own, so a 0644 certificate must not be locked down:
// a web server frequently runs as an account other than the one that installed
// the certificate, and it has to be able to read it.
func TestACertificateIsLeftReadable(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := writeAtomic(cert, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644, nil); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}
	_, control := dacl(t, cert)
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Error("a world-readable certificate had its inheritance broken; only key material should be")
	}
}

// TestOwnerAndGroupAreRefused.
//
// Accepting them and silently doing nothing is how an operator ends up
// believing a service account can read a key it cannot.
func TestOwnerAndGroupAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Destination)
	}{
		{"owner", func(d *Destination) { d.Owner = "nginx" }},
		{"group", func(d *Destination) { d.Group = "www-data" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Destination{
				Name: "site", Certificate: "www.example.com",
				CertPath: `C:\certpilot\cert.pem`, KeyPath: `C:\certpilot\privkey.pem`,
			}
			tc.mutate(&d)
			err := d.validate()
			if err == nil {
				t.Fatal("accepted Unix file ownership on a platform that has none")
			}
			if !strings.Contains(err.Error(), "does not have") {
				t.Errorf("the message does not explain it: %v", err)
			}
		})
	}
}

// TestAnIdentityKeyGrantingEveryoneIsRefused is the Windows counterpart of
// TestAReadableKeyIsRefusedRatherThanWarnedAbout.
//
// The Unix test chmods the key to 0644 and expects the agent to refuse to
// start. os.Chmod cannot express that on Windows, so the condition is created
// the way it actually arises here: an ACL that grants a broad group.
//
// Refused rather than warned about, for the same reason. An identity key other
// accounts can read means every one of those accounts can speak to CertPilot as
// this machine.
func TestAnIdentityKeyGrantingEveryoneIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := agentauth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(dir, priv, State{AgentID: "a", Server: "s"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// As saved, it loads.
	if _, _, err := LoadIdentity(dir); err != nil {
		t.Fatalf("a freshly saved identity was refused: %v", err)
	}

	// Now hand it to Everyone, which is what an operator copying the file about
	// with inheritance on would do.
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	loose, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, keyFile)
	if err := windows.SetNamedSecurityInfo(key, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, loose, nil); err != nil {
		t.Fatalf("could not loosen the key: %v", err)
	}

	_, _, err = LoadIdentity(dir)
	if err == nil {
		t.Fatal("an identity key readable by Everyone must be refused")
	}
	// Whoever hits this is trying to get an agent running, so the message has
	// to name the file and say what to do.
	if !strings.Contains(err.Error(), "other accounts on this host") {
		t.Errorf("the error does not explain the problem: %v", err)
	}
}

// TestALinuxProfileIsRefusedHere.
//
// The catalogue describes Linux services: systemctl to reload, /etc to write
// to. Applying one on Windows would fill a destination with paths that
// validate() then rejects as not absolute, and "cert_path must be an absolute
// path, not /etc/certpilot/..." is a confusing way to learn that the nginx
// profile is not about nginx on Windows.
func TestALinuxProfileIsRefusedHere(t *testing.T) {
	d := Destination{
		Name: "web", Certificate: "www.example.com", Profile: "nginx",
	}
	err := d.applyProfile()
	if err == nil {
		t.Fatal("a Linux deployment profile was accepted on Windows")
	}
	if !strings.Contains(err.Error(), "describes a Linux service") {
		t.Errorf("the message does not explain it: %v", err)
	}
}

// TestADestinationWithWindowsPathsIsAccepted.
//
// The counterpart to the test above: without a profile, a destination that
// names Windows paths is ordinary and must validate.
func TestADestinationWithWindowsPathsIsAccepted(t *testing.T) {
	d := Destination{
		Name:        "app",
		Certificate: "www.example.com",
		CertPath:    `C:\ProgramData\CertPilot\live\www.example.com\cert.pem`,
		KeyPath:     `C:\ProgramData\CertPilot\live\www.example.com\privkey.pem`,
	}
	if err := d.validate(); err != nil {
		t.Fatalf("a Windows destination was refused: %v", err)
	}
}
