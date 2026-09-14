//go:build windows

package agent

// The Windows half of everything that has no portable answer.
//
// The one that matters is restrictToOwner. On Unix this agent enforces "a
// private key is readable by its owner and nobody else" with a file mode, and
// refuses any mode that would breach it. Windows has no file modes: os.WriteFile
// accepts the 0600 and ignores it, and the file inherits whatever the parent
// directory's ACL grants — which under C:\ProgramData is typically read access
// for every authenticated user on the machine.
//
// So a port that only made the code compile would write private keys that look
// correct from Go, report mode 0600 in the inventory, and be world-readable in
// fact. That is worse than not running on Windows at all, because nothing would
// say so. restrictToOwner replaces the inherited ACL with an explicit one and
// is called on every key the installer writes.

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOf reports the account a file belongs to, for the inventory.
//
// Returned as a name where one resolves — "BUILTIN\\Administrators" reads
// better in a finding than a SID — and as the SID string otherwise, which is
// the case for an account from a domain this host cannot currently reach.
func ownerOf(path string, _ os.FileInfo) string {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return ""
	}
	account, domain, _, err := owner.LookupAccount("")
	if err != nil {
		return owner.String()
	}
	if domain == "" {
		return account
	}
	return domain + "\\" + account
}

// privileged reports whether this process can set another account as a file's
// owner, which on Windows means running elevated as a member of the local
// Administrators group.
func privileged() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	// Token(0) is the calling thread's token, falling back to the process
	// token — the documented way to ask "is the caller an administrator right
	// now", which is not the same as "is the caller in the group".
	member, err := windows.Token(0).IsMember(admins)
	return err == nil && member
}

// systemStateDir is where a packaged agent keeps its identity when it runs as a
// service. ProgramData is the Windows equivalent of /var/lib: machine-wide
// application state, not tied to a profile.
func systemStateDir() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return filepath.Join(dir, "CertPilot", "agent")
	}
	return filepath.Join("C:\\", "ProgramData", "CertPilot", "agent")
}

// restrictToOwner re-expresses the private key guarantee as an ACL.
//
// The mode is read for one bit of information only: whether the caller intended
// this file to be group-readable. Unix 0640 with a group is a legitimate and
// common way to let a service account read a key, and the Unix path allows it.
// There is no portable Windows equivalent of "the group", so the closest honest
// translation is the one below — owner, SYSTEM and Administrators — and a
// destination that wants a service account to read the key says so by setting
// owner on the destination, which goes through the same explicit ACL.
//
// Inheritance is switched off rather than merged with. Leaving it on means the
// parent directory decides who can read a private key, which is exactly the
// property being removed.
func restrictToOwner(path string, mode os.FileMode) error {
	owner, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("could not determine who this process runs as: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("could not build the SYSTEM identity: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("could not build the Administrators identity: %w", err)
	}

	grant := func(sid *windows.SID, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}

	// SYSTEM and Administrators are on the list deliberately. A key no
	// administrator can read is not more secure — an administrator can take
	// ownership of it in one command — but it is unbackuppable, unrecoverable
	// by the person responsible for the machine, and invisible to the endpoint
	// tooling every Windows estate runs. The threat this defends against is
	// another ordinary account on the host, and that is what it removes.
	entries := []windows.EXPLICIT_ACCESS{
		grant(owner, windows.TRUSTEE_IS_USER),
		grant(system, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		grant(admins, windows.TRUSTEE_IS_GROUP),
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("could not build an access control list for %s: %w", path, err)
	}

	// PROTECTED_DACL_SECURITY_INFORMATION is the half that matters: it detaches
	// the file from its parent's inheritable entries. Without it this call adds
	// permissions and removes none.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		return fmt.Errorf(
			"could not restrict access to %s; on Windows a private key's permissions are an ACL "+
				"rather than a file mode, and this one could not be set: %w", path, err)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

// ownershipSupported reports whether owner and group on a destination mean
// anything here.
//
// They do not. Both are Unix file ownership, and the closest Windows analogue —
// granting a service account access — is an ACL entry rather than an owner.
// Accepting them and doing nothing would leave an operator believing a service
// account can read a key it cannot, so they are refused when the spec is read.
func ownershipSupported() bool { return false }

// broadSIDs are the groups an ordinary account on this host belongs to. A
// private key granting any of them anything is a key every user can read.
func broadSIDs() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, id := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,             // Everyone
		windows.WinAuthenticatedUserSid, // Authenticated Users
		windows.WinBuiltinUsersSid,      // BUILTIN\\Users
	} {
		sid, err := windows.CreateWellKnownSid(id)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, nil
}

// keyIsPrivate reports whether a key file is readable only by its owner.
//
// Not the mode, which is why this is not shared with the Unix implementation.
// Go reports every file on Windows as 0666, or 0444 when the read-only
// attribute is set, because that is all the attribute bits can say. Reading the
// mode here would refuse every key on every Windows host, which is what the
// first run of this on a real Windows runner did.
//
// The question the mode was asking — can another account read this — is
// answered by the ACL.
func keyIsPrivate(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("could not read the permissions of %s: %w", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("could not read the permissions of %s: %w", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf(
			"%s inherits its permissions from the directory above it, so who can read this agent's "+
				"identity key is decided by that directory rather than by this agent. Re-run "+
				"`certpilot-agent enrol`, or remove inheritance from the file", path)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("could not read the permissions of %s: %w", path, err)
	}
	broad, err := broadSIDs()
	if err != nil {
		return err
	}
	for _, sid := range aclTrustees(acl) {
		for _, wide := range broad {
			if windows.EqualSid(sid, wide) {
				return fmt.Errorf(
					"%s grants access to %s, which lets other accounts on this host read this agent's "+
						"identity key. Re-run `certpilot-agent enrol`", path, wide.String())
			}
		}
	}
	return nil
}

// aclTrustees lists the SIDs an ACL grants anything to.
func aclTrustees(acl *windows.ACL) []*windows.SID {
	if acl == nil {
		return nil
	}
	var out []*windows.SID
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		out = append(out, (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace))+
			unsafe.Offsetof(ace.SidStart))))
	}
	return out
}

// profilesSupported reports whether the deployment profile catalogue applies
// here.
//
// It does not. Every profile in it names a Linux service — systemctl to reload,
// /etc/nginx and /etc/haproxy to write to — and none of those exist on Windows.
// Applying one would fill a destination with paths validate() then refuses as
// not absolute, which is a confusing way to learn that nginx on Windows is not
// what the nginx profile describes. A destination on Windows names its own
// paths and commands.
func profilesSupported() bool { return false }
