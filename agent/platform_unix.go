//go:build !windows

package agent

// The Unix half of everything that has no portable answer.
//
// Three things in this agent are expressed in terms the operating system
// defines rather than Go does: who owns a file, whether this process is
// privileged, and how a private key is made readable by its owner and nobody
// else. On Unix all three are file modes and uids, which is what the rest of
// the agent is written in terms of. Windows has none of them, so each one gets
// a counterpart in platform_windows.go and the callers stay platform-free.

import (
	"fmt"
	"os"
	"syscall"
)

// ownerOf reports the uid:gid a file belongs to, for the inventory.
//
// The path is unused here and required on Windows, where FileInfo carries no
// ownership at all and it has to be asked for by name.
func ownerOf(_ string, info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", stat.Uid, stat.Gid)
}

// privileged reports whether this process can set another account as a file's
// owner, which on Unix means being root.
func privileged() bool { return os.Geteuid() == 0 }

// systemStateDir is where a packaged agent keeps its identity when it runs as
// a system service.
func systemStateDir() string { return "/var/lib/certpilot-agent" }

// restrictToOwner is what enforces "readable by its owner and nobody else".
//
// On Unix nothing needs doing: the file was created with the mode the
// destination asked for, os.WriteFile applied it, and validate() has already
// refused any mode that would make the key readable by other accounts. The
// function exists so that the installer does not have to know that, because on
// Windows the same guarantee takes an explicit ACL and the file's mode means
// nothing at all.
func restrictToOwner(path string, mode os.FileMode) error { return nil }

// ownershipSupported reports whether owner and group on a destination mean
// anything here. They are uids, so: yes.
func ownershipSupported() bool { return true }

// keyIsPrivate reports whether a key file is readable only by its owner.
//
// The mode is the enforcement here, so the mode is what is read.
func keyIsPrivate(path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf(
			"%s is mode %04o, which lets other accounts on this host read this agent's identity key. Run: chmod 600 %s",
			path, mode, path)
	}
	return nil
}

// profilesSupported reports whether the deployment profile catalogue applies
// here. Every profile in it reloads with systemctl and writes under /etc, so:
// yes on Unix, and see platform_windows.go for why not there.
func profilesSupported() bool { return true }
