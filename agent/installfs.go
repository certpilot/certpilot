package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// material is what this host holds for one certificate, read off its own disk.
type material struct {
	certPEM     []byte
	keyPEM      []byte
	chainPEM    []byte
	fingerprint string
}

// readMaterial loads the files the agent wrote when the certificate was issued.
func readMaterial(held *Held) (*material, error) {
	certPEM, err := os.ReadFile(filepath.Join(held.Directory, certFileName))
	if err != nil {
		return nil, fmt.Errorf("could not read the certificate this host holds: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(held.Directory, keyFileName))
	if err != nil {
		return nil, fmt.Errorf("could not read the private key this host holds: %w", err)
	}
	// A chain is normal to be without — an internally issued certificate from a
	// single-tier CA has none — so a missing file is not an error here. It only
	// becomes one if a destination asked for a chain path.
	chainPEM, _ := os.ReadFile(filepath.Join(held.Directory, chainFileName))

	return &material{
		certPEM: certPEM, keyPEM: keyPEM, chainPEM: chainPEM,
		fingerprint: fingerprintOf(certPEM),
	}, nil
}

// fingerprintOf is the SHA-256 of the leaf's DER, which is what the core keys
// certificates on. Computed from the first block so a file that happens to hold
// a chain still identifies its leaf.
func fingerprintOf(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// findHeld matches a destination's certificate name against what this host has.
func findHeld(held []*Held, name string) *Held {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, h := range held {
		for _, candidate := range h.Names {
			if strings.ToLower(strings.TrimSuffix(candidate, ".")) == name {
				return h
			}
		}
	}
	return nil
}

// ── Ownership ───────────────────────────────────────────────

// ownership is the uid and gid a destination's files should carry, resolved
// once per destination rather than once per file.
type ownership struct {
	uid, gid int
}

// ownership resolves the declared owner and group to numeric ids.
//
// Resolved before anything is written, so a group that does not exist on this
// host is an error that costs nothing rather than a key left at root:root on a
// server that runs as somebody else — which fails at the next restart, quietly,
// with a permissions error nobody connects to a certificate.
func (d *Destination) ownership() (*ownership, error) {
	own := &ownership{uid: -1, gid: -1}
	if name := strings.TrimSpace(d.Owner); name != "" {
		u, err := lookupUser(name)
		if err != nil {
			return nil, fmt.Errorf("owner %q: %w", name, err)
		}
		own.uid = u
	}
	if name := strings.TrimSpace(d.Group); name != "" {
		g, err := lookupGroup(name)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", name, err)
		}
		own.gid = g
	}
	return own, nil
}

func (o *ownership) wanted() bool { return o != nil && (o.uid >= 0 || o.gid >= 0) }

// apply sets ownership if any was declared.
func (o *ownership) apply(path string) error {
	if !o.wanted() {
		return nil
	}
	if err := os.Chown(path, o.uid, o.gid); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("could not set the owner of %s; setting a file's owner needs root, and this agent is running as %s",
				path, currentUserName())
		}
		return fmt.Errorf("could not set the owner of %s: %w", path, err)
	}
	return nil
}

// lookupUser accepts a name or a numeric id, because container images
// frequently have neither /etc/passwd entries nor the names a person expects.
func lookupUser(name string) (int, error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("no such user on this host")
	}
	return strconv.Atoi(u.Uid)
}

func lookupGroup(name string) (int, error) {
	if id, err := strconv.Atoi(name); err == nil {
		return id, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no such group on this host")
	}
	return strconv.Atoi(g.Gid)
}

func currentUserName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return fmt.Sprintf("uid %d", os.Getuid())
}

// ── Writing ─────────────────────────────────────────────────

// writeAtomic replaces a file without any reader ever seeing it half-written.
//
// The temporary file is created in the destination's own directory, because
// rename is atomic within a filesystem and not across one — a temporary file in
// /tmp would turn this into a copy, which is the thing being avoided.
//
// The mode is set on the temporary file before the rename rather than after, so
// a private key is never briefly readable at the default mode under its final
// name.
func writeAtomic(path string, content []byte, mode os.FileMode, owner *ownership) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".certpilot-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	// The same statement, made again in the terms the platform actually
	// enforces. On Windows the Chmod above is accepted and ignored, and the
	// file inherits whatever its directory grants — so "not readable by other
	// accounts" has to be said as an ACL or it is not said at all. The rule is
	// the mode's own: a file the mode does not make world-readable must not be
	// world-readable in fact. On Unix this is a no-op, because the mode was
	// the enforcement.
	//
	// Before the rename, for the reason the mode is set before the rename: a
	// private key must never be briefly readable under its final name.
	if mode&0o004 == 0 {
		if err := restrictToOwner(tmpName, mode); err != nil {
			return err
		}
	}
	if owner.wanted() {
		if err := owner.apply(tmpName); err != nil {
			return err
		}
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	// Flushed to the device before the rename. A server that reloads within
	// milliseconds of the rename and a host that loses power a second later
	// must not between them produce a file whose name says one thing and whose
	// contents are empty.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// fileTime is when a path was last written, or the zero time.
func fileTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	out := t.UTC()
	return &out
}

// ── Running the host's own commands ─────────────────────────

// runCommand executes a declared check or reload.
//
// Executed as an argument vector with no shell anywhere in the path. Not for
// quoting convenience: a shell would make the command in the spec file a place
// where a substitution could be smuggled, and this runs as root on hosts where
// that file may be assembled by a template.
func runCommand(ctx context.Context, argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// A deliberately bare environment. Inheriting the agent's own means
	// inheriting whatever put its enrolment token or server address there, and
	// a reload command has no business reading either.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}

	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if len(text) > maxCommandOutput {
		text = text[:maxCommandOutput] + "…"
	}
	if ctx.Err() != nil {
		return text, fmt.Errorf("it did not finish within %s", commandTimeout)
	}
	if err != nil {
		return text, fmt.Errorf("it exited with an error: %w", err)
	}
	return text, nil
}

// commandText renders an argument vector for a person to read.
func commandText(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		if strings.ContainsAny(arg, " \t\"'") {
			arg = strconv.Quote(arg)
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

// suffix appends a command's own output to an error, when it said anything.
func suffix(output string) string {
	if strings.TrimSpace(output) == "" {
		return ""
	}
	return " — " + strings.Join(strings.Fields(output), " ")
}
