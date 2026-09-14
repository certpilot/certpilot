package agent

// Installing into the Windows certificate store.
//
// Everything else this installer does is a file: render the bytes, capture what
// was there, write, check, reload, and put the old bytes back if anything went
// wrong. IIS does not read a file. It binds a certificate by thumbprint out of
// LocalMachine\My, and so do Exchange, ADFS, Network Policy Server and Remote
// Desktop Services. On those hosts an agent that writes flawless PEM to a path
// is an agent that installs nothing.
//
// So a destination may name a store instead of paths, and three things about it
// are different enough to be worth stating.
//
// # There is no check
//
// Every other destination runs a check before the reload, and that line is the
// difference between a bad certificate being a rolled-back non-event and an
// outage. There is no `nginx -t` for a certificate store: nothing on Windows
// will tell you in advance whether a binding you have not made yet will work.
//
// Rather than pretend, this offers the other half of the same guarantee —
// `verify`, which connects to the endpoint after the binding and confirms the
// certificate being served is the one just installed. It is an *after* check, so
// a failure means something was briefly wrong rather than never wrong, and it is
// the strongest honest thing available here. A destination that declares no
// verify has no check at all, and that is said plainly rather than implied.
//
// # The binding is a command, because there are five of them
//
// IIS binds by thumbprint against a site binding; Exchange takes
// Enable-ExchangeCertificate with a service list; ADFS, NPS and RDS each have
// their own cmdlet. Teaching the agent all five would be five things to keep
// current, and it would still be wrong for the sixth.
//
// What it does instead is import the certificate, work out its thumbprint, and
// run the command this host's administrator wrote down with the thumbprint
// substituted into it — exactly the relationship it already has with `reload`.
// The `iis` profile supplies that command so the common case is one word, and
// the uncommon ones are one line rather than unsupported.
//
// # Rollback has to be built, not inherited
//
// A file destination rolls back by writing back bytes it captured. A store has
// no equivalent: importing does not displace anything, so there is nothing to
// capture, and the thing that actually changed is which thumbprint the binding
// names.
//
// The previous thumbprint is therefore recorded, and it is recorded in the store
// itself rather than in a state file beside the agent. Every certificate this
// agent imports is given the friendly name "CertPilot: <destination>", which
// makes the question "which certificate did I last install here" answerable by
// reading the store — by this agent, and by whoever opens certlm.msc and wants
// to know which of the certificates in it are ours.

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// thumbprintPlaceholder is what the bind command carries in place of a value
// nothing can know until the certificate has been imported.
//
// Spelled like the certificate placeholder in profile.go and substituted the
// same way, for the same reason: one placeholder rather than a template
// language, and anything else left in braces is an error rather than a silently
// literal argument.
const thumbprintPlaceholder = "{{ .Thumbprint }}"

// storeFriendlyPrefix marks a certificate as this agent's.
//
// Chosen to be readable in the Friendly Name column of certlm.msc, because the
// person who will one day wonder what these certificates are is looking at that
// column. The destination name follows it, so two destinations on one host do
// not claim each other's certificates.
const storeFriendlyPrefix = "CertPilot: "

// verifyTimeout bounds the post-binding check.
//
// A binding is not always live the instant the command returns — HTTP.sys
// picks one up quickly but not synchronously — so this is a deadline for
// retries rather than for a single connection. Short, because it runs after
// the binding has been made and every second of it is a second the endpoint
// may be serving something unintended.
const verifyTimeout = 20 * time.Second

// storeName is a certificate store, as `Location\Name`.
type storeName struct {
	location string // "LocalMachine" or "CurrentUser"
	name     string // "My", "Root", "WebHosting", …
	text     string // as the operator wrote it, for messages
}

// String renders it the way it was written.
func (s storeName) String() string { return s.text }

// parseStoreName reads `LocalMachine\My` and its relatives.
//
// The location is closed and the store name is not. There are exactly two
// locations a host agent has any business writing to, and getting one wrong is
// silent — a certificate imported into CurrentUser\My when LocalMachine\My was
// meant is invisible to every service on the machine and perfectly visible to
// the account that ran the agent. The store *name* is open because Windows
// treats it as one: WebHosting exists, so do custom stores, and refusing an
// unlisted name would be refusing a working configuration to no end.
func parseStoreName(text string) (storeName, error) {
	raw := strings.TrimSpace(text)
	// Both separators, because half the documentation on this subject is
	// PowerShell and writes Cert:\LocalMachine\My, and somebody copying from it
	// will reach for a forward slash at least once.
	raw = strings.TrimPrefix(raw, `Cert:\`)
	raw = strings.TrimPrefix(raw, "Cert:/")
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == '\\' || r == '/' })
	if len(fields) != 2 {
		return storeName{}, fmt.Errorf(
			"store %q is not a certificate store name; write it as Location\\Name, like LocalMachine\\My", text)
	}
	location, name := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])
	switch strings.ToLower(location) {
	case "localmachine":
		location = "LocalMachine"
	case "currentuser":
		location = "CurrentUser"
	default:
		return storeName{}, fmt.Errorf(
			"store %q names the location %q; it is LocalMachine — which is what every service on this "+
				"host reads — or CurrentUser, which only the account running the agent can see",
			text, fields[0])
	}
	if name == "" {
		return storeName{}, fmt.Errorf("store %q names no store inside %s; IIS reads My", text, location)
	}
	return storeName{location: location, name: name, text: location + `\` + name}, nil
}

// toStore reports whether this destination installs into a certificate store
// rather than writing files.
func (d *Destination) toStore() bool { return strings.TrimSpace(d.Store) != "" }

// friendlyName is the mark this destination's certificates carry in the store.
func (d *Destination) friendlyName() string { return storeFriendlyPrefix + d.Name }

// validateStore checks a store destination against itself.
//
// Refused here rather than at install time, like every other validation in this
// package: a spec that cannot work should fail when it is read, on a host still
// serving the certificate it has, rather than after a certificate has already
// been imported and a binding re-pointed.
func (d *Destination) validateStore() error {
	if !storeSupported() {
		return fmt.Errorf(
			"store names the Windows certificate store, and this is not Windows. A destination on this " +
				"platform writes files: set cert_path and key_path instead of store")
	}
	sn, err := parseStoreName(d.Store)
	if err != nil {
		return err
	}

	// Nothing is written to disk, so every field that names a file or describes
	// one is a field the operator will believe took effect.
	for name, value := range map[string]string{
		"cert_path": d.CertPath, "key_path": d.KeyPath,
		"chain_path": d.ChainPath, "fullchain_path": d.FullChainPath,
	} {
		if strings.TrimSpace(value) != "" {
			return fmt.Errorf(
				"%s and store are two different destinations. A store destination imports the "+
					"certificate, its chain and its key into %s and writes no file at all; declare a "+
					"second destination if this host also needs them on disk", name, sn)
		}
	}
	if strings.TrimSpace(d.Format) != "" {
		return fmt.Errorf(
			"format says what to write to a file, and a store destination writes none. The material " +
				"is handed to Windows as PKCS#12 in memory, which is the only encoding the store accepts")
	}
	// owner and group are here rather than left to the ownershipSupported check
	// in validate(), which a store destination returns before reaching. Without
	// this they are accepted in silence — and an operator who writes an owner
	// believes a service account can use a key it cannot, which is the exact
	// failure that refusal exists to prevent.
	if strings.TrimSpace(d.Owner) != "" || strings.TrimSpace(d.Group) != "" ||
		strings.TrimSpace(d.CertMode) != "" || strings.TrimSpace(d.KeyMode) != "" {
		return fmt.Errorf(
			"owner, group, cert_mode and key_mode all describe a file, and this destination writes no " +
				"file for them to apply to. The private key is held by Windows, and who may use it is " +
				"the key's own access control list")
	}
	if strings.TrimSpace(d.KeystorePassword) != "" || strings.TrimSpace(d.KeystorePasswordFile) != "" {
		return fmt.Errorf(
			"keystore_password is what opens a keystore file, and a store destination produces none. " +
				"The PKCS#12 handed to Windows exists for the length of one import and is protected by " +
				"a password this process generates and discards")
	}
	if strings.TrimSpace(d.KeystoreAlias) != "" {
		return fmt.Errorf(
			"keystore_alias names an entry inside a keystore file. A certificate in the Windows store " +
				"is found by thumbprint, and the name it carries is set by the agent to \"" +
				storeFriendlyPrefix + "<destination>\" so that it can find its own again")
	}
	if len(d.Check) > 0 {
		// The one refusal here that is a statement about the platform rather
		// than about this destination.
		return fmt.Errorf(
			"check runs before a certificate is loaded, and there is nothing on Windows that will say " +
				"in advance whether a binding will work — no `nginx -t` for a certificate store. Use " +
				"verify instead: it connects to the endpoint after the binding and confirms the " +
				"certificate being served is the one just installed")
	}

	if len(d.Bind) > 0 {
		if strings.TrimSpace(d.Bind[0]) == "" {
			return fmt.Errorf("bind has no command in it")
		}
		if !filepath.IsAbs(d.Bind[0]) {
			return fmt.Errorf(
				"bind must name an absolute path, not %q — this runs with the service manager's PATH, not yours",
				d.Bind[0])
		}
		if !hasThumbprintPlaceholder(d.Bind) {
			return fmt.Errorf(
				"bind names no %s, so it would re-point nothing at the certificate just imported. The "+
					"thumbprint is the only thing that changes on a renewal", thumbprintPlaceholder)
		}
		for _, arg := range d.Bind {
			if left := remainingPlaceholder(strings.ReplaceAll(arg, thumbprintPlaceholder, "")); left != "" {
				return fmt.Errorf(
					"bind contains %q, which is not a placeholder this understands; the only one is %s",
					left, thumbprintPlaceholder)
			}
		}
	}

	if v := strings.TrimSpace(d.Verify); v != "" {
		host, port, err := net.SplitHostPort(v)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf(
				"verify is the endpoint to connect to after the binding, as host:port — like "+
					"%s:443. %q is not one", d.Certificate, d.Verify)
		}
	}
	return nil
}

func hasThumbprintPlaceholder(argv []string) bool {
	for _, arg := range argv {
		if strings.Contains(arg, thumbprintPlaceholder) {
			return true
		}
	}
	return false
}

// withThumbprint renders the bind command for one certificate.
func withThumbprint(argv []string, thumbprint string) []string {
	out := make([]string, 0, len(argv))
	for _, arg := range argv {
		out = append(out, strings.ReplaceAll(arg, thumbprintPlaceholder, thumbprint))
	}
	return out
}

// thumbprintOf is the identifier Windows knows a certificate by: the SHA-1 of
// its DER, in uppercase hex with nothing between the bytes.
//
// SHA-1 is not a security decision here and is not being trusted for one. It is
// the value in the Thumbprint column of certlm.msc, the value `netsh http` and
// `Get-ChildItem Cert:\` print, and the value every binding on the host is
// written in terms of. Producing anything else would produce a number that
// matches nothing.
func thumbprintOf(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// encodeForStore builds the PKCS#12 blob Windows imports from, and the password
// that opens it.
//
// The password is random and returned rather than configured, because it
// protects nothing that is not already here: the blob exists in this process's
// memory for the length of one import, is never written to a file, and holds a
// key that was generated on this host and has never left it. A password an
// operator chose would be a value to keep somewhere, and the only thing it would
// change is that it could be got wrong.
//
// Deliberately not reusing encodeKeystore. That function serves a file
// destination and requires the operator to supply the password, which is right
// for a keystore Tomcat has to open and wrong for one that nothing outside this
// function will ever see.
func encodeForStore(m *material) ([]byte, string, error) {
	leaf, err := firstCertificate(m.certPEM)
	if err != nil {
		return nil, "", fmt.Errorf("the issued certificate: %w", err)
	}
	key, err := parsePrivateKey(m.keyPEM)
	if err != nil {
		return nil, "", err
	}
	chain, err := allCertificates(m.chainPEM)
	if err != nil {
		return nil, "", fmt.Errorf("the chain: %w", err)
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, "", fmt.Errorf("could not generate a transfer password: %w", err)
	}
	password := base64.RawStdEncoding.EncodeToString(raw[:])

	// Modern, for the same reason the keystore path uses it: LegacyRC2 exists
	// to read files written decades ago, and nothing here has to be read by
	// anything except the Windows importer on this machine, which has handled
	// AES-based PKCS#12 since Windows 10.
	pfx, err := pkcs12.Modern.Encode(key, leaf, chain, password)
	if err != nil {
		return nil, "", fmt.Errorf("could not encode the certificate for import: %w", err)
	}
	return pfx, password, nil
}

// ── The store itself ────────────────────────────────────────

// certStore is what the installer needs from a certificate store.
//
// An interface for one implementation, which is usually a smell. The reason it
// earns its place is the rollback below: its ordering is the part of this file
// most likely to be wrong, the part whose failure is an outage rather than an
// inconvenience, and — without this — the part testable only by pushing to CI
// and reading a Windows log. With it, every branch of it is a table test that
// runs on whatever machine somebody is sitting at.
type certStore interface {
	// importPFX adds a PKCS#12 to the store and reports the thumbprints of the
	// certificates it added.
	importPFX(sn storeName, pfx []byte, password string) ([]string, error)
	// thumbprintNamed reports which certificate carries a friendly name, or
	// empty when none does.
	thumbprintNamed(sn storeName, friendly string) (string, error)
	// setFriendlyName marks a certificate already in the store.
	setFriendlyName(sn storeName, thumbprint, friendly string) error
	// remove deletes one certificate. Removing one that is not there is not an
	// error: it is the state the caller wanted.
	remove(sn storeName, thumbprint string) error
}

// ── Installing ──────────────────────────────────────────────

// applyStore installs one destination into a certificate store.
//
// The shape mirrors applyOne's file path deliberately — decide what should be
// there, record what is there, change it, prove it, and undo the change if the
// proof fails — because an operator reading a report should not be able to tell
// which kind of destination produced it except by what it names.
func (i *Installer) applyStore(ctx context.Context, d Destination, m *material,
	out agentapi.Installation, force bool) agentapi.Installation {

	sn, err := parseStoreName(d.Store)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}

	leaf, err := firstCertificate(m.certPEM)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = fmt.Sprintf("the issued certificate: %v", err)
		return out
	}
	thumbprint := thumbprintOf(leaf.Raw)

	// Read before write, and a read that fails stops here. Without the previous
	// thumbprint there is nothing to put the binding back to, so an import that
	// went ahead anyway would be an operation with no way out of it — which is
	// the whole objection to doing this casually.
	previous, err := i.store.thumbprintNamed(sn, d.friendlyName())
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = fmt.Sprintf(
			"could not read %s, so nothing was imported: %v. The agent has to know which certificate "+
				"it last installed here before it replaces it, because that is the only thing it could "+
				"put the binding back to", sn, err)
		return out
	}

	if previous == thumbprint && !force {
		out.Status = agentapi.InstallInstalled
		out.Detail = fmt.Sprintf(
			"%s already holds this certificate as %q; nothing was imported and nothing was re-bound",
			sn, d.friendlyName())
		return out
	}

	pfx, password, err := encodeForStore(m)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}

	added, err := i.store.importPFX(sn, pfx, password)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = fmt.Sprintf("could not import the certificate into %s: %v", sn, err)
		// Best effort, and silent about its own failure on purpose: the import
		// is the thing that failed, and a second error about tidying up after
		// it would bury the first.
		_ = i.store.remove(sn, thumbprint)
		return out
	}
	if !contains(added, thumbprint) {
		out.Status = agentapi.InstallFailed
		out.Error = fmt.Sprintf(
			"%s accepted the import and does not hold %s afterwards. The certificate that was imported "+
				"is not the one this host holds, so nothing has been re-bound", sn, thumbprint)
		return out
	}

	now := i.now().UTC()
	out.InstalledAt = &now
	return i.bindAndProve(ctx, d, sn, thumbprint, previous, out)
}

// bindAndProve re-points whatever serves TLS at the new certificate and checks
// that it took.
//
// bind, then reload, then verify. Verify last because it is the only one that
// observes the running system rather than instructing it, so it has to be asked
// after everything that could change the answer.
func (i *Installer) bindAndProve(ctx context.Context, d Destination, sn storeName,
	thumbprint, previous string, out agentapi.Installation) agentapi.Installation {

	bind := withThumbprint(d.Bind, thumbprint)
	bound := false

	if len(bind) > 0 {
		if output, err := i.run(ctx, bind); err != nil {
			return i.rollbackStore(ctx, d, sn, thumbprint, previous, out, false, false,
				fmt.Errorf("%s failed, so nothing was re-pointed at the new certificate: %w%s",
					commandText(bind), err, suffix(output)))
		}
		bound = true
	}

	reloaded := false
	if len(d.Reload) > 0 {
		if output, err := i.run(ctx, d.Reload); err != nil {
			return i.rollbackStore(ctx, d, sn, thumbprint, previous, out, bound, false,
				fmt.Errorf("%s failed after the certificate was bound: %w%s",
					commandText(d.Reload), err, suffix(output)))
		}
		reloaded = true
		at := i.now().UTC()
		out.ReloadedAt = &at
	}

	if addr := strings.TrimSpace(d.Verify); addr != "" {
		if err := i.verify(ctx, addr, d.Certificate, thumbprint); err != nil {
			return i.rollbackStore(ctx, d, sn, thumbprint, previous, out, bound, reloaded, err)
		}
	}

	return i.settle(d, sn, thumbprint, previous, bound, out)
}

// settle marks the new certificate as this destination's and removes the one it
// replaced.
//
// Deliberately last, and deliberately in this order. The friendly name is what
// the next run reads to find the certificate it would roll back to, so setting
// it before the binding was proved would leave a mark on a certificate that is
// not serving anything.
//
// Removing the previous certificate is not tidiness. This agent's own inventory
// reports an expired certificate on a host as a finding, so an installer that
// left one behind on every renewal would be manufacturing its own alerts —
// forty of them over the life of a machine. The safety is that it removes only
// a certificate it imported itself, identified by the name it gave it, and only
// after its replacement is bound and — where a verify is declared — observed
// being served.
//
// Neither step failing is fatal. The certificate is installed, bound and
// serving; a store that could not be tidied is worth saying and is not worth
// undoing a successful deployment for.
func (i *Installer) settle(d Destination, sn storeName, thumbprint, previous string,
	bound bool, out agentapi.Installation) agentapi.Installation {

	out.Status = agentapi.InstallInstalled

	var notes []string
	if err := i.store.setFriendlyName(sn, thumbprint, d.friendlyName()); err != nil {
		notes = append(notes, fmt.Sprintf(
			"it could not be named %q in the store (%v), so the next renewal will not recognise it as "+
				"the one to replace and will leave it behind", d.friendlyName(), err))
	}
	if previous != "" && previous != thumbprint {
		if err := i.store.remove(sn, previous); err != nil {
			notes = append(notes, fmt.Sprintf(
				"the certificate it replaces, %s, could not be removed from %s: %v", previous, sn, err))
		}
	}

	out.Detail = i.storyOf(d, sn, thumbprint, bound)
	if len(notes) > 0 {
		out.Detail += ". " + capitalise(strings.Join(notes, "; "))
	}
	return out
}

// storyOf says what happened, in the order it happened.
func (i *Installer) storyOf(d Destination, sn storeName, thumbprint string, bound bool) string {
	story := fmt.Sprintf("imported %s into %s", thumbprint, sn)
	if bound {
		story += " and ran " + commandText(withThumbprint(d.Bind, thumbprint))
	} else {
		story += ". No bind is declared for this destination, so nothing was re-pointed at it — " +
			"whatever reads this store will pick the certificate up when it is told to"
	}
	if addr := strings.TrimSpace(d.Verify); addr != "" {
		story += fmt.Sprintf(". %s is serving it", addr)
	}
	return story
}

// rollbackStore puts the binding back and takes the new certificate out again.
//
// The order is the whole of it, and it is the order the store makes necessary
// rather than the one that reads best:
//
//  1. Re-bind to the previous thumbprint. Until this succeeds the running
//     service is using the certificate that just failed, and nothing else
//     matters.
//  2. Only then remove the imported certificate. Removing a certificate that a
//     binding still names is worse than the failure being rolled back — it
//     turns a service serving the wrong certificate into a service serving
//     none, and the second is not recoverable by trying again.
//  3. If the re-bind failed, stop. Leave the certificate where it is and say
//     so, loudly.
//
// bound says whether the binding was ever changed; reloaded, whether the
// service has already been told to pick it up. A failure before the bind is the
// easy case and the common one: nothing has been re-pointed, so removing the
// import is the whole of the rollback.
func (i *Installer) rollbackStore(ctx context.Context, d Destination, sn storeName,
	thumbprint, previous string, out agentapi.Installation, bound, reloaded bool,
	cause error) agentapi.Installation {

	out.Status = agentapi.InstallFailed
	out.Error = cause.Error()

	if !bound {
		if err := i.store.remove(sn, thumbprint); err != nil {
			out.Detail = fmt.Sprintf(
				"nothing was re-bound, and the certificate that was imported could not be removed from "+
					"%s again: %v. It is sitting in the store unused and unnamed", sn, err)
			return out
		}
		out.RolledBack = true
		out.Detail = fmt.Sprintf(
			"the certificate was removed from %s again and nothing on this host was re-pointed, so %s "+
				"is still serving what it was before", sn, d.Name)
		return out
	}

	if previous == "" {
		// The first install on this host. There is no earlier certificate of
		// ours to go back to, and removing the one that is now bound would take
		// the endpoint from wrong to absent. The honest report is that the
		// change stands and needs a person.
		out.Detail = fmt.Sprintf(
			"%s is now bound to %s and it could not be put back, because this is the first certificate "+
				"this agent has installed here and there is no earlier one of its own to return to. The "+
				"certificate was left in %s rather than removed: a binding naming a certificate that is "+
				"not there serves nothing at all",
			d.Name, thumbprint, sn)
		return out
	}

	if output, err := i.run(ctx, withThumbprint(d.Bind, previous)); err != nil {
		out.Detail = fmt.Sprintf(
			"the binding could not be put back to %s: %v%s. %s may now be serving a certificate this "+
				"host did not intend to install, and the new certificate was left in %s because "+
				"removing one a binding still names would leave it serving nothing",
			previous, err, suffix(output), d.Name, sn)
		return out
	}

	out.RolledBack = true
	detail := fmt.Sprintf("the binding was put back to %s", previous)
	if err := i.store.remove(sn, thumbprint); err != nil {
		detail += fmt.Sprintf(", and the certificate that failed could not be removed from %s: %v", sn, err)
	}
	if reloaded {
		if _, err := i.run(ctx, d.Reload); err != nil {
			detail += fmt.Sprintf(", but %s failed again afterwards: %v", commandText(d.Reload), err)
			out.Detail = capitalise(detail)
			return out
		}
		detail += fmt.Sprintf(" and %s was reloaded onto it", d.Name)
	}
	out.Detail = capitalise(detail)
	return out
}

// ── Proving it ──────────────────────────────────────────────

// verifyServes connects to an endpoint and reports whether it is serving one
// particular certificate.
//
// The handshake is deliberately not verified. This is not asking whether the
// certificate is trusted — the agent has no idea what this host's clients
// trust, and on a private CA the answer would be no while everything was
// correct. It is asking a single question with one right answer: is the
// certificate on the wire the one just installed. Comparing the thumbprint
// answers exactly that and nothing else, and a chain check here would refuse
// correct installations for reasons that have nothing to do with the
// installation.
func verifyServes(ctx context.Context, addr, serverName, thumbprint string) error {
	dialer := &net.Dialer{}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		// See above: identity is checked by thumbprint, one line down.
		InsecureSkipVerify: true, //nolint:gosec
		// SNI, and it matters. An IIS binding with "Require Server Name
		// Indication" set serves a different certificate — or nothing — to a
		// client that offers no name, so a check made without one would report
		// a failure on a correct binding.
		ServerName: serverName,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("it completed a handshake and presented no certificate")
	}
	served := thumbprintOf(state.PeerCertificates[0].Raw)
	if served != thumbprint {
		return fmt.Errorf("it is serving %s", served)
	}
	return nil
}

// verify retries verifyServes until the deadline.
//
// Retried because a binding is not always live the instant the command that
// made it returns, and a check that ran once and immediately would report a
// failure for a certificate that was correctly installed a second later. The
// deadline is short: every second of it is a second the endpoint may be serving
// something unintended.
func (i *Installer) verify(ctx context.Context, addr, serverName, thumbprint string) error {
	window := i.verifyFor
	if window <= 0 {
		window = verifyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	var last error
	for {
		last = verifyServes(ctx, addr, serverName, thumbprint)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"%s was bound to %s and %s is not serving it: %w. The binding was made and did not "+
					"take, so it has been put back", serverName, thumbprint, addr, last)
		case <-time.After(time.Second):
		}
	}
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
