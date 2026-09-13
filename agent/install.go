package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/agentapi"
)

// Where the destinations are declared, and how long a command may take.
const (
	// SystemSpecPath is where a packaged agent reads its destinations from.
	// /etc, because this file belongs to whatever configuration management owns
	// /etc/nginx/nginx.conf — it is a statement about how this machine is put
	// together, not about CertPilot.
	SystemSpecPath = "/etc/certpilot/installs.json"
	// specFileName is the fallback inside the state directory, for a host
	// running the agent without installing it as a package.
	specFileName = "installs.json"

	// commandTimeout bounds a check or a reload.
	//
	// Generous, because `nginx -t` on a large configuration is not instant and
	// a reload that is cut off halfway is the exact failure this step exists to
	// avoid. Bounded, because a wedged reload must not leave the agent holding
	// files it has already replaced with nothing watching.
	commandTimeout = 60 * time.Second

	// maxCommandOutput is how much of a failed command's output is kept.
	// Enough for the line that says what is wrong, not enough for a
	// configuration dump to end up in the audit log.
	maxCommandOutput = 2000
)

// Destination is one place on this host that a certificate is installed.
//
// This type is deliberately local to the agent and has no counterpart in
// package agentapi, which holds everything the core and the agent both speak.
// The reason is the Reload field. A destination is read from a file on this
// host, written by whoever administers this host; there is no wire format in
// which the core could send one, because a core that could hand a host a
// command to run would be a fleet-wide remote execution channel with a
// certificate manager on the front of it. What the core may say is "install
// certificate X" — never "and here is what to run afterwards".
type Destination struct {
	// Name identifies this destination in reports and in the core's view.
	Name string `json:"name"`
	// Certificate is the name to install here, matched against the names this
	// host holds certificates for.
	Certificate string `json:"certificate"`

	// Where the material goes. CertPath and KeyPath are required; the rest are
	// written only if named, because different servers want different shapes.
	//
	// CertPath and KeyPath may be the same file, which is what HAProxy wants:
	// certificate, chain and key concatenated. That layout is also the one
	// step 4b keeps finding at mode 0644, so when the two are equal the file
	// takes the key's mode rather than the certificate's.
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
	ChainPath     string `json:"chain_path,omitempty"`
	FullChainPath string `json:"fullchain_path,omitempty"`

	// Format is what to write: PEM (the default, and what every destination
	// wrote before this existed) or PKCS12.
	//
	// A keystore is one file holding the certificate, the chain and the key
	// together, so cert_path is that file and key_path must be omitted — the
	// key is inside it. Everything else about a destination is unchanged: the
	// mode, the ownership, the check before the reload, and the rollback from a
	// captured copy all work the same way, because a keystore is a different
	// encoding and not a different kind of operation.
	//
	// PKCS12 and not JKS: Java 9 made PKCS#12 the default keystore type and
	// every JDK since reads it natively, so this covers the modern JVM and the
	// .pfx that Windows tooling and several appliances want. JKS is for the
	// estate still on Java 8 and is a separate decision, because it needs a
	// second third-party module in a binary that runs on every host.
	Format string `json:"format,omitempty"`

	// KeystorePassword is what opens the keystore. Exactly one of these two is
	// required when Format is a keystore, and there is no default.
	//
	// It is worth being clear about what this is and is not. It is **not**
	// protecting the key from anyone: the private key is already on this host,
	// in PEM, written by this same installer, and whoever can read the keystore
	// can read the key beside it. What it is, is a coordination value — Tomcat
	// has it in server.xml, and the keystore will not open unless the two
	// match.
	//
	// Which is why there is no default. `changeit` is what every Java tutorial
	// uses; defaulting to it would be theatre with the added harm of looking
	// like protection.
	KeystorePassword string `json:"keystore_password,omitempty"`
	// KeystorePasswordFile reads it from a file instead, for an operator who
	// already keeps it in one for their application and should not have to copy
	// it into a second place. Trailing whitespace is stripped; nothing else is.
	KeystorePasswordFile string `json:"keystore_password_file,omitempty"`

	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
	// CertMode and KeyMode are octal strings — "0644", "0640". Defaulted rather
	// than required, and the key's default is 0600.
	CertMode string `json:"cert_mode,omitempty"`
	KeyMode  string `json:"key_mode,omitempty"`

	// Check validates the configuration with the new files in place, before
	// anything is told to pick them up: `nginx -t`, `haproxy -c -f …`.
	//
	// This is the single most valuable line in the file. It is the difference
	// between a bad certificate being a rolled-back non-event and a bad
	// certificate being an outage, and it is the reason install and reload are
	// two steps rather than one.
	Check []string `json:"check,omitempty"`
	// Reload tells the running server to pick the new material up.
	Reload []string `json:"reload,omitempty"`
}

// InstallSpec is the whole file.
type InstallSpec struct {
	Destinations []Destination `json:"destinations"`
	// Found records whether the file existed at all, which is not the same as
	// its being empty. A host that has never declared a destination should not
	// appear in the core as a deployment target with nothing in it; a host
	// whose spec was emptied should, so the core can clear what it used to
	// hold. One boolean tells those apart.
	Found bool `json:"-"`
}

// DefaultSpecPath is where this host's destinations are read from.
func DefaultSpecPath(stateDir string) string {
	if _, err := os.Stat(SystemSpecPath); err == nil {
		return SystemSpecPath
	}
	if stateDir == "" {
		return SystemSpecPath
	}
	return filepath.Join(stateDir, specFileName)
}

// LoadInstallSpec reads and validates the destinations declared on this host.
//
// Validated at load rather than at install time, so a typo is an error at
// startup — in the terminal of whoever just edited the file — instead of a
// failure discovered six weeks later when a renewal tries to use it.
//
// A missing file is not an error. Most hosts run the agent to obtain and report
// certificates and install nothing; requiring an empty file to say so would
// make the commonest configuration the one with a mandatory piece of
// boilerplate in it.
func LoadInstallSpec(path string) (InstallSpec, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return InstallSpec{}, nil
		}
		return InstallSpec{}, fmt.Errorf("could not read %s: %w", path, err)
	}

	var spec InstallSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		return InstallSpec{}, fmt.Errorf("%s is not valid JSON: %w", path, err)
	}
	spec.Found = true

	seen := map[string]bool{}
	for i := range spec.Destinations {
		d := &spec.Destinations[i]
		d.Name = strings.TrimSpace(d.Name)
		d.Certificate = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Certificate), "."))
		if d.Name == "" {
			return InstallSpec{}, fmt.Errorf("%s: destination %d has no name", path, i+1)
		}
		if seen[d.Name] {
			return InstallSpec{}, fmt.Errorf("%s: two destinations are both called %q", path, d.Name)
		}
		seen[d.Name] = true
		if err := d.validate(); err != nil {
			return InstallSpec{}, fmt.Errorf("%s: destination %q: %w", path, d.Name, err)
		}
	}
	return spec, nil
}

func (d *Destination) validate() error {
	if d.Certificate == "" {
		return fmt.Errorf("no certificate name — say which certificate belongs here")
	}
	if d.keystore() {
		if err := d.validateKeystore(); err != nil {
			return err
		}
	} else if d.CertPath == "" || d.KeyPath == "" {
		return fmt.Errorf("both cert_path and key_path are required")
	}
	for field, p := range map[string]string{
		"cert_path": d.CertPath, "key_path": d.KeyPath,
		"chain_path": d.ChainPath, "fullchain_path": d.FullChainPath,
	} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path, not %q", field, p)
		}
	}

	certMode, err := parseMode(d.CertMode, 0o644)
	if err != nil {
		return fmt.Errorf("cert_mode: %w", err)
	}
	keyMode, err := parseMode(d.KeyMode, 0o600)
	if err != nil {
		return fmt.Errorf("key_mode: %w", err)
	}
	// The agent must not create the finding it exists to report. Step 4b calls
	// a world-readable private key a CRITICAL and says the fix is reissuance,
	// because renewing leaves the exposure exactly where it was — so an agent
	// that would write one on request is a tool that manufactures its own
	// alerts. Group-readable is refused for the certificate's mode only when
	// the key shares the file; 0640 root:www-data is how this is normally and
	// correctly done.
	if keyMode&0o004 != 0 {
		return fmt.Errorf(
			"key_mode %s would make the private key readable by any account on this host; use 0600, or 0640 with a group",
			d.KeyMode)
	}
	// Only when it was actually written down. A combined file takes the key's
	// mode whatever cert_mode says, so refusing one because the *default*
	// certificate mode is world-readable would reject the correct HAProxy
	// destination — which is the one this project keeps finding at 0644 and
	// wants people to write. An explicit world-readable cert_mode on a file
	// that holds a key is a misunderstanding worth naming; an absent one is
	// not.
	if d.combined() && strings.TrimSpace(d.CertMode) != "" && certMode&0o004 != 0 {
		return fmt.Errorf(
			"cert_path and key_path are the same file, so it holds the private key; cert_mode %s would make it readable by any account on this host",
			d.CertMode)
	}

	for field, argv := range map[string][]string{"check": d.Check, "reload": d.Reload} {
		if len(argv) == 0 {
			continue
		}
		if strings.TrimSpace(argv[0]) == "" {
			return fmt.Errorf("%s has no command in it", field)
		}
		// Absolute, because this very often runs as root out of a systemd unit
		// whose PATH is not the one the person editing this file was looking
		// at. "systemctl" resolving to something different under the service
		// manager than in a shell is a class of surprise worth spending one
		// error message to remove.
		if !filepath.IsAbs(argv[0]) {
			return fmt.Errorf("%s must name an absolute path, not %q — this runs with the service manager's PATH, not yours",
				field, argv[0])
		}
	}
	return nil
}

// combined reports the HAProxy layout: certificate and key in one file.
func (d *Destination) combined() bool { return d.CertPath == d.KeyPath }

// modes resolves the two file modes, having already been validated.
func (d *Destination) modes() (certMode, keyMode os.FileMode) {
	certMode, _ = parseMode(d.CertMode, 0o644)
	keyMode, _ = parseMode(d.KeyMode, 0o600)
	return certMode, keyMode
}

func parseMode(text string, fallback os.FileMode) (os.FileMode, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil || value == 0 || value > 0o7777 {
		return 0, fmt.Errorf("%q is not a file mode; write it as octal, like \"0640\"", text)
	}
	return os.FileMode(value), nil
}

// ── Installing ──────────────────────────────────────────────

// Installer writes what this host holds where its servers actually read it.
type Installer struct {
	spec     InstallSpec
	specPath string
	held     []*Held
	now      func() time.Time
	// run is the command runner, replaced in tests. Nothing else about this
	// package is worth faking: the files are real files in a temporary
	// directory, and a rollback that only works against a mock is not a
	// rollback.
	run func(ctx context.Context, argv []string) (string, error)
}

// NewInstaller creates an installer over what this host currently holds.
func NewInstaller(spec InstallSpec, specPath string, held []*Held) *Installer {
	return &Installer{
		spec: spec, specPath: specPath, held: held,
		now: time.Now, run: runCommand,
	}
}

// Apply brings every declared destination into line with what this host holds.
//
// force names destinations to reinstall even when the files already match —
// which is what the core asks for when somebody presses deploy, and what
// nothing else should ever ask for. An agent that reloaded nginx every five
// minutes because it could would be a worse problem than a stale certificate.
func (i *Installer) Apply(ctx context.Context, force map[string]bool) agentapi.InstallationReport {
	report := agentapi.InstallationReport{
		ReportedAt:    i.now().UTC(),
		SpecPath:      i.specPath,
		Installations: []agentapi.Installation{},
	}
	for idx := range i.spec.Destinations {
		d := i.spec.Destinations[idx]
		report.Installations = append(report.Installations, i.applyOne(ctx, d, force[d.Name]))
	}
	sort.Slice(report.Installations, func(a, b int) bool {
		return report.Installations[a].Name < report.Installations[b].Name
	})
	return report
}

// applyOne installs one destination and says what happened.
func (i *Installer) applyOne(ctx context.Context, d Destination, force bool) agentapi.Installation {
	out := agentapi.Installation{
		Name:          d.Name,
		Certificate:   d.Certificate,
		Paths:         d.paths(),
		ReloadCommand: commandText(d.Reload),
		CheckCommand:  commandText(d.Check),
		Status:        agentapi.InstallUnfulfilled,
	}

	held := findHeld(i.held, d.Certificate)
	if held == nil {
		// Not an error and not silence. This host has been configured to
		// install something it has not been granted, which is a fact only this
		// process can observe and almost always one character in a hostname.
		out.Detail = fmt.Sprintf(
			"this host holds no certificate for %s, so nothing has been written to %s",
			d.Certificate, d.CertPath)
		return out
	}

	out.CertificateID = held.CertificateID
	out.NotAfter = timePtr(held.NotAfter)

	material, err := readMaterial(held)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}
	out.Fingerprint = material.fingerprint

	desired, err := d.render(material)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}

	owner, err := d.ownership()
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}

	changed, err := i.write(d, desired, owner, force)
	if err != nil {
		out.Status = agentapi.InstallFailed
		out.Error = err.Error()
		return out
	}

	if !changed {
		out.Status = agentapi.InstallInstalled
		out.Detail = fmt.Sprintf("%s already holds this certificate; nothing was written and nothing was reloaded",
			d.CertPath)
		out.InstalledAt = timePtr(fileTime(d.CertPath))
		return out
	}
	return i.confirm(ctx, d, desired, owner, out)
}

// confirm validates and reloads, and puts back what was there if either fails.
//
// The order is the whole point of splitting install from reload. A certificate
// is written, the server is asked whether it can live with it, and only then is
// the running process told to pick it up. A check that fails costs a rollback
// of files nothing has read yet; the same failure without a check costs a
// listener.
func (i *Installer) confirm(ctx context.Context, d Destination, desired *rendered,
	owner *ownership, out agentapi.Installation) agentapi.Installation {

	now := i.now().UTC()
	out.InstalledAt = &now

	if len(d.Check) > 0 {
		if output, err := i.run(ctx, d.Check); err != nil {
			return i.rollback(ctx, d, desired, owner, out, false,
				fmt.Errorf("%s refused the new certificate, so it was not loaded: %w%s",
					commandText(d.Check), err, suffix(output)))
		}
	}

	if len(d.Reload) == 0 {
		out.Status = agentapi.InstallInstalled
		out.Detail = fmt.Sprintf("wrote %s. No reload is declared for this destination, so whatever reads these files will pick the certificate up when it next restarts",
			strings.Join(d.paths(), ", "))
		return out
	}

	output, err := i.run(ctx, d.Reload)
	if err != nil {
		return i.rollback(ctx, d, desired, owner, out, true,
			fmt.Errorf("%s failed after the certificate was written: %w%s",
				commandText(d.Reload), err, suffix(output)))
	}

	out.Status = agentapi.InstallInstalled
	out.ReloadedAt = &now
	out.Detail = fmt.Sprintf("wrote %s and ran %s", strings.Join(d.paths(), ", "), commandText(d.Reload))
	return out
}

// rollback puts back what this destination was holding before.
//
// reloaded says whether the server has already been told to pick the new
// material up. If it has, restoring the files is not enough on its own — the
// process is running on something that is no longer on disk — so the reload is
// run again against the restored files. If the check failed, nothing was ever
// loaded and restoring the files is the whole of it.
func (i *Installer) rollback(ctx context.Context, d Destination, desired *rendered,
	owner *ownership, out agentapi.Installation, reloaded bool, cause error) agentapi.Installation {

	out.Status = agentapi.InstallFailed
	out.Error = cause.Error()

	if err := desired.restore(owner); err != nil {
		// The worst outcome this package has, and it is said as such. The
		// listener is now serving material nobody chose.
		out.Detail = fmt.Sprintf(
			"the previous certificate could not be put back: %v. %s may now hold material this host did not intend to install",
			err, d.CertPath)
		slog.Error("a deployment failed and the previous certificate could not be restored",
			"destination", d.Name, "path", d.CertPath, "error", err)
		return out
	}

	out.RolledBack = true
	if !reloaded {
		out.Detail = fmt.Sprintf("the previous certificate was put back and %s was never reloaded, so it is still serving what it was before",
			d.Name)
		return out
	}
	if _, err := i.run(ctx, d.Reload); err != nil {
		out.Detail = fmt.Sprintf("the previous certificate was put back, but %s failed again afterwards: %v",
			commandText(d.Reload), err)
		return out
	}
	out.Detail = fmt.Sprintf("the previous certificate was put back and %s was reloaded onto it",
		d.Name)
	return out
}

// write puts the rendered material in place, remembering what was there.
//
// Every file is written to a temporary name in its own directory and renamed
// over the target, so a server reading the file while this runs sees either the
// old contents or the new ones and never half of either. The rename is atomic
// only within a filesystem, which is why the temporary file is made beside the
// destination rather than in /tmp.
//
// What was there is kept in memory rather than in a backup file. A private key
// copied to `server.key.bak` is a private key nobody is tracking, sitting in
// the directory the agent exists to keep tidy.
func (i *Installer) write(d Destination, desired *rendered, owner *ownership, force bool) (bool, error) {
	if !force && desired.matches() {
		// Permissions are still enforced, without a write and without a reload.
		// A key somebody chmodded to 0644 in an incident three weeks ago is
		// exactly the finding step 4b reports, and this is the one process in
		// the system that can quietly put it back.
		return false, desired.enforce(owner)
	}

	// Indexed, not ranged. `for _, f := range` hands out a copy of each
	// element, so capturing into it recorded what was there on a value that was
	// then discarded — and the rollback, finding no previous contents, deleted
	// a file that had been working. The tests caught it; nothing else would
	// have until a reload failed in production.
	for idx := range desired.files {
		if err := desired.files[idx].capture(); err != nil {
			return false, err
		}
	}
	for idx := range desired.files {
		f := &desired.files[idx]
		if err := writeAtomic(f.path, f.content, f.mode, owner); err != nil {
			// Undo the ones already written before giving up, so a failure
			// halfway through cannot leave a certificate from one issuance
			// beside a key from another.
			_ = desired.restore(owner)
			return false, fmt.Errorf("could not write %s: %w", f.path, err)
		}
		f.written = true
	}
	return true, nil
}

// ── Rendering ───────────────────────────────────────────────

type rendered struct {
	files []targetFile
}

type targetFile struct {
	path    string
	content []byte
	mode    os.FileMode

	written  bool
	existed  bool
	previous []byte
	prevMode os.FileMode
}

func (f *targetFile) capture() error {
	body, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			f.existed = false
			return nil
		}
		return fmt.Errorf("could not read the certificate already at %s: %w", f.path, err)
	}
	info, err := os.Stat(f.path)
	if err != nil {
		return err
	}
	f.existed, f.previous, f.prevMode = true, body, info.Mode().Perm()
	return nil
}

// matches reports whether every file already holds exactly what would be
// written.
func (r *rendered) matches() bool {
	for idx := range r.files {
		body, err := os.ReadFile(r.files[idx].path)
		if err != nil || !bytes.Equal(body, r.files[idx].content) {
			return false
		}
	}
	return true
}

// enforce applies the declared mode and ownership without touching contents.
func (r *rendered) enforce(owner *ownership) error {
	for idx := range r.files {
		f := &r.files[idx]
		info, err := os.Stat(f.path)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != f.mode {
			slog.Info("correcting the permissions on an installed certificate file",
				"path", f.path, "was", fmt.Sprintf("%04o", info.Mode().Perm()),
				"now", fmt.Sprintf("%04o", f.mode))
			if err := os.Chmod(f.path, f.mode); err != nil {
				return fmt.Errorf("could not set the mode on %s: %w", f.path, err)
			}
		}
		if err := owner.apply(f.path); err != nil {
			return err
		}
	}
	return nil
}

// restore puts back everything write() replaced.
func (r *rendered) restore(owner *ownership) error {
	var failures []string
	for idx := len(r.files) - 1; idx >= 0; idx-- {
		f := &r.files[idx]
		if !f.written {
			continue
		}
		var err error
		if f.existed {
			err = writeAtomic(f.path, f.previous, f.prevMode, owner)
		} else if err = os.Remove(f.path); os.IsNotExist(err) {
			err = nil
		}
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", f.path, err))
			continue
		}
		f.written = false
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return nil
}

// render builds the exact bytes each declared file should hold.
func (d *Destination) render(m *material) (*rendered, error) {
	certMode, keyMode := d.modes()
	out := &rendered{}

	if d.keystore() {
		// One file, at the key's mode, because it holds the key. Nothing else
		// about this destination changes: the same capture, the same check
		// before the reload, and the same restore from the captured copy if the
		// reload fails.
		body, err := encodeKeystore(d, m)
		if err != nil {
			return nil, err
		}
		out.files = append(out.files, targetFile{path: d.CertPath, mode: keyMode, content: body})
		return out, nil
	}

	if d.combined() {
		// Certificate, chain, then key, in one file at the key's mode. The
		// order servers that want this layout expect, and the mode the layout
		// actually requires.
		out.files = append(out.files, targetFile{
			path: d.CertPath, mode: keyMode,
			content: concat(m.certPEM, m.chainPEM, m.keyPEM),
		})
	} else {
		out.files = append(out.files,
			targetFile{path: d.CertPath, content: m.certPEM, mode: certMode},
			targetFile{path: d.KeyPath, content: m.keyPEM, mode: keyMode},
		)
	}
	if d.ChainPath != "" {
		if len(m.chainPEM) == 0 {
			return nil, fmt.Errorf("this destination asks for a chain at %s and the issued certificate came with none",
				d.ChainPath)
		}
		out.files = append(out.files, targetFile{path: d.ChainPath, content: m.chainPEM, mode: certMode})
	}
	if d.FullChainPath != "" {
		out.files = append(out.files,
			targetFile{path: d.FullChainPath, content: concat(m.certPEM, m.chainPEM), mode: certMode})
	}
	return out, nil
}

// paths lists the files this destination writes, in the order it writes them.
func (d *Destination) paths() []string {
	out := []string{d.CertPath}
	// A keystore is one file. Without this the list carries an empty string,
	// and the "wrote ..." line an operator reads ends in a stray comma.
	if d.keystore() {
		return out
	}
	if !d.combined() {
		out = append(out, d.KeyPath)
	}
	if d.ChainPath != "" {
		out = append(out, d.ChainPath)
	}
	if d.FullChainPath != "" {
		out = append(out, d.FullChainPath)
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var buf bytes.Buffer
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		buf.Write(p)
		if p[len(p)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}
