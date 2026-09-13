package agent

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// A platform profile fills in a destination, so declaring one names a platform
// instead of restating four facts about it.
//
// The machinery to serve a platform already existed before this file: the
// installer writes atomically, validates the configuration before committing to
// it, reloads the service and rolls back from a captured copy if the reload
// fails. What was missing was any statement of *which* platforms that covers.
// An operator evaluating CertPilot for a Tomcat estate read "there is an agent"
// and had to work it out for themselves, and the honest answer was "yes, if you
// write the spec by hand".
//
// So a profile is four fields — a path, a format, a check command and a reload
// command — and everything else already exists.
//
// # A profile is a default, not a lock
//
// Estates move paths. Every field a profile supplies is one the operator may
// write down themselves, and theirs wins; the profile fills only what was left
// blank. A profile that could not be overridden would be worse than no profile,
// because it would look supported while writing to somewhere nothing reads.
//
// # Detection does not imply support
//
// [Profile.Detect] says what to look for on a host that runs this platform. It
// answers "does this file exist", and that is all it answers. It does not mean
// the paths in this profile are the ones the service is reading — the service
// reads whatever its configuration says, and inventory.go's parser for that
// calls itself a heuristic and openly so. Detection is a prompt for a human,
// never a decision the agent makes on its own.
//
// # Every profile here has been installed to
//
// Not unit-tested: run. scripts/verify-profiles.sh starts the real service in a
// container, installs a certificate through this agent's own installer, runs
// this profile's check and reload, and completes a TLS handshake against the
// running service to prove it is serving that certificate. A profile nobody
// ran is a claim, and this issue exists because unverified assets are how a
// quickstart came to describe a Dockerfile nobody had built.
type Profile struct {
	// Name is what an operator writes in `"profile": "nginx"`.
	Name string
	// Platform is the human name, for `certpilot-agent profiles`.
	Platform string
	// Summary says what this platform does with a certificate, in one line.
	Summary string

	// Detect is paths whose existence suggests this platform is installed.
	// Suggests. See the note above.
	Detect []string

	// The destination this profile fills in. Any field the operator set is
	// left alone; these are defaults.
	Format        string
	CertPath      string
	KeyPath       string
	ChainPath     string
	FullChainPath string
	CertMode      string
	KeyMode       string
	Owner         string
	Group         string
	Check         []string
	Reload        []string

	// Notes is what an operator has to know that the fields do not say: a
	// configuration line they still have to write, a reload that is really a
	// restart, a permission the service needs. Printed by `profiles show`.
	Notes []string

	// Verified records the service and version this profile was last run
	// against, so the claim carries its own evidence.
	Verified string
}

// certificatePlaceholder is substituted into a profile's paths.
//
// One placeholder rather than a template language, because a template package
// brings a parse-error surface and a syntax to learn for a feature whose entire
// requirement is "put the certificate's name in the filename". Anything else
// left in braces is an error rather than a silently literal path — a file
// called "{{ .Name }}.crt" is not a typo anybody wants to discover from a
// failed handshake.
const certificatePlaceholder = "{{ .Certificate }}"

// profileDir is where profiles put material they own.
//
// Deliberately not inside /etc/nginx or /etc/postfix. Those directories belong
// to a package manager and to whatever configuration management already writes
// there; a certificate manager that scatters files through them is one that
// makes somebody else's `dpkg --verify` noisy and its own uninstall a hunt. One
// directory, one owner, and a configuration line pointing into it.
const profileDir = "/etc/certpilot/live"

// Profiles is the catalogue, ordered as `certpilot-agent profiles` prints it.
//
// Web servers first, because that is the shape of most estates, then the
// services that terminate TLS without anybody thinking of them as web servers —
// which is where the certificates nobody is tracking usually are.
func Profiles() []Profile { return append([]Profile(nil), catalogue...) }

// LookupProfile finds one by name.
func LookupProfile(name string) (Profile, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, p := range catalogue {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// ProfileNames is every name, for an error message that lists the alternatives.
func ProfileNames() []string {
	names := make([]string, 0, len(catalogue))
	for _, p := range catalogue {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return names
}

// apply fills in whatever the operator left blank.
//
// The operator's own value always wins, including an explicit empty list: a
// `"reload": []` is somebody saying this destination reloads by some other
// means, and replacing it with the profile's default would run a command they
// had deliberately removed. That distinction is why the list fields test
// against nil rather than length.
func (d *Destination) applyProfile() error {
	if strings.TrimSpace(d.Profile) == "" {
		// No profile, but the placeholder still expands. Somebody writing
		// their own paths with {{ .Certificate }} in them has done nothing
		// wrong, and a substitution that worked only alongside a profile would
		// be a rule nobody could remember.
		return d.expandPlaceholders()
	}
	p, ok := LookupProfile(d.Profile)
	if !ok {
		return fmt.Errorf("no profile called %q — known profiles: %s",
			d.Profile, strings.Join(ProfileNames(), ", "))
	}

	fill := func(dst *string, from string) {
		if strings.TrimSpace(*dst) == "" {
			*dst = from
		}
	}
	fill(&d.Format, p.Format)
	fill(&d.CertPath, p.CertPath)
	fill(&d.KeyPath, p.KeyPath)
	fill(&d.ChainPath, p.ChainPath)
	fill(&d.FullChainPath, p.FullChainPath)
	fill(&d.CertMode, p.CertMode)
	fill(&d.KeyMode, p.KeyMode)
	fill(&d.Owner, p.Owner)
	fill(&d.Group, p.Group)
	if d.Check == nil {
		d.Check = append([]string(nil), p.Check...)
	}
	if d.Reload == nil {
		d.Reload = append([]string(nil), p.Reload...)
	}

	return d.expandPlaceholders()
}

// expandPlaceholders substitutes the certificate name into the paths.
//
// Applied to the operator's own paths too, not only the profile's. Somebody
// overriding cert_path to keep their existing directory layout wants the same
// substitution the profile would have done, and a placeholder that worked in
// one field and not the other would be a rule nobody could remember.
func (d *Destination) expandPlaceholders() error {
	for _, f := range []struct {
		name string
		p    *string
	}{
		{"cert_path", &d.CertPath},
		{"key_path", &d.KeyPath},
		{"chain_path", &d.ChainPath},
		{"fullchain_path", &d.FullChainPath},
	} {
		*f.p = strings.ReplaceAll(*f.p, certificatePlaceholder, d.Certificate)
		if strings.Contains(*f.p, "{{") {
			return fmt.Errorf(
				"%s contains %q, which is not a placeholder this understands; the only one is %s",
				f.name, remainingPlaceholder(*f.p), certificatePlaceholder)
		}
	}
	return nil
}

func remainingPlaceholder(path string) string {
	start := strings.Index(path, "{{")
	if start < 0 {
		return ""
	}
	end := strings.Index(path[start:], "}}")
	if end < 0 {
		return path[start:]
	}
	return path[start : start+end+2]
}

// DetectProfiles reports which platforms appear to be installed on this host.
//
// "Appear to be". The result is a prompt for somebody to confirm, never an
// instruction the agent acts on: a returned profile means one of its detect
// paths exists, which is a statement about a file and not about what the
// running service is configured to read.
func DetectProfiles() []Profile {
	var found []Profile
	for _, p := range catalogue {
		for _, path := range p.Detect {
			if _, err := os.Stat(path); err == nil {
				found = append(found, p)
				break
			}
		}
	}
	return found
}
