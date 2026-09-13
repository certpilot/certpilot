package agentapi

import "time"

// What one declared destination is currently doing.
const (
	// InstallInstalled means the destination holds the material the host holds.
	InstallInstalled = "INSTALLED"
	// InstallFailed means the last attempt did not finish. Whether the old
	// material was put back is a separate field, because "it failed" and "it
	// failed and the listener is now serving nothing" are different mornings.
	InstallFailed = "FAILED"
	// InstallUnfulfilled means this host declares a destination for a
	// certificate it does not hold.
	//
	// The status no other view in this system can produce. A remote scanner
	// sees what a listener serves; the issuance record sees what was asked
	// for; neither can see that a machine has been configured to install
	// something nobody ever granted it. It is almost always a name in the spec
	// that does not match the name on the grant — a typo that will be
	// discovered at the next renewal, in the dark, unless something says so
	// now.
	InstallUnfulfilled = "UNFULFILLED"
)

// Installation is what one named destination on one host looks like.
//
// Reported by the agent, never sent to it. The distinction is the whole
// security argument of this step and it is worth stating where the type lives:
// the *specification* — which paths, which owner, and above all which command
// to run — is read from a file on the host, and there is no wire format for it
// in this package because it must never have one. A core that could hand an
// agent a command to run would be a fleet-wide remote execution channel wearing
// a certificate manager's clothes.
//
// What travels is this: what the host was told to do, and what happened when it
// did it.
type Installation struct {
	// Name is the destination's name in the host's spec — "nginx", "haproxy".
	Name string `json:"name"`
	// Certificate is the name this destination is declared for, as written in
	// the spec. Kept even when nothing matched it, because an unmatched name is
	// the finding.
	Certificate string `json:"certificate"`

	// CertificateID is the core's id for what was installed, when the host
	// holds one. Empty for an unfulfilled destination.
	CertificateID string     `json:"certificate_id,omitempty"`
	Fingerprint   string     `json:"fingerprint_sha256,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`

	// Paths are the files this destination writes, in the order they are
	// written. Reported so the central view can answer "where does this
	// certificate actually live on that machine" without anybody logging in.
	Paths []string `json:"paths,omitempty"`

	Status string `json:"status"`
	// Detail is what happened, in words, for whoever reads the attempt log.
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`

	// RolledBack records that an attempt failed and the previous material was
	// put back. Separate from the error on purpose: a failed install that
	// restored what was working is an inconvenience, and a failed install that
	// did not is an outage.
	RolledBack bool `json:"rolled_back,omitempty"`

	InstalledAt *time.Time `json:"installed_at,omitempty"`
	ReloadedAt  *time.Time `json:"reloaded_at,omitempty"`

	// ReloadCommand and CheckCommand are reported for visibility, rendered as
	// text. A central team should be able to see that installing a certificate
	// on this host runs `nginx -s reload` without having shell on it — and
	// seeing it is the opposite of being able to set it.
	ReloadCommand string `json:"reload_command,omitempty"`
	CheckCommand  string `json:"check_command,omitempty"`

	// JobID is set when this install was done because the core asked for one,
	// rather than because the host noticed its own files were stale.
	JobID string `json:"job_id,omitempty"`
}

// InstallationReport is the full state of one host's destinations.
//
// Full state rather than a delta, exactly like the inventory report, and for
// the same reason: a lost report costs nothing because the next one carries
// everything, and the core's picture converges without either side keeping a
// cursor the other could disagree with.
type InstallationReport struct {
	ReportedAt time.Time `json:"reported_at"`
	// SpecPath is where the host read its destinations from, so "the core shows
	// no destinations for this machine" can be told apart from "the machine is
	// reading a file nobody edited".
	SpecPath      string         `json:"spec_path,omitempty"`
	Installations []Installation `json:"installations"`
	// Errors are destinations that could not even be attempted — an unreadable
	// spec, a directory that does not exist. Reported rather than swallowed.
	Errors []string `json:"errors,omitempty"`
}

// DeploymentAssignment is one installation the core is asking a host to do now.
//
// It names a certificate and a place, and carries no instruction of any kind.
// Everything about *how* to install — the paths, the ownership, the command —
// comes from the host's own spec, so the worst a compromised core can do to a
// host through this channel is ask it to reinstall something it already holds.
type DeploymentAssignment struct {
	JobID        string `json:"job_id"`
	DeploymentID string `json:"deployment_id"`

	CertificateID string `json:"certificate_id"`
	CommonName    string `json:"common_name"`
	Fingerprint   string `json:"fingerprint_sha256,omitempty"`

	// Destinations are the named destinations on this host that this binding
	// covers, as the host itself last reported them.
	Destinations []string `json:"destinations,omitempty"`

	Reason   string     `json:"reason,omitempty"`
	NotAfter *time.Time `json:"not_after,omitempty"`
}

// DeploymentResult is what the host did with an assignment.
type DeploymentResult struct {
	JobID   string `json:"job_id"`
	Success bool   `json:"success"`
	Detail  string `json:"detail,omitempty"`
	Error   string `json:"error,omitempty"`
}
