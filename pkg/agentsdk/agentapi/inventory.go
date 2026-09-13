// Package agentapi holds the wire types an agent and the core both speak.
//
// One definition rather than one per side. These structs cross a version
// boundary that is wider than any other in this system: an agent installed on a
// host in March is still running in December, against a core that has been
// upgraded four times. A field that means one thing on one side and something
// else on the other is the failure mode, and two copies of a struct is how it
// starts — which is the same argument that put the signature scheme in
// package webhooksig.
package agentapi

import "time"

// Certificate kinds.
const (
	// KindLeaf is an end-entity certificate: the thing a server presents.
	KindLeaf = "leaf"
	// KindCA is a certificate authority — a chain file, an intermediate, a
	// root somebody dropped on the host.
	KindCA = "ca"
	// KindBundle is a trust store. A host's ca-certificates file holds well
	// over a hundred roots the distribution manages and nobody in this
	// organisation is responsible for; it is recorded as one row that says so,
	// rather than as a hundred findings.
	KindBundle = "bundle"
)

// Discovered is one certificate file found on a host.
//
// The certificate travels as PEM, unparsed. Parsing centrally rather than on
// the host is a deliberate split: this runs on machines nobody upgrades for
// years, and parsing logic living on five hundred of them is parsing logic that
// cannot be fixed.
//
// There is no private key field, and that is the point rather than an
// oversight. The agent parses a key it finds only far enough to derive its
// public half and compare, and there is nothing here it could travel in.
type Discovered struct {
	Path           string `json:"path"`
	CertificatePEM string `json:"certificate_pem"`
	Fingerprint    string `json:"fingerprint_sha256"`

	Kind             string `json:"kind"`
	CertificateCount int    `json:"certificate_count"`

	// What only a process on the host can see.
	Mode       string    `json:"mode"`
	Owner      string    `json:"owner"`
	ModifiedAt time.Time `json:"modified_at"`

	// PrivateKeyPath is where the matching key was found, if it was. Empty is
	// information rather than an absence: a certificate on a host with no key
	// is one that host cannot serve.
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	PrivateKeyMode string `json:"private_key_mode,omitempty"`
	// PrivateKeyInSameFile marks the layout HAProxy requires and many other
	// things allow: certificate and key concatenated. The file's permissions
	// then matter as much as a key file's, and are very often set as though it
	// were only a certificate.
	PrivateKeyInSameFile bool `json:"private_key_in_same_file,omitempty"`
	// PrivateKeyMatches is whether the key actually belongs to this
	// certificate. A mismatched pair is a service that will not come back after
	// its next restart, waiting quietly for something to restart it.
	PrivateKeyMatches bool `json:"private_key_matches,omitempty"`

	// ReferencedBy is where this file is named in a server configuration.
	// Found by text search, so empty means "not matched", never "unused".
	ReferencedBy []string `json:"referenced_by,omitempty"`
}

// InventoryReport is what one scan of one host produced.
type InventoryReport struct {
	ScannedAt    time.Time    `json:"scanned_at"`
	Paths        []string     `json:"paths"`
	FilesSeen    int          `json:"files_seen"`
	Certificates []Discovered `json:"certificates"`
	// Errors are directories or files that could not be read. Reported rather
	// than swallowed: "found nothing under /etc/pki" and "could not read
	// /etc/pki" are opposite conclusions and look identical in a result set
	// that omits the second.
	Errors []string `json:"errors,omitempty"`
	// Truncated is set when the scan hit one of its own limits, so a short list
	// is never mistaken for a small host.
	Truncated bool `json:"truncated,omitempty"`
}

// ConfigScanWorked reports whether the reference heuristic matched anything at
// all on this host.
//
// Used to decide whether "no configuration names this file" is worth saying. On
// a host where nothing was matched, that sentence is a finding about the
// heuristic rather than about the host, and reporting it against every file
// would teach its reader to ignore the whole category.
func (r InventoryReport) ConfigScanWorked() bool {
	for _, c := range r.Certificates {
		if len(c.ReferencedBy) > 0 {
			return true
		}
	}
	return false
}
