package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/certpilot/certpilot-agent-sdk/agentapi"
)

// Discovered and InventoryReport are the wire types, defined once in
// package agentapi because the core has to read exactly what this writes.
type (
	Discovered      = agentapi.Discovered
	InventoryReport = agentapi.InventoryReport
)

// Bounds on a scan.
//
// An agent walks a production filesystem on a timer. Every one of these exists
// so that a misconfigured root, a runaway mount, or a directory somebody
// symlinked to / costs a bounded amount of IO rather than the host.
const (
	maxDepth     = 8
	maxFiles     = 20000
	maxFileBytes = 1 << 20
	// maxCertificatesInFile is where a file stops being a certificate and
	// becomes a trust store. /etc/ssl/certs/ca-certificates.crt holds well over
	// a hundred roots, and reporting each of them would bury every real finding
	// on the host under the contents of a package nobody edited.
	maxCertificatesInFile = 20
	// maxReported bounds one report, so a host with a pathological directory
	// cannot send an unbounded body.
	maxReported = 500
)

// DefaultScanPaths are where certificates live on a Unix host.
//
// Deliberately a list of specific directories rather than "/". An agent that
// walks the whole filesystem finds the same certificates plus every test
// fixture in every application's vendor directory, takes minutes doing it, and
// teaches its operator to ignore the results.
func DefaultScanPaths() []string {
	return []string{
		"/etc/ssl",
		"/etc/pki",
		"/etc/nginx",
		"/etc/apache2",
		"/etc/httpd",
		"/etc/haproxy",
		"/etc/letsencrypt",
		"/etc/certpilot",
		"/usr/local/etc/ssl",
		"/usr/local/etc/nginx",
		"/opt/certs",
		"/srv/certs",
	}
}

// skipDirs are never descended into.
//
// The kernel filesystems would produce an unbounded walk; the trust stores
// would produce hundreds of rows for root certificates the distribution
// manages and nobody in this organisation is responsible for.
var skipDirs = map[string]bool{
	"/proc": true, "/sys": true, "/dev": true,
	"/etc/ssl/certs": true, "/etc/pki/ca-trust": true,
	"/usr/share/ca-certificates": true,
}

// Scan walks this host for certificates.
func Scan(paths []string) InventoryReport {
	if len(paths) == 0 {
		paths = DefaultScanPaths()
	}

	report := InventoryReport{ScannedAt: time.Now(), Paths: paths}
	seen := map[string]bool{} // resolved path, so a symlink farm is one row
	byPath := map[string]*Discovered{}
	order := []string{}

	for _, root := range paths {
		if _, err := os.Stat(root); err != nil {
			// Not an error worth reporting. Most hosts have most of the default
			// paths absent, and listing them would make every report mostly
			// noise about software that is not installed.
			continue
		}
		walkRoot(root, &report, seen, byPath, &order)
	}

	// Where the configuration says these files are used. Done after the walk so
	// it can match against what was actually found.
	scanConfigReferences(paths, byPath, &report)

	for _, path := range order {
		if len(report.Certificates) >= maxReported {
			report.Truncated = true
			break
		}
		report.Certificates = append(report.Certificates, *byPath[path])
	}
	return report
}

func walkRoot(root string, report *InventoryReport, seen map[string]bool,
	byPath map[string]*Discovered, order *[]string) {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", path, err))
			return fs.SkipDir
		}
		if report.FilesSeen >= maxFiles {
			report.Truncated = true
			return fs.SkipAll
		}

		if d.IsDir() {
			if skipDirs[filepath.Clean(path)] {
				return fs.SkipDir
			}
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		// Directory symlinks are not followed — a link back up the tree would
		// otherwise walk forever. File symlinks are, because that is how Let's
		// Encrypt lays out `live/`.
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil
			}
			info, err := os.Stat(target)
			if err != nil || info.IsDir() {
				return nil
			}
		}

		report.FilesSeen++
		if !looksLikeCertificate(path) {
			return nil
		}

		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path
		}
		if seen[real] {
			// The same file reached twice. Let's Encrypt's live/ directory is
			// symlinks into archive/, and reporting both would double every
			// certbot host's inventory.
			return nil
		}

		found := inspect(path)
		if found == nil {
			return nil
		}
		seen[real] = true
		byPath[path] = found
		*order = append(*order, path)
		return nil
	})
}

// certExtensions are the file names worth opening.
//
// Extension-first rather than content-first because the alternative is reading
// every file under /etc to see whether it starts with a PEM header, and /etc
// contains a great many files.
var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true, ".ca-bundle": true,
}

func looksLikeCertificate(path string) bool {
	if certExtensions[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	// Certbot writes fullchain.pem and cert.pem; some deployments drop the
	// extension entirely on the file HAProxy loads.
	base := strings.ToLower(filepath.Base(path))
	return base == "fullchain" || base == "cert" || base == "server" || base == "tls"
}

// inspect reads one candidate file and returns what it is, or nil.
func inspect(path string) *Discovered {
	info, err := os.Stat(path)
	if err != nil || info.Size() > maxFileBytes || info.Size() == 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	certs, keyInFile := parsePEMFile(raw)
	if len(certs) == 0 {
		// Try DER: a .cer or .der written straight out of a Windows export.
		if cert, err := x509.ParseCertificate(raw); err == nil {
			certs = []*x509.Certificate{cert}
		} else {
			return nil
		}
	}

	// The subject of the row is the first certificate in the file. A file
	// holding a leaf and its chain is one certificate on this host, not three.
	leaf := certs[0]
	kind := agentapi.KindLeaf
	switch {
	case len(certs) > maxCertificatesInFile:
		kind = agentapi.KindBundle
	case isAuthority(leaf):
		kind = agentapi.KindCA
	}

	sum := sha256.Sum256(leaf.Raw)
	found := &Discovered{
		Path:                 path,
		CertificatePEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		Fingerprint:          hex.EncodeToString(sum[:]),
		Kind:                 kind,
		CertificateCount:     len(certs),
		Mode:                 fmt.Sprintf("%04o", info.Mode().Perm()),
		Owner:                ownerOf(info),
		ModifiedAt:           info.ModTime(),
		PrivateKeyInSameFile: keyInFile != nil,
	}

	// A trust store is recorded and left alone. It is worth knowing the file is
	// there; it is not worth a finding per root certificate in it.
	if kind == agentapi.KindBundle {
		return found
	}

	if keyInFile != nil {
		found.PrivateKeyPath = path
		found.PrivateKeyMode = found.Mode
		found.PrivateKeyMatches = keyMatches(keyInFile, leaf)
		return found
	}
	if keyPath, key := findPrivateKey(path, leaf); key != nil {
		keyInfo, err := os.Stat(keyPath)
		if err == nil {
			found.PrivateKeyPath = keyPath
			found.PrivateKeyMode = fmt.Sprintf("%04o", keyInfo.Mode().Perm())
			found.PrivateKeyMatches = keyMatches(key, leaf)
		}
	}
	return found
}

// parsePEMFile pulls every certificate, and any private key, out of one file.
//
// The key is parsed but never kept beyond this function: what leaves here is
// whether it is there, whether it matches, and what its permissions are. There
// is no field on Discovered that a private key could travel in, which is the
// same property the agent's own identity key has.
func parsePEMFile(raw []byte) ([]*x509.Certificate, crypto.PublicKey) {
	var certs []*x509.Certificate
	var public crypto.PublicKey

	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				certs = append(certs, cert)
			}
		case strings.Contains(block.Type, "PRIVATE KEY"):
			if pub := publicOf(block); pub != nil {
				public = pub
			}
		}
	}
	return certs, public
}

// publicOf derives the public half of a private key without retaining it.
func publicOf(block *pem.Block) crypto.PublicKey {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer.Public()
		}
		return nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key.Public()
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key.Public()
	}
	return nil
}

// keyCandidates are the names a certificate's key is kept under, split by how
// much the name tells us.
//
// A stem-derived name — `site.key` beside `site.crt` — is a statement that
// these two belong together, so a key found there that does not match the
// certificate is a genuine mismatch worth alerting on.
//
// A conventional name — `key.pem`, `privkey.pem` — is a guess. It is usually
// right, and when it is wrong it is wrong because the directory holds more than
// one certificate. Treating a failed guess as a mismatch produced a CRITICAL
// alert about a chain file whose "key" was the leaf's, which is precisely the
// kind of false positive that teaches people to ignore the real ones.
func keyCandidates(certPath string) (specific, conventional []string) {
	dir := filepath.Dir(certPath)
	base := filepath.Base(certPath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))

	for _, name := range []string{stem + ".key", stem + "-key.pem", stem + ".key.pem", stem + "_key.pem"} {
		specific = append(specific, filepath.Join(dir, name))
	}
	// Certbot writes cert.pem and fullchain.pem beside privkey.pem.
	for _, name := range []string{"privkey.pem", "private.key", "server.key", "tls.key", "key.pem"} {
		conventional = append(conventional, filepath.Join(dir, name))
	}
	return specific, conventional
}

// findPrivateKey looks for the key belonging to a certificate.
//
// A key found under a name derived from the certificate's own is reported
// whether or not it matches — that is the mismatch worth knowing about. A key
// found under a conventional name is reported only if it does match, because a
// guess that turns out wrong is evidence the key is elsewhere, not evidence the
// pair is broken.
func findPrivateKey(certPath string, cert *x509.Certificate) (string, crypto.PublicKey) {
	specific, conventional := keyCandidates(certPath)

	for _, candidate := range specific {
		if candidate == certPath {
			continue
		}
		if key := readPublicHalf(candidate); key != nil {
			return candidate, key
		}
	}
	for _, candidate := range conventional {
		if candidate == certPath {
			continue
		}
		key := readPublicHalf(candidate)
		if key != nil && keyMatches(key, cert) {
			return candidate, key
		}
	}
	return "", nil
}

func readPublicHalf(path string) crypto.PublicKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	_, key := parsePEMFile(raw)
	return key
}

// keyMatches reports whether a private key belongs to a certificate.
//
// Compared on the public half, which is the only comparison that means
// anything: a key file sitting next to a certificate proves nothing, and a
// mismatched pair is a service that will not come back after its next restart,
// waiting quietly for something to restart it.
func keyMatches(public crypto.PublicKey, cert *x509.Certificate) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		if eq, ok := pub.(equaler); ok {
			return eq.Equal(public)
		}
	}
	return false
}

// isAuthority reports whether a certificate is a CA rather than something a
// server presents.
//
// Not simply `IsCA`. OpenSSL's `req -x509` sets basicConstraints CA:TRUE by
// default, so a very large share of the self-signed certificates on an
// internal estate — which is most of them — claim to be authorities while
// plainly being server certificates. Classifying those as CAs made them skip
// the findings that only apply to leaves, and it was a fixture built to look
// like a real internal host that showed it.
//
// The distinguishing question is not what the certificate claims about itself
// but whether it identifies a host: a genuine root or intermediate has no DNS
// or IP subject alternative names, and a certificate that has them is being
// used to serve something whatever its basic constraints say.
func isAuthority(cert *x509.Certificate) bool {
	if !cert.IsCA {
		return false
	}
	return len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0
}

func ownerOf(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", stat.Uid, stat.Gid)
}

// configDirectives maps a server's way of naming a certificate to the regexp
// that finds it.
//
// A heuristic and openly so. Writing a real nginx configuration parser — with
// includes, variables, and inheritance — to answer "is this file referenced" is
// a project in itself, and getting it 90% right is worth far more here than a
// perfect answer nobody has time to build. What matters is that the false
// direction is safe: a file we fail to match is reported as unreferenced, which
// invites a look, rather than being silently marked as in use.
var configDirectives = []*regexp.Regexp{
	// nginx: ssl_certificate /path;   ssl_certificate_key /path;
	regexp.MustCompile(`(?m)^\s*ssl_certificate(?:_key)?\s+([^\s;]+)\s*;`),
	// apache: SSLCertificateFile /path
	regexp.MustCompile(`(?mi)^\s*SSLCertificate(?:Key|Chain)?File\s+"?([^\s"]+)"?`),
	// haproxy: bind :443 ssl crt /path
	regexp.MustCompile(`(?m)\bcrt\s+([^\s]+)`),
}

var configExtensions = map[string]bool{
	".conf": true, ".cfg": true, ".config": true, "": true,
}

// scanConfigReferences marks the files a server configuration names.
func scanConfigReferences(roots []string, byPath map[string]*Discovered, report *InventoryReport) {
	if len(byPath) == 0 {
		return
	}

	// Resolved path to the entries that live there, so a reference to a symlink
	// finds the file it points at.
	byReal := map[string][]*Discovered{}
	for path, found := range byPath {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path
		}
		byReal[real] = append(byReal[real], found)
	}

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if err != nil {
					return fs.SkipDir
				}
				if skipDirs[filepath.Clean(path)] {
					return fs.SkipDir
				}
				return nil
			}
			if !configExtensions[strings.ToLower(filepath.Ext(path))] {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxFileBytes {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			for _, re := range configDirectives {
				for _, match := range re.FindAllStringSubmatch(string(raw), -1) {
					target := match[1]
					if !filepath.IsAbs(target) {
						target = filepath.Join(filepath.Dir(path), target)
					}
					real, err := filepath.EvalSymlinks(target)
					if err != nil {
						real = filepath.Clean(target)
					}
					for _, found := range byReal[real] {
						found.ReferencedBy = appendUnique(found.ReferencedBy, path)
					}
				}
			}
			return nil
		})
	}
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}
