// Package agentauth defines how a CertPilot agent proves who it is.
//
// The agent's credential is a private key it generated on the host it runs on
// and has never sent anywhere. The core stores only the public half, so a
// database that leaks yields nothing that can impersonate an agent — which is
// not true of a bearer token, and bearer tokens on five hundred hosts are
// exactly the thing this product exists to stop organisations doing.
//
// # Why signatures rather than mTLS
//
// mTLS would be the obvious answer and it is the wrong one *here*. The core is
// routinely deployed behind a reverse proxy — the shipped compose stack puts
// nginx in front of it — and client-certificate authentication terminates at
// that proxy. What reaches the application is a header, and a header is
// trivially forged by anything that can reach the core directly. An
// application-layer signature is verified by the process that acts on the
// request, so it survives every proxy, ingress, and service mesh between the
// agent and the core.
//
// TLS is still expected on the wire. This authenticates; it does not encrypt.
//
// # What this does and does not prevent
//
// The signature covers the method, the path, the timestamp, and a hash of the
// body, so none of those can be altered in flight and a signature captured from
// one request cannot be reused on another.
//
// It does **not** prevent an identical request being replayed inside the
// tolerance window. That is a deliberate omission rather than an oversight: a
// nonce would have to be checked against something shared by every replica, and
// a nonce checked in one replica's memory is decoration — it implies a property
// that does not hold across a deployment of two. Decoration in a security
// mechanism is worse than its absence, because people rely on it. The window is
// the real bound, and it is short.
package agentauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Headers an agent sets on every request.
const (
	// AgentHeader carries the agent's id, which is what selects the public key
	// the signature is checked against.
	AgentHeader = "X-CertPilot-Agent"
	// TimestampHeader carries the Unix seconds covered by the signature.
	TimestampHeader = "X-CertPilot-Timestamp"
	// SignatureHeader carries the base64 Ed25519 signature.
	SignatureHeader = "X-CertPilot-Signature"
)

// Scheme names the signing construction.
//
// Inside the signed bytes, not merely alongside them. A verifier that has to
// support two schemes at once must not be talked into checking a v2 signature
// with v1 rules by an attacker who controls a header.
const Scheme = "certpilot-agent-v1"

// DefaultTolerance is how far a request's timestamp may be from the verifier's
// clock.
//
// Wide enough to survive the clock drift of a host nobody has looked at in a
// year, which is most hosts. Narrow enough that a captured request is useless
// by the time anybody has finished capturing it.
const DefaultTolerance = 5 * time.Minute

// GenerateKey creates an agent's identity key.
//
// Ed25519 rather than RSA or ECDSA: the key is small enough to fit in a log
// line if anybody needs to compare one, signing has no per-signature randomness
// to get wrong, and there are no parameters for an operator to choose badly.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SigningString builds the exact bytes that are signed.
//
// Written out rather than hidden inside Sign, because this is a wire contract:
// anybody implementing an agent in another language has to reproduce it byte
// for byte, and a contract that exists only as the inside of a function is a
// contract nobody can read.
//
//	certpilot-agent-v1 \n
//	METHOD             \n
//	/request/path      \n
//	<unix seconds>     \n
//	<hex sha256 of the request body>
//
// The path is included so a signature for a heartbeat cannot be lifted onto a
// certificate request. The body hash is included so nothing in it can be
// altered. An empty body hashes normally rather than being skipped, so "no
// body" and "a body that happens to be empty" cannot be swapped.
func SigningString(method, path string, timestamp int64, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		Scheme,
		strings.ToUpper(method),
		path,
		strconv.FormatInt(timestamp, 10),
		hex.EncodeToString(sum[:]),
	}, "\n")
}

// Sign returns the base64 signature for one request.
func Sign(key ed25519.PrivateKey, method, path string, timestamp int64, body []byte) string {
	sig := ed25519.Sign(key, []byte(SigningString(method, path, timestamp, body)))
	return base64.StdEncoding.EncodeToString(sig)
}

// Verify checks a signature and its freshness.
//
// Returns an error naming which check failed, for the log. What goes back on
// the wire is a flat 401 either way: telling a caller whether the agent id was
// unknown, the clock was wrong, or the signature was bad is telling them how to
// get closer.
func Verify(key ed25519.PublicKey, method, path string, timestamp int64,
	signature string, body []byte, tolerance time.Duration) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("the stored public key is not an Ed25519 key")
	}

	age := time.Since(time.Unix(timestamp, 0))
	if age < 0 {
		age = -age
	}
	if tolerance > 0 && age > tolerance {
		return fmt.Errorf("timestamp is %s away from this server's clock, outside the tolerance of %s",
			age.Round(time.Second), tolerance)
	}

	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	if !ed25519.Verify(key, []byte(SigningString(method, path, timestamp, body)), raw) {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

// EncodePublicKey renders a public key as PEM.
//
// PEM rather than raw base64 so that what is stored in the database, printed by
// the agent, and shown in the API are the same inspectable thing, and so an
// operator comparing "is this the key my host generated" can do it by eye.
func EncodePublicKey(key ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ParsePublicKey reads a PEM public key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, fmt.Errorf("not a PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not Ed25519", parsed)
	}
	return key, nil
}

// EncodePrivateKey renders a private key as PKCS#8 PEM, for the agent's own
// state directory. It never crosses the network.
func EncodePrivateKey(key ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParsePrivateKey reads a PKCS#8 PEM private key.
func ParsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, fmt.Errorf("not a PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not Ed25519", parsed)
	}
	return key, nil
}

// KeyID is a short, stable fingerprint of a public key.
//
// For humans: it is what an operator compares between the line the agent
// printed on the host and the row in the API, to answer "is the thing enrolled
// under this name the machine I ran the command on". Never used to look a key
// up — the agent id does that, and a truncated hash is not an identifier.
func KeyID(key ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16]
}
