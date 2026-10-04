// Package secrets provides authenticated envelope encryption for data that
// CertPilot stores at rest — CA account credentials and certificate private keys.
//
// Every value is sealed under a freshly generated 256-bit data encryption key
// (DEK), and that DEK is itself wrapped by a long-lived key encryption key (KEK).
// Only the KEK needs external custody (an env var today, a KMS or HSM later);
// rotating it never requires re-encrypting every row at once, because the
// keyring can unwrap with retired KEKs while sealing new writes under the
// current one.
//
// Ciphertexts are bound to a caller-supplied context string via AES-GCM
// additional authenticated data. A blob sealed as "ca_account:config" will not
// decrypt as "certificate:private_key", so a database-level mixup or a
// deliberate field swap fails closed instead of silently succeeding.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Context strings identify which field a ciphertext belongs to. They are bound
// into the ciphertext as additional authenticated data.
const (
	ContextCAAccountConfig       = "ca_account:config"
	ContextCertificatePrivKey    = "certificate:private_key"
	ContextDeploymentConfig      = "deployment_target:config"
	ContextNotificationConfig    = "notification_channel:config"
	ContextCloudConnectionConfig = "cloud_connection:config"
	ContextACMEAccountKey        = "ca_account:acme_account_key"
)

const (
	// KEKSize is the required key encryption key length in bytes (AES-256).
	KEKSize = 32
	// dekSize is the per-record data encryption key length in bytes (AES-256).
	dekSize = 32
	// keyIDSize is how many bytes of the KEK digest identify it in an envelope.
	keyIDSize = 8
	// wrappedDEKSize is dekSize plus the 16-byte GCM authentication tag.
	wrappedDEKSize = dekSize + 16

	magic       = "CPS1"
	magicSize   = 4
	gcmNonceLen = 12
)

// envelopeOverhead is the fixed byte cost of an envelope before ciphertext.
const envelopeOverhead = magicSize + keyIDSize + gcmNonceLen + wrappedDEKSize + gcmNonceLen

var (
	// ErrNoKey reports that no KEK is configured.
	ErrNoKey = errors.New("secrets: no key encryption key configured")
	// ErrUnknownKey reports a ciphertext sealed under a KEK the keyring lacks.
	ErrUnknownKey = errors.New("secrets: ciphertext was sealed with an unknown key encryption key")
	// ErrMalformed reports a ciphertext that is not a well-formed envelope.
	ErrMalformed = errors.New("secrets: malformed ciphertext envelope")
	// ErrWrongContext reports authentication failure, usually a context mismatch.
	ErrWrongContext = errors.New("secrets: decryption failed (wrong key, wrong context, or tampered ciphertext)")
)

// Keyring seals values under a primary KEK and unwraps values sealed under the
// primary or any retired KEK. It is safe for concurrent use.
type Keyring struct {
	primaryID [keyIDSize]byte
	keks      map[[keyIDSize]byte][]byte
}

// NewKeyring builds a keyring. The primary KEK seals all new writes; retired
// KEKs are accepted for decryption only, which is what makes rotation
// incremental rather than a flag-day migration.
func NewKeyring(primary []byte, retired ...[]byte) (*Keyring, error) {
	if len(primary) != KEKSize {
		return nil, fmt.Errorf("secrets: primary key must be %d bytes, got %d", KEKSize, len(primary))
	}

	kr := &Keyring{keks: make(map[[keyIDSize]byte][]byte, 1+len(retired))}
	kr.primaryID = keyID(primary)
	kr.keks[kr.primaryID] = append([]byte(nil), primary...)

	for i, k := range retired {
		if len(k) != KEKSize {
			return nil, fmt.Errorf("secrets: retired key %d must be %d bytes, got %d", i, KEKSize, len(k))
		}
		kr.keks[keyID(k)] = append([]byte(nil), k...)
	}

	return kr, nil
}

// LoadKeyring reads CERTPILOT_KEK (required) and CERTPILOT_KEK_RETIRED (an
// optional comma-separated list), both base64-encoded 32-byte keys.
//
// Kept as the environment provider spelled out, because it is the default and
// because every existing deployment calls it. Anything wanting a key from
// somewhere else goes through LoadKeyringFrom.
func LoadKeyring() (*Keyring, error) {
	return LoadKeyringFrom(context.Background(), EnvProvider{})
}

// NewEphemeralKeyring generates a keyring backed by a random KEK that exists
// only for the life of the process. It is meant for tests and for the
// in-memory store, where nothing outlives the process anyway. Never use it
// against a real database: every stored ciphertext becomes unreadable on
// restart.
func NewEphemeralKeyring() (*Keyring, error) {
	kek := make([]byte, KEKSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("secrets: failed to generate ephemeral key: %w", err)
	}
	return NewKeyring(kek)
}

// GenerateKEK returns a new base64-encoded 32-byte key, suitable for
// CERTPILOT_KEK.
func GenerateKEK() (string, error) {
	kek := make([]byte, KEKSize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return "", fmt.Errorf("secrets: failed to generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(kek), nil
}

// PrimaryKeyID returns a short hex identifier for the sealing key, for logs and
// diagnostics. It reveals nothing about the key itself.
func (kr *Keyring) PrimaryKeyID() string {
	return fmt.Sprintf("%x", kr.primaryID)
}

// Encrypt seals plaintext under a fresh DEK and returns a base64 envelope.
// The context string is authenticated but not encrypted, and must be supplied
// identically to Decrypt.
func (kr *Keyring) Encrypt(plaintext []byte, context string) (string, error) {
	if kr == nil {
		return "", ErrNoKey
	}

	kek := kr.keks[kr.primaryID]

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("secrets: failed to generate data key: %w", err)
	}
	defer zero(dek)

	// Seal the payload under the DEK.
	dekGCM, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	dekNonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return "", fmt.Errorf("secrets: failed to generate nonce: %w", err)
	}
	ciphertext := dekGCM.Seal(nil, dekNonce, plaintext, []byte(context))

	// Wrap the DEK under the KEK, binding the same context.
	kekGCM, err := newGCM(kek)
	if err != nil {
		return "", err
	}
	kekNonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, kekNonce); err != nil {
		return "", fmt.Errorf("secrets: failed to generate nonce: %w", err)
	}
	wrappedDEK := kekGCM.Seal(nil, kekNonce, dek, []byte(context))

	buf := make([]byte, 0, envelopeOverhead+len(ciphertext))
	buf = append(buf, magic...)
	buf = append(buf, kr.primaryID[:]...)
	buf = append(buf, kekNonce...)
	buf = append(buf, wrappedDEK...)
	buf = append(buf, dekNonce...)
	buf = append(buf, ciphertext...)

	return base64.StdEncoding.EncodeToString(buf), nil
}

// EncryptString is Encrypt for string payloads.
func (kr *Keyring) EncryptString(plaintext, context string) (string, error) {
	return kr.Encrypt([]byte(plaintext), context)
}

// Decrypt opens an envelope produced by Encrypt under the same context.
func (kr *Keyring) Decrypt(envelope, context string) ([]byte, error) {
	if kr == nil {
		return nil, ErrNoKey
	}

	buf, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return nil, ErrMalformed
	}
	if len(buf) < envelopeOverhead {
		return nil, ErrMalformed
	}
	if subtle.ConstantTimeCompare(buf[:magicSize], []byte(magic)) != 1 {
		return nil, ErrMalformed
	}

	off := magicSize
	var id [keyIDSize]byte
	copy(id[:], buf[off:off+keyIDSize])
	off += keyIDSize

	kek, ok := kr.keks[id]
	if !ok {
		return nil, ErrUnknownKey
	}

	kekNonce := buf[off : off+gcmNonceLen]
	off += gcmNonceLen
	wrappedDEK := buf[off : off+wrappedDEKSize]
	off += wrappedDEKSize
	dekNonce := buf[off : off+gcmNonceLen]
	off += gcmNonceLen
	ciphertext := buf[off:]

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, kekNonce, wrappedDEK, []byte(context))
	if err != nil {
		return nil, ErrWrongContext
	}
	defer zero(dek)

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, dekNonce, ciphertext, []byte(context))
	if err != nil {
		return nil, ErrWrongContext
	}

	return plaintext, nil
}

// DecryptString is Decrypt for string payloads.
func (kr *Keyring) DecryptString(envelope, context string) (string, error) {
	b, err := kr.Decrypt(envelope, context)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NeedsRotation reports whether a ciphertext was sealed under a retired KEK and
// should be re-encrypted under the primary one.
func (kr *Keyring) NeedsRotation(envelope string) bool {
	buf, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil || len(buf) < magicSize+keyIDSize {
		return false
	}
	if subtle.ConstantTimeCompare(buf[:magicSize], []byte(magic)) != 1 {
		return false
	}
	var id [keyIDSize]byte
	copy(id[:], buf[magicSize:magicSize+keyIDSize])
	return id != kr.primaryID
}

// IsEnvelope reports whether a stored value is already sealed. It lets callers
// migrate rows written before encryption existed without a separate flag column.
func IsEnvelope(value string) bool {
	if value == "" {
		return false
	}
	buf, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(buf) < envelopeOverhead {
		return false
	}
	return subtle.ConstantTimeCompare(buf[:magicSize], []byte(magic)) == 1
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to initialize cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: failed to initialize GCM: %w", err)
	}
	return gcm, nil
}

func keyID(kek []byte) [keyIDSize]byte {
	// Domain-separated so the identifier can never collide with a hash of the
	// key used for any other purpose.
	sum := sha256.Sum256(append([]byte("certpilot/kek-id\x00"), kek...))
	var id [keyIDSize]byte
	copy(id[:], sum[:keyIDSize])
	return id
}

func decodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Accept raw URL-safe base64 too, since operators paste from many places.
		key, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("not valid base64")
		}
	}
	if len(key) != KEKSize {
		return nil, fmt.Errorf("must decode to %d bytes, got %d", KEKSize, len(key))
	}
	return key, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ── Keyed authentication ────────────────────────────────

// PurposeAuditChain domain-separates the audit log's chain key. A purpose
// string is bound into the subkey derivation, so a tag computed for one
// purpose can never be replayed as a valid tag for another.
const PurposeAuditChain = "audit-chain"

// MACSize is the length in bytes of a tag returned by MAC.
const MACSize = sha256.Size

// MAC authenticates data under a subkey derived from the primary KEK and
// returns the tag alongside the identifier of the key that produced it.
//
// The identifier is what makes rotation survivable. A tag computed today and
// checked after a KEK rotation is still verifiable, because VerifyMAC looks the
// original key up in the keyring by that identifier — exactly as Decrypt does
// for an envelope. Without it, rotating the KEK would invalidate every audit
// chain link ever written, which is a strong reason never to rotate.
//
// The KEK itself never leaves the keyring: callers get a tag, not key material.
// That boundary is the whole point for the audit log — the key lives in the
// core's environment and not in the database, so somebody holding a database
// dump can rewrite a row but cannot produce a tag that agrees with it.
func (kr *Keyring) MAC(purpose string, data []byte) (keyIDHex string, tag []byte, err error) {
	if kr == nil {
		return "", nil, ErrNoKey
	}
	kek, ok := kr.keks[kr.primaryID]
	if !ok {
		return "", nil, ErrNoKey
	}
	return kr.PrimaryKeyID(), mac(kek, purpose, data), nil
}

// VerifyMAC recomputes the tag with the KEK named by keyIDHex and compares in
// constant time.
//
// An unknown identifier returns ErrUnknownKey rather than false. The two mean
// different things to an operator reading the result: a mismatch says the
// record was altered, while an unknown key says this core cannot answer the
// question because the KEK that wrote the record was never given to it.
func (kr *Keyring) VerifyMAC(keyIDHex, purpose string, data, tag []byte) (bool, error) {
	if kr == nil {
		return false, ErrNoKey
	}

	raw, err := hex.DecodeString(keyIDHex)
	if err != nil || len(raw) != keyIDSize {
		return false, ErrUnknownKey
	}
	var id [keyIDSize]byte
	copy(id[:], raw)

	kek, ok := kr.keks[id]
	if !ok {
		return false, ErrUnknownKey
	}
	return subtle.ConstantTimeCompare(mac(kek, purpose, data), tag) == 1, nil
}

// mac derives a purpose-specific subkey from the KEK and authenticates data
// under it.
//
// Two layers of HMAC rather than one: the KEK is also the wrapping key for
// every stored secret, and using it directly as a MAC key would mean one key
// serving two cryptographic roles. The derivation keeps them separate, so a
// weakness in one construction cannot be carried into the other.
func mac(kek []byte, purpose string, data []byte) []byte {
	derive := hmac.New(sha256.New, kek)
	derive.Write([]byte("certpilot/subkey\x00"))
	derive.Write([]byte(purpose))
	subkey := derive.Sum(nil)
	defer zero(subkey)

	h := hmac.New(sha256.New, subkey)
	h.Write(data)
	return h.Sum(nil)
}

// Knows reports whether the keyring holds the key named by keyIDHex, as primary
// or retired.
//
// Every envelope and audit tag names the key that wrote it, so this is how the
// core can tell, before writing anything, that a database was sealed with a
// key it was not given.
func (kr *Keyring) Knows(keyIDHex string) bool {
	if kr == nil {
		return false
	}
	raw, err := hex.DecodeString(keyIDHex)
	if err != nil || len(raw) != keyIDSize {
		return false
	}
	var id [keyIDSize]byte
	copy(id[:], raw)
	_, ok := kr.keks[id]
	return ok
}

// KeyIDs lists the identifiers of every key the keyring holds: the primary
// first, then the retired ones in a stable order. For messages that have to
// say which keys were tried.
func (kr *Keyring) KeyIDs() []string {
	if kr == nil {
		return nil
	}
	var retired []string
	for id := range kr.keks {
		if id != kr.primaryID {
			retired = append(retired, fmt.Sprintf("%x", id))
		}
	}
	sort.Strings(retired)
	return append([]string{kr.PrimaryKeyID()}, retired...)
}
