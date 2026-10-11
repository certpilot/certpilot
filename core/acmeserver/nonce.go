package acmeserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"context"
)

// Nonces are stateless to issue and stateful to spend.
//
// Issuing one writes nothing, so a flood of GETs to new-nonce costs the server
// a MAC and nothing else. A nonce is random bytes and an expiry, authenticated
// with a subkey of the KEK so that nobody can mint one, and it names the key
// that signed it so a rotated KEK still accepts the nonces already out.
//
// Spending one is a write: the hash goes into acme_used_nonces, and a second
// attempt to insert it fails. That is the part that has to hold across
// replicas, and a primary key is what decides it.
const (
	nonceLife    = 10 * time.Minute
	nonceRandom  = 16
	noncePurpose = "acme-nonce"
)

var errBadNonce = errors.New("the nonce was not issued by this server, has expired, or was already used")

func (s *Server) mintNonce() (string, error) {
	data := make([]byte, nonceRandom+8)
	if _, err := rand.Read(data[:nonceRandom]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(data[nonceRandom:], uint64(s.cfg.Now().Add(nonceLife).Unix()))

	keyID, tag, err := s.cfg.Keyring.MAC(noncePurpose, data)
	if err != nil {
		return "", err
	}
	id, err := hex.DecodeString(keyID)
	if err != nil {
		return "", err
	}
	raw := append(append(id, data...), tag...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// spendNonce checks a nonce and marks it used.
func (s *Server) spendNonce(ctx context.Context, nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return errBadNonce
	}
	idLen := len(s.cfg.Keyring.PrimaryKeyID()) / 2
	dataLen := nonceRandom + 8
	if len(raw) != idLen+dataLen+sha256.Size {
		return errBadNonce
	}
	keyID := hex.EncodeToString(raw[:idLen])
	data := raw[idLen : idLen+dataLen]
	tag := raw[idLen+dataLen:]

	ok, err := s.cfg.Keyring.VerifyMAC(keyID, noncePurpose, data, tag)
	if err != nil || !ok {
		return errBadNonce
	}
	expires := time.Unix(int64(binary.BigEndian.Uint64(data[nonceRandom:])), 0)
	if !expires.After(s.cfg.Now()) {
		return errBadNonce
	}

	hash := sha256.Sum256([]byte(nonce))
	first, err := s.cfg.Store.ClaimACMENonce(ctx, hash[:], expires)
	if err != nil {
		return err
	}
	if !first {
		return errBadNonce
	}
	return nil
}
