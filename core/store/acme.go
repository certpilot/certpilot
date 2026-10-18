package store

import "time"

// ACMEEABCredential is what an administrator hands to an ACME client so that
// it may register.
//
// Registration is closed: there is no open sign-up, and an account can only be
// made by presenting one of these (RFC 8555 §7.3.4, External Account Binding).
// A credential belongs to one template, so the account made with it can only
// ever ask for what that template allows.
//
// The key is sealed rather than hashed, unlike an agent enrolment token. The
// core has to recompute an HMAC over the client's account key to check the
// binding, so it needs the key itself.
type ACMEEABCredential struct {
	ID         string `json:"id"`
	KID        string `json:"kid"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
	// HMACKeySealed is the HMAC key under the keyring. Never serialised.
	HMACKeySealed string `json:"-"`

	// AccountID is the account made with this credential, once there is one.
	AccountID *string `json:"account_id,omitempty"`

	CreatedBy *string    `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy *string    `json:"revoked_by,omitempty"`
}

// ACME account states (RFC 8555 §7.1.2). Revoked is not offered: an
// administrator ends an account by revoking its credential.
const (
	ACMEAccountValid       = "valid"
	ACMEAccountDeactivated = "deactivated"
)

// ACMEAccount is one client's registration against one template.
type ACMEAccount struct {
	ID         string `json:"id"`
	TemplateID string `json:"template_id"`
	// EABID is the credential it was made with. One credential makes one
	// account, so a leaked credential cannot be used to mint more.
	EABID string `json:"eab_id"`

	// JWKThumbprint is the RFC 7638 thumbprint of the account key, which is
	// what identifies an account when its client has lost the account URL.
	JWKThumbprint string `json:"jwk_thumbprint"`
	// JWK is the account's public key as the client registered it.
	JWK string `json:"-"`

	Status    string    `json:"status"`
	Contacts  []string  `json:"contacts"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ACME order states (RFC 8555 §7.1.6). Authorisations are pre-authorised by
// the account's credential, so an order is ready the moment it exists.
const (
	ACMEOrderPending    = "pending"
	ACMEOrderReady      = "ready"
	ACMEOrderProcessing = "processing"
	ACMEOrderValid      = "valid"
	ACMEOrderInvalid    = "invalid"
)

// ACMEIdentifier is one name an order asks for.
type ACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACMEOrder is one request for a certificate from an ACME account.
type ACMEOrder struct {
	ID          string           `json:"id"`
	AccountID   string           `json:"account_id"`
	Status      string           `json:"status"`
	Identifiers []ACMEIdentifier `json:"identifiers"`
	ExpiresAt   time.Time        `json:"expires_at"`
	// CertificateID is the certificate the order produced, once valid.
	CertificateID *string `json:"certificate_id,omitempty"`
	// Error is the problem document that made the order invalid, as JSON.
	Error string `json:"error,omitempty"`
	// Replaces is the RFC 9773 certificate identifier the client said this
	// order replaces (the issuer's key identifier and the serial), and
	// ReplacesCertificateID the record that certificate was in. The record is
	// written over by each renewal; the identifier says which of its
	// certificates this order replaced.
	ReplacesCertificateID *string   `json:"replaces_certificate_id,omitempty"`
	Replaces              string    `json:"replaces,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}
