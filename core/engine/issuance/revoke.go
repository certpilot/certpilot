package issuance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	providerv1 "github.com/certpilot/certpilot-gateway-sdk/pb/provider/v1"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// Revoker has the issuing CA revoke a certificate, and records the revocation
// only once the CA has accepted it.
//
// Every path that revokes goes through here: an administrator's request in
// the console, and an ACME client's. The order is the safety property, and a
// second copy of it is a second place for it to be got wrong.
type Revoker struct {
	store   store.Store
	plugins *pluginmgr.Manager
	keyring *secrets.Keyring
}

// NewRevoker creates a revoker.
func NewRevoker(st store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring) *Revoker {
	return &Revoker{store: st, plugins: pm, keyring: kr}
}

// RevokeFailure says which way a revocation failed, which is what a caller
// needs to choose its answer.
type RevokeFailure int

const (
	// RevokeBadReason: the reason is not one CertPilot accepts.
	RevokeBadReason RevokeFailure = iota + 1
	// RevokeAlreadyRevoked: nothing to do.
	RevokeAlreadyRevoked
	// RevokeNotPossible: CertPilot has nothing to show a CA, or no CA to show
	// it to.
	RevokeNotPossible
	// RevokeCANotTold: the CA could not be reached or declined. Nothing has
	// been changed.
	RevokeCANotTold
	// RevokeInternal: CertPilot failed before asking the CA. Nothing has been
	// changed.
	RevokeInternal
	// RevokeNotRecorded: the CA revoked the certificate and the record could
	// not be updated. The estate is safe and the record is wrong.
	RevokeNotRecorded
)

// RevokeError is a revocation that did not happen, or happened and was not
// recorded, with a message written for the operator.
type RevokeError struct {
	Kind RevokeFailure
	msg  string
	err  error
}

func (e *RevokeError) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

func (e *RevokeError) Unwrap() error { return e.err }

// AsRevokeError unwraps a RevokeError.
func AsRevokeError(err error) (*RevokeError, bool) {
	var re *RevokeError
	ok := errors.As(err, &re)
	return re, ok
}

func revokeFailed(kind RevokeFailure, msg string, err error) error {
	return &RevokeError{Kind: kind, msg: msg, err: err}
}

// Revoke asks the CA that issued cert to revoke it with an RFC 5280 reason,
// then records it. actor is who asked, as revoked_by will show it.
//
// It returns the record as revoked, or a RevokeError.
func (r *Revoker) Revoke(ctx context.Context, cert *store.Certificate, reason int, actor string) (*store.Certificate, error) {
	if !store.ValidRevocationReason(reason) {
		return nil, revokeFailed(RevokeBadReason,
			fmt.Sprintf("%d is not a revocation reason CertPilot accepts", reason), nil)
	}
	if cert.Status == "REVOKED" {
		return nil, revokeFailed(RevokeAlreadyRevoked, "this certificate is already revoked", nil)
	}
	if cert.CertificatePEM == nil || *cert.CertificatePEM == "" {
		// Discovered certificates can reach here with no PEM stored. A CA
		// cannot be asked to revoke a certificate that cannot be shown to it.
		return nil, revokeFailed(RevokeNotPossible,
			"CertPilot holds no copy of this certificate, so it cannot ask a CA to revoke it. "+
				"Revoke it directly at the issuing CA", nil)
	}
	if cert.CAAccountID == nil || *cert.CAAccountID == "" {
		return nil, revokeFailed(RevokeNotPossible,
			"this certificate is not bound to a CA account, so there is nowhere to send a revocation. "+
				"It was most likely discovered rather than issued here", nil)
	}

	account, err := r.store.GetCAAccount(ctx, *cert.CAAccountID)
	if err != nil || account == nil {
		return nil, revokeFailed(RevokeCANotTold, "the CA account this certificate was issued by could not be read", err)
	}

	gw, err := r.plugins.GatewayFor(ctx, pluginmgr.Endpoint{
		Name: account.Name, Addr: account.GatewayAddr, Type: account.ProviderType, ServerName: account.ServerName,
	})
	if err != nil {
		// Deliberately not recorded as revoked. An unreachable gateway means
		// the CA has not been told, and marking it here would leave a
		// certificate that reads REVOKED in the console and answers
		// handshakes in production.
		return nil, revokeFailed(RevokeCANotTold, fmt.Sprintf(
			"gateway for CA %s is not connected, so the CA has not been told; nothing has been changed", account.Name), nil)
	}

	config, err := DecryptCAConfig(r.keyring, account)
	if err != nil {
		return nil, revokeFailed(RevokeInternal, "could not open the CA account's configuration", err)
	}

	resp, err := gw.Client.RevokeCertificate(ctx, &providerv1.RevokeCertificateRequest{
		CertificatePem:        []byte(*cert.CertificatePEM),
		ProviderCertificateId: cert.FingerprintSHA256,
		Reason:                int32(reason),
		ProviderConfig:        config,
	})
	if err != nil {
		return nil, revokeFailed(RevokeCANotTold, "the CA refused the revocation, so nothing has been changed", err)
	}
	if !resp.Success {
		return nil, revokeFailed(RevokeCANotTold,
			"the CA did not revoke this certificate, so nothing has been changed: "+resp.Message, nil)
	}

	revoked, err := r.store.MarkCertificateRevoked(ctx, cert.ID, reason, actor)
	if err != nil {
		// The CA has revoked it and CertPilot could not write that down. This
		// is the one genuinely dangerous outcome, so it is logged as such
		// whoever asked.
		slog.Error("the CA revoked a certificate but the record could not be updated",
			"error", err, "certificate_id", cert.ID, "common_name", cert.CommonName)
		return nil, revokeFailed(RevokeNotRecorded,
			"the CA has revoked this certificate, but CertPilot could not record it. "+
				"The certificate is no longer valid; this record will be wrong until the write succeeds", nil)
	}
	if revoked == nil {
		// Somebody else revoked it between the read and the write.
		return nil, revokeFailed(RevokeAlreadyRevoked, "this certificate is already revoked", nil)
	}
	return revoked, nil
}
