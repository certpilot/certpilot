package renewal

import (
	"context"
	"errors"
	"fmt"

	"github.com/certpilot/certpilot/core/store"
)

// ErrKeyHeldElsewhere is why a certificate cannot be renewed by CertPilot: its
// private key is somewhere CertPilot is not.
//
// RenewCertificateRequest carries no CSR, so a renewal here always ends with the
// gateway generating a fresh keypair and the core sealing it. For a certificate
// whose key is on a host or behind a caller's signing request, that is two
// failures at once. CertPilot holds a key it promised never to hold, for a
// record whose key_custody goes on saying otherwise; and the record stops
// describing the certificate the key holder is actually serving, which nothing
// reconciles, because the host correctly decides it already has what it asked
// for (#107).
var ErrKeyHeldElsewhere = errors.New("CertPilot does not hold this certificate's private key")

// KeyHeldElsewhere returns nil when CertPilot may renew cert, and otherwise an
// error wrapping ErrKeyHeldElsewhere that says who renews it instead.
//
// Checked in three places, so that no path can commit the key: the API refuses
// before anything is queued, the queue cancels a job that got in some other way,
// and the executor refuses whatever reaches it regardless.
func KeyHeldElsewhere(ctx context.Context, st store.Store, cert *store.Certificate) error {
	switch cert.KeyCustody {
	case store.KeyCustodyAgent:
		return fmt.Errorf("%w: %s was issued to agent %s, which generated the key on its host. "+
			"Renewing here would issue against a new key that host does not have. "+
			"The agent renews it itself when renew_after arrives; to renew it now, run "+
			"`certpilot-agent request --name %s` on that host",
			ErrKeyHeldElsewhere, describeName(cert), holderName(ctx, st, cert), requestName(cert))
	case store.KeyCustodyExternal:
		return fmt.Errorf("%w: %s was issued from a signing request, and whoever holds its key renews it. "+
			"Renewing here would issue against a new key that certificate's server does not use. "+
			"Submit a new signing request from the key holder instead",
			ErrKeyHeldElsewhere, describeName(cert))
	}
	return nil
}

// holderName names the agent the way the console does, so the operator can
// find the host. An agent that cannot be read still has an ID worth printing;
// failing the refusal over a lookup would be worse than a less friendly name.
func holderName(ctx context.Context, st store.Store, cert *store.Certificate) string {
	if cert.KeyHolderAgentID == nil || *cert.KeyHolderAgentID == "" {
		return "(no agent recorded)"
	}
	agent, err := st.GetAgent(ctx, *cert.KeyHolderAgentID)
	if err != nil || agent == nil || agent.Name == "" {
		return *cert.KeyHolderAgentID
	}
	return fmt.Sprintf("%q (%s)", agent.Name, agent.ID)
}

// describeName is the certificate as a person would recognise it. A SAN-only
// certificate has no common name, and "certificate " followed by nothing is
// what #108 already showed a reader once.
func describeName(cert *store.Certificate) string {
	if name := requestName(cert); name != "" {
		return "certificate " + name
	}
	return "certificate " + cert.ID
}

// requestName is the name the agent was asked for, which is what it needs to be
// asked for again.
func requestName(cert *store.Certificate) string {
	if cert.CommonName != "" {
		return cert.CommonName
	}
	if len(cert.SANs) > 0 {
		return cert.SANs[0]
	}
	return ""
}
