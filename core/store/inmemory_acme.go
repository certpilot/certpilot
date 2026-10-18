package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

func (m *MemoryStore) CreateACMEEABCredential(ctx context.Context, c *ACMEEABCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.acmeCredentials {
		if existing.KID == c.KID {
			return fmt.Errorf("an ACME credential with key id %q already exists", c.KID)
		}
	}
	if _, ok := m.certificateTemplates[c.TemplateID]; !ok {
		return fmt.Errorf("certificate template %s %w", c.TemplateID, ErrNotFound)
	}
	stored := clone(c)
	stored.ID = uuid.New().String()
	stored.CreatedAt = time.Now()
	m.acmeCredentials[stored.ID] = stored
	c.ID, c.CreatedAt = stored.ID, stored.CreatedAt
	return nil
}

// withAccount fills AccountID the way the PostgreSQL query does.
func (m *MemoryStore) acmeCredentialView(c *ACMEEABCredential) *ACMEEABCredential {
	out := clone(c)
	out.AccountID = nil
	for _, a := range m.acmeAccounts {
		if a.EABID == c.ID {
			id := a.ID
			out.AccountID = &id
		}
	}
	return out
}

func (m *MemoryStore) ListACMEEABCredentials(ctx context.Context) ([]*ACMEEABCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ACMEEABCredential, 0, len(m.acmeCredentials))
	for _, c := range m.acmeCredentials {
		out = append(out, m.acmeCredentialView(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetACMEEABCredentialByKID(ctx context.Context, kid string) (*ACMEEABCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.acmeCredentials {
		if c.KID == kid {
			return m.acmeCredentialView(c), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) RevokeACMEEABCredential(ctx context.Context, id string, revokedBy *string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.acmeCredentials[id]
	if !ok {
		return "", fmt.Errorf("ACME credential %s %w", id, ErrNotFound)
	}
	if c.RevokedAt == nil {
		now := time.Now()
		c.RevokedAt, c.RevokedBy = &now, revokedBy
	}
	for _, a := range m.acmeAccounts {
		if a.EABID == id && a.Status == ACMEAccountValid {
			a.Status, a.UpdatedAt = ACMEAccountDeactivated, time.Now()
			return a.ID, nil
		}
	}
	return "", nil
}

func (m *MemoryStore) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cred, ok := m.acmeCredentials[a.EABID]
	if !ok {
		return fmt.Errorf("ACME credential %s %w", a.EABID, ErrNotFound)
	}
	if cred.RevokedAt != nil {
		return fmt.Errorf("the ACME credential has been revoked: %w", ErrRevoked)
	}
	for _, existing := range m.acmeAccounts {
		if existing.EABID == a.EABID ||
			(existing.TemplateID == a.TemplateID && existing.JWKThumbprint == a.JWKThumbprint) {
			return fmt.Errorf("an ACME account already exists for this credential or key: %w", ErrConflict)
		}
	}
	stored := cloneACMEAccount(a)
	stored.ID = uuid.New().String()
	stored.Status = ACMEAccountValid
	stored.CreatedAt = time.Now()
	stored.UpdatedAt = stored.CreatedAt
	if stored.Contacts == nil {
		stored.Contacts = []string{}
	}
	m.acmeAccounts[stored.ID] = stored
	*a = *cloneACMEAccount(stored)
	return nil
}

func cloneACMEAccount(a *ACMEAccount) *ACMEAccount {
	c := *a
	c.Contacts = append([]string(nil), a.Contacts...)
	return &c
}

func (m *MemoryStore) GetACMEAccount(ctx context.Context, id string) (*ACMEAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.acmeAccounts[id]
	if !ok {
		return nil, fmt.Errorf("ACME account %s %w", id, ErrNotFound)
	}
	return cloneACMEAccount(a), nil
}

func (m *MemoryStore) GetACMEAccountByThumbprint(ctx context.Context, templateID, thumbprint string) (*ACMEAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.acmeAccounts {
		if a.TemplateID == templateID && a.JWKThumbprint == thumbprint {
			return cloneACMEAccount(a), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) GetACMEAccountByEAB(ctx context.Context, eabID string) (*ACMEAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.acmeAccounts {
		if a.EABID == eabID {
			return cloneACMEAccount(a), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) UpdateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.acmeAccounts[a.ID]
	if !ok {
		return fmt.Errorf("ACME account %s %w", a.ID, ErrNotFound)
	}
	stored.Status = a.Status
	stored.Contacts = append([]string{}, a.Contacts...)
	stored.UpdatedAt = time.Now()
	a.UpdatedAt = stored.UpdatedAt
	return nil
}

func (m *MemoryStore) UpdateACMEAccountKey(ctx context.Context, id, jwk, thumbprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.acmeAccounts[id]
	if !ok {
		return fmt.Errorf("ACME account %s %w", id, ErrNotFound)
	}
	for _, other := range m.acmeAccounts {
		if other.ID != id && other.TemplateID == stored.TemplateID && other.JWKThumbprint == thumbprint {
			return fmt.Errorf("another ACME account on this template already has that key: %w", ErrConflict)
		}
	}
	stored.JWK, stored.JWKThumbprint, stored.UpdatedAt = jwk, thumbprint, time.Now()
	return nil
}

func (m *MemoryStore) ClaimACMENonce(ctx context.Context, hash []byte, expiresAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := string(hash)
	if _, seen := m.acmeNonces[key]; seen {
		return false, nil
	}
	m.acmeNonces[key] = expiresAt
	return true, nil
}

func (m *MemoryStore) SweepACMENonces(ctx context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for key, expires := range m.acmeNonces {
		if !expires.After(now) {
			delete(m.acmeNonces, key)
			n++
		}
	}
	return n, nil
}

func cloneACMEOrder(o *ACMEOrder) *ACMEOrder {
	c := *o
	c.Identifiers = append([]ACMEIdentifier(nil), o.Identifiers...)
	if o.ReplacesCertificateID != nil {
		id := *o.ReplacesCertificateID
		c.ReplacesCertificateID = &id
	}
	return &c
}

func (m *MemoryStore) CreateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.acmeAccounts[o.AccountID]; !ok {
		return fmt.Errorf("ACME account %s %w", o.AccountID, ErrNotFound)
	}
	stored := cloneACMEOrder(o)
	stored.ID = uuid.New().String()
	stored.CreatedAt = time.Now()
	stored.UpdatedAt = stored.CreatedAt
	m.acmeOrders[stored.ID] = stored
	o.ID, o.CreatedAt, o.UpdatedAt = stored.ID, stored.CreatedAt, stored.UpdatedAt
	return nil
}

func (m *MemoryStore) GetACMEOrder(ctx context.Context, id string) (*ACMEOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.acmeOrders[id]
	if !ok {
		return nil, fmt.Errorf("ACME order %s %w", id, ErrNotFound)
	}
	return cloneACMEOrder(o), nil
}

func (m *MemoryStore) GetACMEOrderByCertificate(ctx context.Context, certificateID string) (*ACMEOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, o := range m.acmeOrders {
		if o.CertificateID != nil && *o.CertificateID == certificateID {
			return cloneACMEOrder(o), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) GetACMEOrderReplacing(ctx context.Context, certID string) (*ACMEOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var newest *ACMEOrder
	for _, o := range m.acmeOrders {
		if o.Replaces != certID || certID == "" ||
			(o.Status != ACMEOrderValid && o.Status != ACMEOrderProcessing) {
			continue
		}
		if newest == nil || o.CreatedAt.After(newest.CreatedAt) {
			newest = o
		}
	}
	if newest == nil {
		return nil, nil
	}
	return cloneACMEOrder(newest), nil
}

func (m *MemoryStore) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]*ACMEOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []*ACMEOrder{}
	for _, o := range m.acmeOrders {
		if o.AccountID == accountID {
			out = append(out, cloneACMEOrder(o))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) ClaimACMEOrderForFinalize(ctx context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.acmeOrders[id]
	if !ok || o.Status != ACMEOrderReady || !o.ExpiresAt.After(time.Now()) {
		return false, nil
	}
	o.Status = ACMEOrderProcessing
	o.UpdatedAt = time.Now()
	return true, nil
}

func (m *MemoryStore) UpdateACMEOrder(ctx context.Context, o *ACMEOrder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.acmeOrders[o.ID]
	if !ok {
		return fmt.Errorf("ACME order %s %w", o.ID, ErrNotFound)
	}
	stored.Status, stored.CertificateID, stored.Error = o.Status, o.CertificateID, o.Error
	stored.UpdatedAt = time.Now()
	o.UpdatedAt = stored.UpdatedAt
	return nil
}
