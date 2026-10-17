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

func (m *MemoryStore) RevokeACMEEABCredential(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.acmeCredentials[id]
	if !ok {
		return fmt.Errorf("ACME credential %s %w", id, ErrNotFound)
	}
	if c.RevokedAt == nil {
		now := time.Now()
		c.RevokedAt, c.RevokedBy = &now, revokedBy
	}
	return nil
}

func (m *MemoryStore) CreateACMEAccount(ctx context.Context, a *ACMEAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
