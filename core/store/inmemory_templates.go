package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// cloneTemplate deep-copies, where clone() shallow-copies.
//
// A template is mostly slices and maps. A shallow copy hands every caller a
// reference to the same backing array, so a handler that appends one allowed
// key type to what it read would edit the stored record without writing it —
// and against PostgreSQL it would not. The conformance test exists to catch
// exactly that kind of divergence, so the in-memory store should not create it.
func cloneTemplate(t *CertificateTemplate) *CertificateTemplate {
	c := *t

	c.SubjectDefaults = make(map[string]string, len(t.SubjectDefaults))
	for k, v := range t.SubjectDefaults {
		c.SubjectDefaults[k] = v
	}

	c.CommonNameRule.Suffixes = append([]string(nil), t.CommonNameRule.Suffixes...)
	c.CommonNameRule.ForbiddenPatterns = append([]string(nil), t.CommonNameRule.ForbiddenPatterns...)
	if t.CommonNameRule.Required != nil {
		required := *t.CommonNameRule.Required
		c.CommonNameRule.Required = &required
	}

	c.SANRules.Types = append([]string(nil), t.SANRules.Types...)
	c.SANRules.Suffixes = append([]string(nil), t.SANRules.Suffixes...)
	if t.SANRules.AllowWildcards != nil {
		allow := *t.SANRules.AllowWildcards
		c.SANRules.AllowWildcards = &allow
	}

	c.AllowedKeyTypes = append([]string{}, t.AllowedKeyTypes...)
	c.ECDSACurves = append([]string{}, t.ECDSACurves...)
	c.RequireMetadata = append([]string{}, t.RequireMetadata...)
	c.DefaultTags = append([]string{}, t.DefaultTags...)
	c.KeyUsage = append([]string{}, t.KeyUsage...)
	c.ExtendedKeyUsage = append([]string{}, t.ExtendedKeyUsage...)
	c.PassthroughOIDs = append([]string{}, t.PassthroughOIDs...)

	return &c
}

func (m *MemoryStore) ListCertificateTemplates(ctx context.Context) ([]*CertificateTemplate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*CertificateTemplate, 0, len(m.certificateTemplates))
	for _, t := range m.certificateTemplates {
		list = append(list, cloneTemplate(t))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetCertificateTemplate(ctx context.Context, id string) (*CertificateTemplate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.certificateTemplates[id]
	if !ok {
		return nil, fmt.Errorf("certificate template %s not found", id)
	}
	return cloneTemplate(t), nil
}

func (m *MemoryStore) GetCertificateTemplateBySlug(ctx context.Context, slug string) (*CertificateTemplate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.certificateTemplates {
		if t.Slug == slug {
			return cloneTemplate(t), nil
		}
	}
	return nil, fmt.Errorf("certificate template %q not found", slug)
}

func (m *MemoryStore) CreateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// The unique index PostgreSQL carries. Without it here the two stores
	// disagree about whether two templates may answer to the same name, which
	// is the kind of difference that only shows up in production.
	for _, existing := range m.certificateTemplates {
		if existing.Slug == t.Slug && existing.ID != t.ID {
			return fmt.Errorf("a certificate template with slug %q already exists", t.Slug)
		}
	}

	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.Version = orOne(t.Version)
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()
	normaliseTemplate(t)
	m.certificateTemplates[t.ID] = cloneTemplate(t)
	return nil
}

func (m *MemoryStore) UpdateCertificateTemplate(ctx context.Context, t *CertificateTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certificateTemplates[t.ID]; !ok {
		return fmt.Errorf("certificate template %s not found", t.ID)
	}
	for _, existing := range m.certificateTemplates {
		if existing.Slug == t.Slug && existing.ID != t.ID {
			return fmt.Errorf("a certificate template with slug %q already exists", t.Slug)
		}
	}
	t.Version = orOne(t.Version)
	t.UpdatedAt = time.Now()
	normaliseTemplate(t)
	m.certificateTemplates[t.ID] = cloneTemplate(t)
	return nil
}

func (m *MemoryStore) DeleteCertificateTemplate(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.certificateTemplates[id]; !ok {
		return fmt.Errorf("certificate template %s not found", id)
	}
	delete(m.certificateTemplates, id)
	return nil
}
