// Package rekey answers what still depends on each key encryption key, and
// moves what a retired key sealed onto the primary one.
//
// Rotating the key only changes what seals new data. Until everything the old
// key sealed has been re-sealed, the old key cannot be dropped, and after a
// suspected compromise everything it sealed stays exposed. Survey says how much
// that is; Reseal brings it to nothing.
package rekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

// How a key stands with the keyring this core was given.
const (
	StatusPrimary = "primary"
	StatusRetired = "retired"
	// StatusMissing is a key the database names and this core does not hold.
	// What it sealed cannot be read here, and what it signed cannot be checked.
	StatusMissing = "missing"
)

// pageSize bounds one read. A sealed private key is a few kilobytes. A
// variable so a test can page through a handful of records.
var pageSize = 200

// KeyUsage is what depends on one key.
type KeyUsage struct {
	KeyID  string `json:"key_id"`
	Status string `json:"status"`
	// Sealed counts the records this key seals, by kind.
	Sealed      map[string]int64 `json:"sealed"`
	SealedTotal int64            `json:"sealed_total"`
	// Audit is the part of the audit chain this key signed, which can only be
	// checked while the core holds it. Nil when it signed nothing.
	Audit *store.AuditKeyUsage `json:"audit,omitempty"`
}

// Report is what depends on every key the database names or the core holds.
type Report struct {
	PrimaryKeyID string `json:"primary_key_id"`
	// Keys lists the primary first, then retired keys, then missing ones.
	Keys []KeyUsage `json:"keys"`
	// NotSealed counts stored values that are not envelopes, by kind: rows
	// written before sealing existed. No key protects them.
	NotSealed map[string]int64 `json:"not_sealed,omitempty"`
}

// Survey reads every sealed value's header and the audit chain's key ids. It
// opens nothing, so it works for keys this core does not hold.
func Survey(ctx context.Context, st store.Store, kr *secrets.Keyring) (*Report, error) {
	if kr == nil {
		return nil, secrets.ErrNoKey
	}
	report := &Report{PrimaryKeyID: kr.PrimaryKeyID(), NotSealed: map[string]int64{}}
	usage := map[string]*KeyUsage{}
	get := func(id string) *KeyUsage {
		u, ok := usage[id]
		if !ok {
			u = &KeyUsage{KeyID: id, Status: StatusMissing, Sealed: map[string]int64{}}
			usage[id] = u
		}
		return u
	}
	for i, id := range kr.KeyIDs() {
		get(id).Status = StatusRetired
		if i == 0 {
			get(id).Status = StatusPrimary
		}
	}

	for _, kind := range store.SealedKinds {
		err := eachSealed(ctx, st, kind.Name, func(v store.SealedValue) error {
			id, ok := secrets.EnvelopeKeyID(v.Value)
			if !ok {
				report.NotSealed[kind.Name]++
				return nil
			}
			u := get(id)
			u.Sealed[kind.Name]++
			u.SealedTotal++
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	audit, err := st.AuditKeyUsage(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading which keys signed the audit log: %w", err)
	}
	for i := range audit {
		get(audit[i].KeyID).Audit = &audit[i]
	}

	for _, u := range usage {
		report.Keys = append(report.Keys, *u)
	}
	rank := map[string]int{StatusPrimary: 0, StatusRetired: 1, StatusMissing: 2}
	sort.Slice(report.Keys, func(i, j int) bool {
		a, b := report.Keys[i], report.Keys[j]
		if rank[a.Status] != rank[b.Status] {
			return rank[a.Status] < rank[b.Status]
		}
		return a.KeyID < b.KeyID
	})
	return report, nil
}

// Result is what one re-seal did.
type Result struct {
	// Resealed counts records moved onto the primary key, in all and by kind.
	Resealed int64            `json:"resealed"`
	ByKind   map[string]int64 `json:"by_kind,omitempty"`
	// Unreadable counts records another key seals that could not be opened:
	// the key is not in the keyring, or the value does not open with it.
	Unreadable int64 `json:"unreadable"`
	// ChangedMeanwhile counts records the core rewrote between the read and
	// the write. They were left as the core wrote them.
	ChangedMeanwhile int64 `json:"changed_meanwhile"`
	// Remaining counts records still not sealed by the primary key when the
	// re-seal finished. A retired key can be dropped only when this is zero.
	Remaining int64 `json:"remaining"`
}

// Reseal moves every record a retired key seals onto the primary key.
//
// It is safe beside a running core and safe to interrupt. Each record is
// replaced in one conditional write, only if it still holds what was read, so
// a reader sees the old envelope or the new one and both open: the keyring
// still holds the retired key. Run again, it does only what is left.
func Reseal(ctx context.Context, st store.Store, kr *secrets.Keyring) (*Result, error) {
	if kr == nil {
		return nil, secrets.ErrNoKey
	}
	result := &Result{ByKind: map[string]int64{}}
	primary := kr.PrimaryKeyID()

	for _, kind := range store.SealedKinds {
		err := eachSealed(ctx, st, kind.Name, func(v store.SealedValue) error {
			id, ok := secrets.EnvelopeKeyID(v.Value)
			if !ok || id == primary {
				return nil
			}
			next, _, err := kr.Reseal(v.Value, kind.Context)
			if err != nil {
				if errors.Is(err, secrets.ErrNoKey) {
					return err
				}
				result.Unreadable++
				slog.Warn("a sealed record could not be opened and was left as it is",
					"kind", kind.Name, "id", v.ID, "sealed_by", id, "error", err)
				return nil
			}
			swapped, err := st.SwapSealed(ctx, kind.Name, v.ID, v.Value, next)
			if err != nil {
				return fmt.Errorf("re-sealing %s %s: %w", kind.Name, v.ID, err)
			}
			if !swapped {
				result.ChangedMeanwhile++
				return nil
			}
			result.Resealed++
			result.ByKind[kind.Name]++
			return nil
		})
		if err != nil {
			return result, err
		}
	}

	// Counted afresh, not derived: a record the core rewrote meanwhile may or
	// may not be under the primary key now, and only reading it says which.
	report, err := Survey(ctx, st, kr)
	if err != nil {
		return result, err
	}
	for _, k := range report.Keys {
		if k.Status != StatusPrimary {
			result.Remaining += k.SealedTotal
		}
	}

	if result.Resealed > 0 {
		details, _ := json.Marshal(map[string]any{
			"key_id":            primary,
			"resealed":          result.Resealed,
			"by_kind":           result.ByKind,
			"unreadable":        result.Unreadable,
			"changed_meanwhile": result.ChangedMeanwhile,
			"remaining":         result.Remaining,
		})
		if err := st.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "secrets.resealed",
			EntityType: "secrets",
			Details:    string(details),
		}); err != nil {
			return result, fmt.Errorf("recording the re-seal in the audit log: %w", err)
		}
	}
	return result, nil
}

// eachSealed calls fn for every sealed value of one kind, a page at a time.
func eachSealed(ctx context.Context, st store.Store, kind string, fn func(store.SealedValue) error) error {
	after := ""
	for {
		page, err := st.ListSealed(ctx, kind, after, pageSize)
		if err != nil {
			return fmt.Errorf("listing sealed %s records: %w", kind, err)
		}
		for _, v := range page {
			if err := fn(v); err != nil {
				return err
			}
			after = v.ID
		}
		if len(page) < pageSize {
			return nil
		}
	}
}
