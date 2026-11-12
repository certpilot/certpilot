package rekey

import (
	"context"
	"fmt"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
)

type keys struct {
	old, both, onlyNew *secrets.Keyring
}

func rotatedKeys(t *testing.T) keys {
	t.Helper()
	oldKey, newKey := make([]byte, secrets.KEKSize), make([]byte, secrets.KEKSize)
	for i := range oldKey {
		oldKey[i], newKey[i] = byte(i), byte(255-i)
	}
	var k keys
	var err error
	if k.old, err = secrets.NewKeyring(oldKey); err != nil {
		t.Fatal(err)
	}
	if k.both, err = secrets.NewKeyring(newKey, oldKey); err != nil {
		t.Fatal(err)
	}
	if k.onlyNew, err = secrets.NewKeyring(newKey); err != nil {
		t.Fatal(err)
	}
	return k
}

// estate writes one record of every sealed kind under kr, and returns the
// plaintext each holds, by kind.
func estate(t *testing.T, st store.Store, kr *secrets.Keyring, label string) map[string]string {
	t.Helper()
	ctx := context.Background()
	plain := map[string]string{}
	seal := func(kind string) string {
		k := kindNamed(t, kind)
		plain[kind] = label + " secret of " + kind
		sealed, err := kr.EncryptString(plain[kind], k.Context)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}

	acc := &store.CAAccount{Name: label + "-ca", ProviderType: "selfsigned", GatewayAddr: "127.0.0.1:9443",
		ConfigEncrypted: seal(store.SealedCAAccount), Status: "CONNECTED"}
	must(t, st.CreateCAAccount(ctx, acc))

	key := seal(store.SealedCertificate)
	must(t, st.CreateCertificate(ctx, &store.Certificate{CommonName: label + ".example.com", Status: "ISSUED",
		FingerprintSHA256: label + "-fp", SerialNumber: label, DiscoveredVia: "MANUAL",
		KeyCustody: store.KeyCustodyCertPilot, PrivateKeyEncrypted: &key}))

	must(t, st.CreateDeploymentTarget(ctx, &store.DeploymentTarget{Name: label + "-target", TargetType: "webhook",
		IsEnabled: true, ConfigEncrypted: seal(store.SealedDeploymentTarget)}))
	must(t, st.CreateNotificationChannel(ctx, &store.NotificationChannel{Name: label + "-channel", ChannelType: "webhook",
		IsEnabled: true, SeverityThreshold: "WARNING", ConfigEncrypted: seal(store.SealedNotificationChannel)}))
	must(t, st.CreateCloudConnection(ctx, &store.CloudConnection{Name: label + "-conn", Provider: store.CloudProviderAWSACM,
		IsEnabled: true, SyncIntervalMinutes: 360, ConfigEncrypted: seal(store.SealedCloudConnection)}))

	tpl := &store.CertificateTemplate{Slug: label + "-tpl", Name: label + "-tpl", CAAccountID: acc.ID}
	must(t, st.CreateCertificateTemplate(ctx, tpl))
	must(t, st.CreateACMEEABCredential(ctx, &store.ACMEEABCredential{KID: label + "-kid", Name: label,
		TemplateID: tpl.ID, HMACKeySealed: seal(store.SealedACMECredential)}))
	return plain
}

func kindNamed(t *testing.T, name string) store.SealedKind {
	t.Helper()
	for _, k := range store.SealedKinds {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("no sealed kind %q", name)
	return store.SealedKind{}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func usageOf(t *testing.T, r *Report, keyID string) KeyUsage {
	t.Helper()
	for _, k := range r.Keys {
		if k.KeyID == keyID {
			return k
		}
	}
	t.Fatalf("the report does not mention key %s: %+v", keyID, r.Keys)
	return KeyUsage{}
}

// What an operator needs before dropping a key: what it still seals, by kind,
// and which audit entries it signed.
func TestTheReportCountsWhatDependsOnEachKey(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()

	st.UseAuditChain(store.NewAuditChainer(k.old))
	estate(t, st, k.old, "before")
	must(t, st.CreateAuditLog(ctx, &store.AuditLog{Action: "a", EntityType: "t"}))
	must(t, st.CreateAuditLog(ctx, &store.AuditLog{Action: "b", EntityType: "t"}))
	st.UseAuditChain(store.NewAuditChainer(k.both))
	estate(t, st, k.both, "after")
	must(t, st.CreateAuditLog(ctx, &store.AuditLog{Action: "c", EntityType: "t"}))

	report, err := Survey(ctx, st, k.both)
	must(t, err)

	if report.PrimaryKeyID != k.both.PrimaryKeyID() {
		t.Errorf("primary = %s", report.PrimaryKeyID)
	}
	primary, retired := usageOf(t, report, k.both.PrimaryKeyID()), usageOf(t, report, k.old.PrimaryKeyID())
	if primary.Status != StatusPrimary || retired.Status != StatusRetired {
		t.Errorf("statuses: primary=%s retired=%s", primary.Status, retired.Status)
	}
	if report.Keys[0].KeyID != k.both.PrimaryKeyID() {
		t.Error("the primary key is not listed first")
	}
	for _, kind := range store.SealedKinds {
		if primary.Sealed[kind.Name] != 1 || retired.Sealed[kind.Name] != 1 {
			t.Errorf("%s: primary seals %d and retired seals %d, want 1 and 1",
				kind.Name, primary.Sealed[kind.Name], retired.Sealed[kind.Name])
		}
	}
	if primary.SealedTotal != 6 || retired.SealedTotal != 6 {
		t.Errorf("totals: primary=%d retired=%d, want 6 and 6", primary.SealedTotal, retired.SealedTotal)
	}
	if retired.Audit == nil || retired.Audit.Entries != 2 || retired.Audit.FirstSeq != 1 || retired.Audit.LastSeq != 2 {
		t.Errorf("the retired key's audit range = %+v, want entries 1 to 2", retired.Audit)
	}
	if primary.Audit == nil || primary.Audit.FirstSeq != 3 || primary.Audit.LastSeq != 3 {
		t.Errorf("the primary key's audit range = %+v, want entry 3", primary.Audit)
	}
}

// The report has to work on a core that was never given the key, because that
// is exactly when somebody needs to know what they lost.
func TestTheReportNamesAKeyTheKeyringDoesNotHold(t *testing.T) {
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	estate(t, st, k.old, "before")

	report, err := Survey(context.Background(), st, k.onlyNew)
	must(t, err)
	missing := usageOf(t, report, k.old.PrimaryKeyID())
	if missing.Status != StatusMissing || missing.SealedTotal != 6 {
		t.Errorf("the key this core does not hold reads %s with %d records, want missing with 6",
			missing.Status, missing.SealedTotal)
	}
	if usageOf(t, report, k.onlyNew.PrimaryKeyID()).SealedTotal != 0 {
		t.Error("the primary key is credited with records it did not seal")
	}
}

// The outcome of #133: after a re-seal the retired key is not needed to read
// anything.
func TestAfterAResealNothingNeedsTheRetiredKey(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	plain := estate(t, st, k.old, "before")

	result, err := Reseal(ctx, st, k.both)
	must(t, err)
	if result.Resealed != 6 || result.Unreadable != 0 || result.Remaining != 0 {
		t.Fatalf("result = %+v, want 6 re-sealed and nothing left", result)
	}

	for _, kind := range store.SealedKinds {
		values, err := st.ListSealed(ctx, kind.Name, "", 100)
		must(t, err)
		found := false
		for _, v := range values {
			got, err := k.onlyNew.DecryptString(v.Value, kind.Context)
			if err != nil {
				if secrets.IsEnvelope(v.Value) {
					t.Errorf("%s %s cannot be read with the new key alone: %v", kind.Name, v.ID, err)
				}
				continue
			}
			found = found || got == plain[kind.Name]
		}
		if !found {
			t.Errorf("%s: the record written before the rotation is not readable with the new key alone", kind.Name)
		}
	}

	report, err := Survey(ctx, st, k.both)
	must(t, err)
	if n := usageOf(t, report, k.old.PrimaryKeyID()).SealedTotal; n != 0 {
		t.Errorf("after the re-seal the retired key still seals %d records", n)
	}

	again, err := Reseal(ctx, st, k.both)
	must(t, err)
	if again.Resealed != 0 {
		t.Errorf("a second re-seal rewrote %d records", again.Resealed)
	}
}

// What cannot be opened is left exactly as it was and counted, never replaced.
func TestAResealLeavesWhatItCannotOpen(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	estate(t, st, k.old, "before")

	before := map[string]string{}
	for _, kind := range store.SealedKinds {
		values, _ := st.ListSealed(ctx, kind.Name, "", 100)
		for _, v := range values {
			before[kind.Name+"/"+v.ID] = v.Value
		}
	}

	result, err := Reseal(ctx, st, k.onlyNew)
	must(t, err)
	if result.Resealed != 0 || result.Unreadable != 6 || result.Remaining != 6 {
		t.Fatalf("result = %+v, want nothing re-sealed and 6 unreadable", result)
	}
	for _, kind := range store.SealedKinds {
		values, _ := st.ListSealed(ctx, kind.Name, "", 100)
		for _, v := range values {
			if before[kind.Name+"/"+v.ID] != v.Value {
				t.Errorf("%s %s was changed by a re-seal that could not open it", kind.Name, v.ID)
			}
		}
	}
}

// writesBehind changes a record between the re-seal reading it and swapping it,
// which is what a running core does.
type writesBehind struct {
	store.Store
	kr *secrets.Keyring
}

func (w writesBehind) SwapSealed(ctx context.Context, kind, id, old, next string) (bool, error) {
	if kind == store.SealedCAAccount {
		k := store.SealedKinds[0]
		fresh, _ := w.kr.EncryptString("written by the running core", k.Context)
		if ok, err := w.Store.SwapSealed(ctx, kind, id, old, fresh); err != nil || !ok {
			return false, err
		}
	}
	return w.Store.SwapSealed(ctx, kind, id, old, next)
}

// Safe beside a running core: a record the core rewrote in the meantime keeps
// what the core wrote.
func TestAResealDoesNotOverwriteAConcurrentWrite(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	estate(t, st, k.old, "before")

	result, err := Reseal(ctx, writesBehind{st, k.both}, k.both)
	must(t, err)
	if result.Resealed != 5 || result.ChangedMeanwhile != 1 {
		t.Fatalf("result = %+v, want 5 re-sealed and 1 changed meanwhile", result)
	}
	values, _ := st.ListSealed(ctx, store.SealedCAAccount, "", 100)
	kept := false
	for _, v := range values {
		if got, err := k.onlyNew.DecryptString(v.Value, secrets.ContextCAAccountConfig); err == nil && got == "written by the running core" {
			kept = true
		}
	}
	if !kept {
		t.Error("the value the running core wrote was replaced by the re-seal")
	}
}

// A re-seal changes what every backup of this database can be read with, so it
// goes in the audit log.
func TestAResealIsAudited(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	st.UseAuditChain(store.NewAuditChainer(k.both))
	estate(t, st, k.old, "before")

	_, err := Reseal(ctx, st, k.both)
	must(t, err)
	logs, _, err := st.ListAuditLogs(ctx, store.AuditLogFilter{Actions: []string{"secrets.resealed"}})
	must(t, err)
	if len(logs) != 1 {
		t.Fatalf("%d secrets.resealed entries, want 1", len(logs))
	}

	_, err = Reseal(ctx, st, k.both)
	must(t, err)
	logs, _, _ = st.ListAuditLogs(ctx, store.AuditLogFilter{Actions: []string{"secrets.resealed"}})
	if len(logs) != 1 {
		t.Errorf("a re-seal with nothing to do wrote an audit entry (%d in all)", len(logs))
	}
}

// An estate is larger than one read. A walk that stopped after the first page
// would report a clean re-seal with most of the records untouched.
func TestEveryPageIsWalked(t *testing.T) {
	ctx := context.Background()
	k := rotatedKeys(t)
	st := store.NewMemoryStore()
	for i := 0; i < 5; i++ {
		sealed, err := k.old.EncryptString("secret", secrets.ContextNotificationConfig)
		must(t, err)
		must(t, st.CreateNotificationChannel(ctx, &store.NotificationChannel{Name: fmt.Sprintf("ch-%d", i),
			ChannelType: "webhook", IsEnabled: true, SeverityThreshold: "WARNING", ConfigEncrypted: sealed}))
	}

	was := pageSize
	pageSize = 2
	defer func() { pageSize = was }()

	report, err := Survey(ctx, st, k.both)
	must(t, err)
	if n := usageOf(t, report, k.old.PrimaryKeyID()).Sealed[store.SealedNotificationChannel]; n != 5 {
		t.Errorf("the report counted %d of 5 records", n)
	}
	result, err := Reseal(ctx, st, k.both)
	must(t, err)
	if result.Resealed != 5 || result.Remaining != 0 {
		t.Errorf("result = %+v, want 5 re-sealed and nothing left", result)
	}
}
