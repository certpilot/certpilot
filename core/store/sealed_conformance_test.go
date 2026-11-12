package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/certpilot/certpilot/pkg/secrets"
)

// sealedFixture writes one record of every kind that holds a sealed value and
// returns the id of each, keyed by kind.
func sealedFixture(t *testing.T, s Store, value func(kind string) string) map[string]string {
	t.Helper()
	ctx := context.Background()
	ids := map[string]string{}

	acc := &CAAccount{Name: "sealed-ca", ProviderType: "selfsigned", GatewayAddr: "127.0.0.1:9443",
		ConfigEncrypted: value(SealedCAAccount), Status: "CONNECTED"}
	if err := s.CreateCAAccount(ctx, acc); err != nil {
		t.Fatalf("CA account: %v", err)
	}
	ids[SealedCAAccount] = acc.ID

	cert := sampleCertificate("sealed-cert")
	key := value(SealedCertificate)
	cert.PrivateKeyEncrypted = &key
	if err := s.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("certificate: %v", err)
	}
	ids[SealedCertificate] = cert.ID

	target := &DeploymentTarget{Name: "sealed-target", TargetType: "webhook", IsEnabled: true,
		ConfigEncrypted: value(SealedDeploymentTarget)}
	if err := s.CreateDeploymentTarget(ctx, target); err != nil {
		t.Fatalf("deployment target: %v", err)
	}
	ids[SealedDeploymentTarget] = target.ID

	channel := &NotificationChannel{Name: "sealed-channel", ChannelType: "webhook", IsEnabled: true,
		SeverityThreshold: "WARNING", ConfigEncrypted: value(SealedNotificationChannel)}
	if err := s.CreateNotificationChannel(ctx, channel); err != nil {
		t.Fatalf("notification channel: %v", err)
	}
	ids[SealedNotificationChannel] = channel.ID

	conn := &CloudConnection{Name: "sealed-conn", Provider: CloudProviderAWSACM, IsEnabled: true,
		SyncIntervalMinutes: 360, ConfigEncrypted: value(SealedCloudConnection)}
	if err := s.CreateCloudConnection(ctx, conn); err != nil {
		t.Fatalf("cloud connection: %v", err)
	}
	ids[SealedCloudConnection] = conn.ID

	cred := &ACMEEABCredential{KID: "sealed-kid", Name: "sealed", TemplateID: acmeTemplate(t, s),
		HMACKeySealed: value(SealedACMECredential)}
	if err := s.CreateACMEEABCredential(ctx, cred); err != nil {
		t.Fatalf("ACME credential: %v", err)
	}
	ids[SealedACMECredential] = cred.ID

	return ids
}

// allSealed pages through one kind two at a time, so the paging is exercised
// on every call.
func allSealed(t *testing.T, s Store, kind string) map[string]string {
	t.Helper()
	out := map[string]string{}
	after := ""
	for {
		page, err := s.ListSealed(context.Background(), kind, after, 2)
		if err != nil {
			t.Fatalf("ListSealed(%s): %v", kind, err)
		}
		if len(page) == 0 {
			return out
		}
		for _, v := range page {
			if v.ID <= after {
				t.Fatalf("ListSealed(%s) returned %s after %s: not in id order", kind, v.ID, after)
			}
			if _, dup := out[v.ID]; dup {
				t.Fatalf("ListSealed(%s) returned %s twice", kind, v.ID)
			}
			out[v.ID] = v.Value
			after = v.ID
		}
	}
}

// Every kind of record that holds a sealed value is listed here, so adding one
// to the schema without teaching the re-seal about it fails in this test and
// not after somebody has dropped a key.
func TestEverySealedKindIsListedWithItsValue(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		if len(SealedKinds) != 6 {
			t.Fatalf("%d sealed kinds; this test writes 6. Add the new one to sealedFixture", len(SealedKinds))
		}
		ids := sealedFixture(t, s, func(kind string) string { return "sealed:" + kind })
		for _, k := range SealedKinds {
			got := allSealed(t, s, k.Name)
			if got[ids[k.Name]] != "sealed:"+k.Name {
				t.Errorf("%s: record %s lists %q, want %q", k.Name, ids[k.Name], got[ids[k.Name]], "sealed:"+k.Name)
			}
		}
		if _, err := s.ListSealed(context.Background(), "no_such_kind", "", 10); err == nil {
			t.Error("an unknown kind was listed without an error")
		}
	})
}

// A record with nothing sealed in it has nothing to re-seal, and listing it
// would make every report count agent-held keys as depending on a key.
func TestARecordWithNothingSealedIsNotListed(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		cert := sampleCertificate("no-key-held")
		if err := s.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
		if _, listed := allSealed(t, s, SealedCertificate)[cert.ID]; listed {
			t.Error("a certificate with no sealed key was listed")
		}
	})
}

// The swap is what makes re-sealing safe beside a running core: it replaces
// the value only if it is still the one that was read.
func TestASealedValueIsSwappedOnlyIfItHasNotChanged(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		ids := sealedFixture(t, s, func(kind string) string { return "old:" + kind })

		for _, k := range SealedKinds {
			id := ids[k.Name]

			swapped, err := s.SwapSealed(ctx, k.Name, id, "old:"+k.Name, "new:"+k.Name)
			if err != nil || !swapped {
				t.Fatalf("%s: SwapSealed = %v, %v; want swapped", k.Name, swapped, err)
			}
			if got := allSealed(t, s, k.Name)[id]; got != "new:"+k.Name {
				t.Fatalf("%s: after the swap the record holds %q", k.Name, got)
			}

			// Somebody else wrote the record between the read and the swap.
			swapped, err = s.SwapSealed(ctx, k.Name, id, "old:"+k.Name, "stale:"+k.Name)
			if err != nil || swapped {
				t.Fatalf("%s: a swap from a stale value = %v, %v; want not swapped", k.Name, swapped, err)
			}
			if got := allSealed(t, s, k.Name)[id]; got != "new:"+k.Name {
				t.Fatalf("%s: a stale swap changed the record to %q", k.Name, got)
			}

			swapped, err = s.SwapSealed(ctx, k.Name, "00000000-0000-0000-0000-000000000000", "a", "b")
			if err != nil || swapped {
				t.Fatalf("%s: a swap on a record that does not exist = %v, %v", k.Name, swapped, err)
			}
		}
	})
}

// Which key signed which audit entries: the question to answer before a key
// is dropped, since those entries can only be checked with it.
func TestAuditKeyUsageNamesEachKeyAndItsRange(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()

		if usage, err := s.AuditKeyUsage(ctx); err != nil || len(usage) != 0 {
			t.Fatalf("before anything is chained: %v, %v; want nothing", usage, err)
		}

		oldKey, newKey := make([]byte, secrets.KEKSize), make([]byte, secrets.KEKSize)
		for i := range oldKey {
			oldKey[i], newKey[i] = byte(i), byte(255-i)
		}
		before, _ := secrets.NewKeyring(oldKey)
		after, _ := secrets.NewKeyring(newKey, oldKey)

		write := func(n int, action string) {
			for i := 0; i < n; i++ {
				if err := s.CreateAuditLog(ctx, &AuditLog{Action: fmt.Sprintf("%s.%d", action, i), EntityType: "test"}); err != nil {
					t.Fatal(err)
				}
			}
		}
		s.UseAuditChain(NewAuditChainer(before))
		write(3, "before")
		s.UseAuditChain(NewAuditChainer(after))
		write(2, "after")

		usage, err := s.AuditKeyUsage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := []AuditKeyUsage{
			{KeyID: before.PrimaryKeyID(), Entries: 3, FirstSeq: 1, LastSeq: 3},
			{KeyID: after.PrimaryKeyID(), Entries: 2, FirstSeq: 4, LastSeq: 5},
		}
		if len(usage) != len(want) {
			t.Fatalf("usage = %+v, want %+v", usage, want)
		}
		for i := range want {
			if usage[i] != want[i] {
				t.Errorf("usage[%d] = %+v, want %+v", i, usage[i], want[i])
			}
		}
	})
}

// The schema is the authority on what is sealed. A column added by a migration
// and left out of SealedKinds would stay under a retired key for ever, and the
// report would say nothing depended on it.
func TestEverySealedColumnInTheSchemaIsASealedKind(t *testing.T) {
	s := postgresOnly(t)

	rows, err := s.pool.Query(context.Background(), `
		SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND (column_name LIKE '%\_encrypted' OR column_name LIKE '%\_sealed')
		ORDER BY 1, 2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	known := map[string]bool{}
	for _, k := range SealedKinds {
		known[k.table+"."+k.column] = true
	}
	found := 0
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		found++
		if !known[table+"."+column] {
			t.Errorf("%s.%s looks sealed and is not in SealedKinds, so a re-seal would skip it", table, column)
		}
	}
	if found != len(SealedKinds) {
		t.Errorf("the schema has %d sealed columns and SealedKinds lists %d", found, len(SealedKinds))
	}
}
